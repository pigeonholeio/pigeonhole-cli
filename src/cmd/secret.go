package cmd

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pigeonholeio/common/utils"
	"github.com/pigeonholeio/pigeonhole-cli/config"
	"github.com/pigeonholeio/pigeonhole-cli/sdk"
	"github.com/pigeonholeio/pigeonhole-cli/ui"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// formatBytes converts byte counts to human-readable format (B, KB, MB, GB, etc.)
func formatBytes(bytes int64) string {
	const (
		B  = 1
		KB = 1024 * B
		MB = 1024 * KB
		GB = 1024 * MB
		TB = 1024 * GB
	)

	if bytes < KB {
		return fmt.Sprintf("%d B", bytes)
	} else if bytes < MB {
		return fmt.Sprintf("%.2f KB", float64(bytes)/float64(KB))
	} else if bytes < GB {
		return fmt.Sprintf("%.2f MB", float64(bytes)/float64(MB))
	} else if bytes < TB {
		return fmt.Sprintf("%.2f GB", float64(bytes)/float64(GB))
	} else {
		return fmt.Sprintf("%.2f TB", float64(bytes)/float64(TB))
	}
}

// compressToBytes compresses a file or directory to tar.gz format in memory
func compressToBytes(src string) ([]byte, error) {
	buf := new(bytes.Buffer)
	zr := gzip.NewWriter(buf)
	tw := tar.NewWriter(zr)

	// is file a folder?
	fi, err := os.Stat(src)
	if err != nil {
		return nil, err
	}
	mode := fi.Mode()
	if mode.IsRegular() {
		// get header
		header, err := tar.FileInfoHeader(fi, src)
		if err != nil {
			return nil, err
		}
		// write header
		if err := tw.WriteHeader(header); err != nil {
			return nil, err
		}
		// get content
		data, err := os.Open(src)
		if err != nil {
			return nil, err
		}
		defer data.Close()
		if _, err := io.Copy(tw, data); err != nil {
			return nil, err
		}
	} else if mode.IsDir() { // folder
		// walk through every file in the folder
		if err := filepath.Walk(src, func(file string, fi os.FileInfo, err error) error {
			// check for walk errors
			if err != nil {
				return err
			}
			// generate tar header
			header, err := tar.FileInfoHeader(fi, file)
			if err != nil {
				return err
			}

			// must provide real name
			header.Name = filepath.ToSlash(file)

			// write header
			if err := tw.WriteHeader(header); err != nil {
				return err
			}
			// if not a dir, write file content
			if !fi.IsDir() {
				data, err := os.Open(file)
				if err != nil {
					return err
				}
				defer data.Close()
				if _, err := io.Copy(tw, data); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("error: file type not supported")
	}

	// produce tar
	if err := tw.Close(); err != nil {
		return nil, err
	}
	// produce gzip
	if err := zr.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// compressStdinData compresses stdin data into a tar.gz format and returns it as bytes
func compressStdinData(data []byte) ([]byte, error) {
	buf := new(bytes.Buffer)
	zr := gzip.NewWriter(buf)
	tw := tar.NewWriter(zr)

	// Create a tar header for the stdin data with a default filename
	header := &tar.Header{
		Name:    "plain.txt",
		Size:    int64(len(data)),
		Mode:    0644,
		ModTime: time.Now(),
	}

	if err := tw.WriteHeader(header); err != nil {
		return nil, err
	}

	if _, err := tw.Write(data); err != nil {
		return nil, err
	}

	if err := tw.Close(); err != nil {
		return nil, err
	}

	if err := zr.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// secretsCmd represents the secrets command
var secretsCmd = &cobra.Command{
	Use: "secret",
	Annotations: map[string]string{
		"skip-pre-run": "true",
	},
	Aliases: []string{"secrets", "s"},
	Short:   "Manage your secrets",
	Long:    `Manage your secrets`,
	Run: func(cmd *cobra.Command, args []string) {
		utils.DisplayHelp(cmd, args)
	},
}

// RetrieveCmd represents the collect command
var SecretsRetrieveCmd = &cobra.Command{
	Use:     "retrieve",
	Aliases: []string{"r", "download", "get", "g", "fetch", "f"},
	Short:   "Retrieve and decrypt secrets",
	Long:    `Retrieve and decrypt secrets`,
	Run: func(cmd *cobra.Command, args []string) {

		ui.Header("📨", "Retrieving secret")

		doneFetch := ui.Step("Fetching envelope")
		downloadResp, err := PigeonHoleClient.GetSecretSecretIdDownloadWithResponse(GlobalCtx, secretQueryReference)
		if err != nil {
			doneFetch(err)
			return
		}

		if downloadResp.StatusCode() != http.StatusOK || downloadResp.JSON200 == nil {
			switch downloadResp.StatusCode() {
			case http.StatusNotFound:
				if downloadResp.JSON404 != nil && downloadResp.JSON404.Message != nil {
					logrus.Debugf("Message from PigeonHole: %s", *downloadResp.JSON404.Message)
				}
				doneFetch(fmt.Errorf("secret not found"))
			case http.StatusBadRequest:
				if downloadResp.JSON400 != nil && downloadResp.JSON400.Message != nil {
					logrus.Debugf("Message from PigeonHole: %s", *downloadResp.JSON400.Message)
				}
				doneFetch(fmt.Errorf("bad request"))
			default:
				doneFetch(fmt.Errorf("status %d", downloadResp.StatusCode()))
			}
			return
		}
		doneFetch(nil)

		if downloadSecretPath == "" {
			downloadSecretPath = fmt.Sprintf("%s/%s", "decrypted", *downloadResp.JSON200.SecretReference)
		}
		downloadSecretPath, _ = filepath.Abs(downloadSecretPath)

		if err = os.MkdirAll(downloadSecretPath, 0744); err != nil {
			logrus.Debugf("%v", err)
			ui.Error("Can't create output path: " + downloadSecretPath)
			return
		}
		logrus.Debugf("secret download url found: %s", *downloadResp.JSON200.DownloadUrl)

		// Check if we have the right key to decrypt this secret
		var applicableKeys []string
		if downloadResp.JSON200.RecipientKeyFingerprint != nil && *downloadResp.JSON200.RecipientKeyFingerprint != "" {
			doneKey := ui.Step("Checking decryption key")
			for email, identity := range PigeonHoleConfig.Identity {
				if identity.GPGKey != nil && identity.GPGKey.Fingerprint != nil {
					if *identity.GPGKey.Fingerprint == *downloadResp.JSON200.RecipientKeyFingerprint {
						applicableKeys = append(applicableKeys, email)
					}
				}
			}

			if len(applicableKeys) == 0 {
				doneKey(fmt.Errorf("no matching key found"))
				ui.Info("Secret encrypted with fingerprint: " + *downloadResp.JSON200.RecipientKeyFingerprint)
				ui.Info("Your keys:")
				if len(PigeonHoleConfig.Identity) == 0 {
					ui.Info("  • No keys found — run: pigeonhole keys init")
				} else {
					for email, identity := range PigeonHoleConfig.Identity {
						if identity.GPGKey != nil && identity.GPGKey.Fingerprint != nil {
							ui.Info(fmt.Sprintf("  • %s (%s)", email, *identity.GPGKey.Fingerprint))
						} else {
							ui.Info("  • " + email)
						}
					}
				}
				return
			}
			doneKey(nil)
		}

		doneDownload := ui.Step("Downloading")
		tmpFileName, _ := utils.DownloadFile(downloadResp.JSON200.DownloadUrl)
		inputBytes, err := os.ReadFile(tmpFileName)
		if err != nil {
			doneDownload(err)
			return
		}
		doneDownload(nil)

		doneDecrypt := ui.Step("Decrypting")
		var decryptedFilePath string
		decrypted := false
		var decryptionErrors []string

		for _, i := range PigeonHoleConfig.Identity {
			decodedKey, _ := i.GPGKey.DecodedPrivateKey()
			decryptedFilePath, err = utils.DecryptBytes(inputBytes, &downloadSecretPath, &decodedKey)
			if err != nil {
				logrus.Debugf("Failed to decrypt with key: %s", err.Error())
				decryptionErrors = append(decryptionErrors, err.Error())
				continue
			}
			decrypted = true
			break
		}

		if !decrypted {
			if len(PigeonHoleConfig.Identity) == 0 {
				doneDecrypt(fmt.Errorf("no GPG keys in configuration"))
				ui.Info("Initialize keys: pigeonhole keys init")
				return
			}

			hasIncorrectKeyError := false
			for _, errMsg := range decryptionErrors {
				if strings.Contains(strings.ToLower(errMsg), "incorrect key") ||
					strings.Contains(strings.ToLower(errMsg), "bad decrypt") ||
					strings.Contains(strings.ToLower(errMsg), "decryption failed") {
					hasIncorrectKeyError = true
					break
				}
			}

			if hasIncorrectKeyError {
				doneDecrypt(fmt.Errorf("wrong key — secret encrypted with a different GPG key pair"))
				ui.Info("The secret may have been sent to a different device or key.")
				ui.Info("Ask the sender to re-encrypt with your current public key.")
			} else {
				doneDecrypt(fmt.Errorf("decryption failed with all available keys"))
				ui.Info("Run: pigeonhole keys list")
			}
			return
		}
		logrus.Debugf("decryptedFilePath: %s", decryptedFilePath)

		utils.DecompressFile(decryptedFilePath, downloadSecretPath)
		utils.ShredFile(decryptedFilePath, 3)
		doneDecrypt(nil)
		ui.Success(fmt.Sprintf("Saved to %s", downloadSecretPath))
	},
}

// secretsListCmd represents the secretsList command
var SecretsCountCmd = &cobra.Command{
	Use:   "count",
	Short: "Count the number of secrets",
	Long:  `Count the number of secrets`,
	Run: func(cmd *cobra.Command, args []string) {

		// fmt.Println(query)
		s := sdk.GetSecretParams{
			All:       &listAllSecrets,
			Reference: &secretQueryReference,
		}

		// f, _ := PigeonHoleClient.GetSecret()
		f, err := PigeonHoleClient.GetSecretWithResponse(GlobalCtx, &s)
		if err != nil {
			logrus.Debugf("%v", err)
			fmt.Println("Something went wrong with the PigeonHole API")
			return
		}
		code := f.StatusCode()

		logrus.Debugf("PigeonHole return status: %d", code)

		if f.StatusCode() == http.StatusOK && f.JSON200 != nil && f.JSON200.Secrets != nil && len(*f.JSON200.Secrets) > 0 {
			logrus.Debugf("PigeonHole return message: %s", *f.JSON200.Message)
			fmt.Printf("Secret count: %d\n", len(*f.JSON200.Secrets))
			// utils.OutputData(sdk.ToSecretViewSlice(*f.JSON200.Secrets))

		} else if f.StatusCode() == 400 && f.JSON400 != nil && f.JSON400.Message != nil {
			fmt.Printf("failed: %s\n", *f.JSON400.Message)
		} else if f.StatusCode() == 401 && f.JSON401 != nil && f.JSON401.Message != nil {
			fmt.Printf("failed: %s\n", *f.JSON401.Message)
		} else if f.StatusCode() == 403 && f.JSON403 != nil && f.JSON403.Message != nil {
			fmt.Printf("failed: %s\n", *f.JSON403.Message)
		} else if f.StatusCode() == 404 && f.JSON404 != nil && f.JSON404.Message != nil {
			fmt.Printf("failed: %s\n", *f.JSON404.Message)
		} else if f.StatusCode() == 500 && f.JSON500 != nil && f.JSON500.Message != nil {
			logrus.Debugf("PigeonHole return message: %s", *f.JSON500.Message)
			fmt.Printf("failed: %s\n", *f.JSON500.Message)
		} else if f.StatusCode() == 502 || f.StatusCode() == 503 || f.StatusCode() == 504 {
			fmt.Println("Unable to connect to the Pigeonhole API. The service may be temporarily unavailable.")
			fmt.Println("Please try again in a few moments.")
		} else if f.StatusCode() == http.StatusOK && f.JSON200 != nil {
			fmt.Println("No secrets found")
		} else {
			fmt.Println("An unexpected error occurred. Please try again or contact support.")
		}

	},
}
// checkDecryptable checks if a secret can be decrypted with the user's local keys
func checkDecryptable(secret sdk.Secret, cfg config.PigeonHoleConfig) bool {
	if secret.RecipientKeyFingerprint == nil || *secret.RecipientKeyFingerprint == "" {
		return true // legacy: no fingerprint = assume decryptable
	}
	for _, identity := range cfg.Identity {
		if identity.GPGKey != nil && identity.GPGKey.Fingerprint != nil {
			if *identity.GPGKey.Fingerprint == *secret.RecipientKeyFingerprint {
				return true
			}
		}
	}
	return false
}

var SecretsListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"l", "ls"},
	Short:   "List out your secrets",
	Long: `List your secrets that you can collect and decrypt.
By default only received secrets are listed, use --all to list sent and active secrets too.`,
	Run: func(cmd *cobra.Command, args []string) {

		// fmt.Println(query)
		s := sdk.GetSecretParams{
			All:       &listAllSecrets,
			Reference: &secretQueryReference,
		}

		// f, _ := PigeonHoleClient.GetSecret()
		f, err := PigeonHoleClient.GetSecretWithResponse(GlobalCtx, &s)
		if err != nil {
			logrus.Debugf("%v", err)
			fmt.Println("Something went wrong with the PigeonHole API")
			return
		}
		code := f.StatusCode()

		logrus.Debugf("PigeonHole return status: %d", code)

		if f.StatusCode() == http.StatusOK && f.JSON200 != nil && f.JSON200.Secrets != nil && len(*f.JSON200.Secrets) > 0 {
			logrus.Debugf("PigeonHole return message: %s", *f.JSON200.Message)

		// Build SecretView slice with decryptable status
		views := make([]sdk.SecretView, 0, len(*f.JSON200.Secrets))
			for _, secret := range *f.JSON200.Secrets {
				canDecrypt := checkDecryptable(secret, PigeonHoleConfig)
				view := sdk.ToSecretView(secret)
				view.Decryptable = &canDecrypt
				views = append(views, view)

				if !canDecrypt {
					logrus.Debugf("Secret %s encrypted with different key - cannot decrypt", *secret.Reference)
				}
			}

			utils.OutputData(views)

		} else if f.StatusCode() == 400 && f.JSON400 != nil && f.JSON400.Message != nil {
			fmt.Printf("failed: %s\n", *f.JSON400.Message)
		} else if f.StatusCode() == 401 && f.JSON401 != nil && f.JSON401.Message != nil {
			fmt.Printf("failed: %s\n", *f.JSON401.Message)
		} else if f.StatusCode() == 403 && f.JSON403 != nil && f.JSON403.Message != nil {
			fmt.Printf("failed: %s\n", *f.JSON403.Message)
		} else if f.StatusCode() == 404 && f.JSON404 != nil && f.JSON404.Message != nil {
			fmt.Printf("failed: %s\n", *f.JSON404.Message)
		} else if f.StatusCode() == 500 && f.JSON500 != nil && f.JSON500.Message != nil {
			logrus.Debugf("PigeonHole return message: %s", *f.JSON500.Message)
			fmt.Printf("failed: %s\n", *f.JSON500.Message)
		} else if f.StatusCode() == 502 || f.StatusCode() == 503 || f.StatusCode() == 504 {
			fmt.Println("Unable to connect to the Pigeonhole API. The service may be temporarily unavailable.")
			fmt.Println("Please try again in a few moments.")
		} else if f.StatusCode() == http.StatusOK && f.JSON200 != nil {
			fmt.Println("No secrets found")
		} else {
			fmt.Println("An unexpected error occurred. Please try again or contact support.")
		}

	},
}

// dropCmd represents the drop command
var SecretsDropCmd = &cobra.Command{
	Use:     "post",
	Aliases: []string{"send", "drop", "ship", "s", "p"},
	Short:   "Post a secret securely",
	Long:    `Post a secret securely.`,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		// Check if there is data in stdin
		fileInfo, err := os.Stdin.Stat()
		if err != nil {
			// On error, assume piped input (treat as not a char device)
		}
		if fileInfo != nil && (fileInfo.Mode() & os.ModeCharDevice) == 0 {

			// There is data in stdin
			// fmt.Println("Data is being piped to stdin.")
		} else {
			// No data in stdin, check if the flag is set
			requiredFlag, err := cmd.Flags().GetString("filepath")
			if err != nil || requiredFlag == "" {
				return fmt.Errorf("You must specify a path '-f' or pipe from stdin")
			}
		}
		return nil
	},

	Run: func(cmd *cobra.Command, args []string) {

		// Check if reading from stdin
		fileInfo, stdinErr := os.Stdin.Stat()
		isStdin := fileInfo != nil && (fileInfo.Mode() & os.ModeCharDevice) == 0
		_ = stdinErr

		var resolvedPath string
		if !isStdin {
			var err error
			resolvedPath, err = filepath.Abs(filename)
			if err != nil {
				logrus.Debugln(err.Error())
				fmt.Printf("❌ Failed to resolve path: %s\n", filename)
				return
			}

			// Check if file or directory exists
			if _, err := os.Stat(resolvedPath); err != nil {
				logrus.Debugln(err.Error())
				fmt.Printf("❌ No file or directory at: %s\n", resolvedPath)
				return
			}
		}
		ui.Header("📨", "Sending secret")

		reference := utils.GenerateCodeWord(2)
		timeSecretExpiry, err := utils.ParseExpiration(secretExpiry)
		if err != nil {
			logrus.Debugf("Invlid Expiration: %s", err.Error())
			ui.Warn("Invalid expiration")
		}

		doneCompress := ui.Step("Compressing")
		var compressedData []byte
		if isStdin {
			logrus.Debug("Reading from stdin")
			stdinData, err := io.ReadAll(os.Stdin)
			if err != nil {
				doneCompress(fmt.Errorf("error reading from stdin"))
				logrus.Debugf("Error reading from stdin: %s", err.Error())
				return
			}

			logrus.Debug("Compressing stdin data into tar.gz")
			compressedData, err = compressStdinData(stdinData)
			if err != nil {
				doneCompress(err)
				logrus.Debugf("Error compressing stdin data: %s", err.Error())
				return
			}
		} else {
			logrus.Debug("Compressing file/directory into tar.gz")
			compressedData, err = compressToBytes(filename)
			if err != nil {
				doneCompress(err)
				logrus.Debugf("Error compressing data: %s", err.Error())
				return
			}
		}
		doneCompress(nil)

		// Calculate payload size after compression
		payloadSize := int64(len(compressedData))
		logrus.Debugf("Compressed payload size: %d bytes", payloadSize)

		newSecretRequest := sdk.CreateSecretEnvelopeOptions{ //PostSecretJSONRequestBody
			RecipientIds:     recipients,
			Reference:        reference,
			Ephemeralkeys:    &useEpheralKeys,
			Onetime:          &oneTimeSecret,
			Expiration:       &timeSecretExpiry,
			TotalPayloadSize: payloadSize,
		}

		doneEnvelope := ui.Step("Requesting envelope")
		secretEnvelopeResponse, err := PigeonHoleClient.PostSecretWithResponse(GlobalCtx, newSecretRequest)
		if err != nil {
			doneEnvelope(err)
			logrus.Debugln(err.Error())
			return
		}

		switch {
		case secretEnvelopeResponse.JSON201 != nil && secretEnvelopeResponse.StatusCode() == http.StatusCreated:
			doneEnvelope(nil)
			logrus.Debugln("Secret envelope received, posting secret")

			doneEncrypt := ui.Step("Encrypting")
			logrus.Debugf("Retrieving public keys")
			user_pubs, err := sdk.GetUserGPGArmoredPubKeysFromIdSlice(&GlobalCtx, secretEnvelopeResponse.JSON201)
			if err != nil {
				doneEncrypt(err)
				return
			}
			if len(user_pubs) == 0 {
				doneEncrypt(fmt.Errorf("no public keys found for recipients"))
				ui.Info("Use -e to send with ephemeral keys: pigeonhole secret send -r <email> -f ./myfile -e")
				return
			}
			logrus.Debugf("Found %d keys", len(user_pubs))

			encryptedFile, err := os.CreateTemp(os.TempDir(), "pigeonhole-encrypted-")
			if err != nil {
				doneEncrypt(err)
				logrus.Debugf("Error creating temp file: %s", err.Error())
				return
			}
			defer encryptedFile.Close()

			logrus.Debug("Encrypting compressed data")
			err = utils.EncryptStream(bytes.NewReader(compressedData), encryptedFile, user_pubs)
			if err != nil {
				doneEncrypt(err)
				logrus.Debugf("Encryption failed: %s", err.Error())
				return
			}
			encryptedFilePath := encryptedFile.Name()
			logrus.Debugf("Encrypted file created at: %s", encryptedFilePath)
			doneEncrypt(nil)

			doneUpload := ui.Step("Uploading")
			errx := sdk.UploadFile(*secretEnvelopeResponse.JSON201, encryptedFilePath)
			logrus.Debugf("Shredding encrypted temp file: %s", encryptedFilePath)
			utils.ShredFile(encryptedFilePath, 3)
			if errx != nil {
				doneUpload(errx)
				logrus.Debugln(errx.Error())
			} else {
				doneUpload(nil)
				fmt.Println()
				ui.Success(fmt.Sprintf("Secret sent — ref: %s", *secretEnvelopeResponse.JSON201.S3Info.Fields.XAmzMetaReference))
			}

		case secretEnvelopeResponse.StatusCode() == http.StatusNotAcceptable:
			doneEnvelope(fmt.Errorf("recipients missing public keys"))
			if secretEnvelopeResponse.JSON406 != nil && secretEnvelopeResponse.JSON406.Message != nil {
				logrus.Debugf("PigeonHole API message: %s", *secretEnvelopeResponse.JSON406.Message)
			}
			ui.Info("Use -e for ephemeral keys: pigeonhole secret send -r <email> -f ./myfile -e")

		case secretEnvelopeResponse.StatusCode() == http.StatusTooManyRequests:
			if secretEnvelopeResponse.JSON429 != nil {
				doneEnvelope(fmt.Errorf("monthly active secret quota exceeded: %s", secretEnvelopeResponse.JSON429.Message))
				ui.Info("Delete unused secrets: pigeonhole secret delete -r <reference>")
				ui.Info("Request a quota increase: quota@pigeono.io")
			}

		case secretEnvelopeResponse.StatusCode() == http.StatusRequestEntityTooLarge:
			if secretEnvelopeResponse.JSON413 != nil {
				msg := "monthly sent bytes quota exceeded"
				if secretEnvelopeResponse.JSON413.Message != "" {
					msg = secretEnvelopeResponse.JSON413.Message
				}
				doneEnvelope(fmt.Errorf("%s", msg))
				if secretEnvelopeResponse.JSON413.Requested != nil {
					ui.Info("Requested: " + formatBytes(*secretEnvelopeResponse.JSON413.Requested))
				}
			}

		case secretEnvelopeResponse.StatusCode() == http.StatusBadRequest:
			msg := "bad request"
			if secretEnvelopeResponse.JSON400 != nil && secretEnvelopeResponse.JSON400.Message != nil {
				msg = *secretEnvelopeResponse.JSON400.Message
			}
			doneEnvelope(fmt.Errorf("%s", msg))

		case secretEnvelopeResponse.StatusCode() == http.StatusUnauthorized:
			msg := "unauthorized"
			if secretEnvelopeResponse.JSON401 != nil && secretEnvelopeResponse.JSON401.Message != nil {
				msg = *secretEnvelopeResponse.JSON401.Message
			}
			doneEnvelope(fmt.Errorf("%s", msg))

		case secretEnvelopeResponse.StatusCode() == http.StatusForbidden:
			msg := "forbidden"
			if secretEnvelopeResponse.JSON403 != nil && secretEnvelopeResponse.JSON403.Message != nil {
				msg = *secretEnvelopeResponse.JSON403.Message
			}
			doneEnvelope(fmt.Errorf("%s", msg))

		case secretEnvelopeResponse.StatusCode() == http.StatusNotFound:
			msg := "not found"
			if secretEnvelopeResponse.JSON404 != nil && secretEnvelopeResponse.JSON404.Message != nil {
				msg = *secretEnvelopeResponse.JSON404.Message
			}
			doneEnvelope(fmt.Errorf("%s", msg))

		case secretEnvelopeResponse.StatusCode() == http.StatusInternalServerError:
			msg := "server error"
			if secretEnvelopeResponse.JSON500 != nil && secretEnvelopeResponse.JSON500.Message != nil {
				logrus.Debugf("PigeonHole return message: %s", *secretEnvelopeResponse.JSON500.Message)
				msg = *secretEnvelopeResponse.JSON500.Message
			}
			doneEnvelope(fmt.Errorf("%s", msg))

		default:
			doneEnvelope(fmt.Errorf("unexpected status %d", secretEnvelopeResponse.StatusCode()))
		}
	},
}

var SecretsDeleteCmd = &cobra.Command{
	Use:     "delete",
	Aliases: []string{"del", "rm", "d"},
	Short:   "Delete secrets you may no longer want or need",
	Long:    `Delete secrets you may no longer want or need.`,
	Run: func(cmd *cobra.Command, args []string) {
		if secretQueryReference == "" && !deleteAllSecrets {
			utils.DisplayHelp(cmd, args)
			return
		}

		var resp *sdk.DeleteSecretResponse
		var err error

		if deleteAllSecrets {
			resp, err = PigeonHoleClient.DeleteSecretWithResponse(GlobalCtx)
			if err != nil {
				logrus.Debugln(err.Error())
				fmt.Println("Something went wrong deleting all secrets")
				return
			}

			switch resp.StatusCode() {
			case http.StatusInternalServerError:
				if resp.JSON500 != nil && resp.JSON500.Message != nil {
					logrus.Debugln(*resp.JSON500.Message)
				}
				fmt.Println("Something went wrong deleting all secrets")
			case http.StatusNotFound:
				fmt.Println("No secrets found")
			case http.StatusOK:
				fmt.Println("All secrets deleted")
			default:
				fmt.Printf("Unhandled Exception with Status Code: %d\n", resp.StatusCode())
			}

		} else {
			logrus.Debugf("Querying for secret: %s\n", secretQueryReference)
			respx, err := PigeonHoleClient.DeleteSecretSecretIdWithResponse(GlobalCtx, secretQueryReference)

			if err != nil {
				logrus.Debugln(err.Error())
				fmt.Printf("Error: Something went wrong deleting secret: %s\n", secretQueryReference)
				return
			}
			switch respx.StatusCode() {
			case http.StatusOK:
				if respx.JSON200 != nil && respx.JSON200.Message != nil {
					logrus.Debugln(*respx.JSON200.Message)
				}
				if respx.JSON200 != nil && respx.JSON200.Secret != nil && respx.JSON200.Secret.Reference != nil {
					fmt.Printf("✅ Secret deleted for %s\n", *respx.JSON200.Secret.Reference)
				}
			case http.StatusBadRequest:
				fmt.Printf("❌ No secret found for %s\n", secretQueryReference)
			case http.StatusInternalServerError:
				if respx.JSON500 != nil && respx.JSON500.Message != nil {
					logrus.Debugln(*respx.JSON500.Message)
					fmt.Printf("Something went wrong deleting secret %s: %s", secretQueryReference, *respx.JSON500.Message)
				} else {
					fmt.Printf("Something went wrong deleting secret %s", secretQueryReference)
				}
			case http.StatusNotFound:
				if respx.JSON404 != nil && respx.JSON404.Message != nil {
					logrus.Debugln(*respx.JSON404.Message)
				}
				fmt.Printf("❌ No secret found for %s\n", secretQueryReference)
			default:
				fmt.Printf("Unhandled Exception with Status Code: %d\n", respx.StatusCode())
			}

		}

	},
}

var (
	useEpheralKeys       bool
	recipients           []string
	filename             string
	reference            string
	deleteAllSecrets     bool
	secretQueryReference string
	downloadSecretPath   string
	listAllSecrets       bool
	oneTimeSecret        bool
	secretExpiry         string
)

func init() {
	rootCmd.AddCommand(secretsCmd)
	secretsCmd.AddCommand(SecretsRetrieveCmd)
	secretsCmd.AddCommand(SecretsDeleteCmd)
	secretsCmd.AddCommand(SecretsDropCmd)
	secretsCmd.AddCommand(SecretsListCmd)
	secretsCmd.AddCommand(SecretsCountCmd)

	SecretsRetrieveCmd.Flags().StringVarP(&downloadSecretPath, "filepath", "f", "", "The path where to download, decrypt and extract your secret")
	SecretsRetrieveCmd.Flags().StringVarP(&secretQueryReference, "reference", "r", "", "The id or reference of the secret")
	SecretsRetrieveCmd.MarkPersistentFlagRequired("reference")

	SecretsDeleteCmd.Flags().BoolVarP(&deleteAllSecrets, "all", "a", false, "Delete all secrets that you have sent/received")
	SecretsDeleteCmd.Flags().StringVarP(&secretQueryReference, "reference", "r", "", "The id or reference of the secret")

	SecretsDropCmd.Flags().BoolVarP(&useEpheralKeys, "use-ephemeral-keys", "e", false, "manage the use of ephemeral keys (Default: false)")
	SecretsDropCmd.Flags().BoolVarP(&oneTimeSecret, "one-time-secret", "1", false, "Ensure a one time secret - deletes the secret after one retrieval (Default: false)")
	SecretsDropCmd.Flags().StringSliceVarP(&recipients, "recipient", "r", nil, "Email addresses of the recipients (add multiple or separate with comma)")
	SecretsDropCmd.Flags().StringVarP(&filename, "filepath", "f", "", "A path to a file or folder to send")
	SecretsDropCmd.Flags().StringVarP(&secretExpiry, "expiry", "x", "7d", "The expiration of the secret in time duration")
	// SecretsDropCmd.Flags().StringVarP(&secretQueryReference, "reference", "r", "", "If you want to override the encrypted secret code name for the secret drop")
	// SecretsDropCmd.MarkFlagRequired("filepath")
	SecretsDropCmd.MarkFlagRequired("recipient")
	SecretsListCmd.Flags().StringVarP(&secretQueryReference, "reference", "r", "", "The id or reference of the secret")
	SecretsListCmd.Flags().BoolVarP(&listAllSecrets, "all", "a", false, "List all sent and received secrets (default just received)")
	SecretsCountCmd.Flags().StringVarP(&secretQueryReference, "reference", "r", "", "The id or reference of the secret")
	SecretsCountCmd.Flags().BoolVarP(&listAllSecrets, "all", "a", false, "List all sent and received secrets (default just received)")
	// viper.BindPFlag("recipient", SecretsDropCmd.PersistentFlags().Lookup("recipient"))

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// secretsCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// secretsCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
