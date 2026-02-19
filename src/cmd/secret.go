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

	// "github.com/davecgh/go-spew/spew"
	"github.com/pigeonholeio/common/utils"
	"github.com/pigeonholeio/pigeonhole-cli/sdk"
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
		filepath.Walk(src, func(file string, fi os.FileInfo, err error) error {
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
		})
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

		fmt.Printf("Fetching secret envelope...")
		downloadResp, _ := PigeonHoleClient.GetSecretSecretIdDownloadWithResponse(GlobalCtx, secretQueryReference)

		// Check for 307 redirect with valid response
		if downloadResp.StatusCode() != http.StatusOK || downloadResp.JSON200 == nil {
			// Handle error cases for non-307 responses
			switch downloadResp.StatusCode() {
			case http.StatusNotFound:
				if downloadResp.JSON404 != nil && downloadResp.JSON404.Message != nil {
					logrus.Debugf("Message from PigeonHole: %s", *downloadResp.JSON404.Message)
				}
				fmt.Println("No secret found")
			case http.StatusBadRequest:
				if downloadResp.JSON400 != nil && downloadResp.JSON400.Message != nil {
					logrus.Debugf("Message from PigeonHole: %s", *downloadResp.JSON400.Message)
				} else {
					fmt.Println("Bad request")
				}
			default:
				fmt.Println("Failed to fetch secret")
			}
			return
		}

		if downloadSecretPath == "" {
			downloadSecretPath = fmt.Sprintf("%s/%s", "decrypted", *downloadResp.JSON200.SecretReference)
		}
		downloadSecretPath, _ = filepath.Abs(downloadSecretPath)

		err := os.MkdirAll(downloadSecretPath, 0744)

		if err != nil {
			logrus.Debugf(err.Error())
			fmt.Printf("Can't create path: %s\n", downloadSecretPath)
			return
		}
		// var filename string
		logrus.Debugf("secret download url found: %s", *downloadResp.JSON200.DownloadUrl)

		fmt.Printf("done!\nRetrieving and decrypting secret %s...", *downloadResp.JSON200.SecretReference)
		tmpFileName, _ := utils.DownloadFile(downloadResp.JSON200.DownloadUrl)
		inputBytes, err := os.ReadFile(tmpFileName)
		if err != nil {
			fmt.Printf("\nFailed!")
			return
		}
		var decryptedFilePath string

		// Check if we have the right key to decrypt this secret
		var applicableKeys []string
		if downloadResp.JSON200.RecipientKeyFingerprint != nil && *downloadResp.JSON200.RecipientKeyFingerprint != "" {
			fmt.Printf("\n⏳ Checking if you have the key needed to decrypt this secret...")
			// Check which keys can decrypt this secret
			for email, identity := range PigeonHoleConfig.Identity {
				if identity.GPGKey != nil && identity.GPGKey.Fingerprint != nil {
					if *identity.GPGKey.Fingerprint == *downloadResp.JSON200.RecipientKeyFingerprint {
						applicableKeys = append(applicableKeys, email)
					}
				}
			}

			if len(applicableKeys) == 0 {
				fmt.Println(" Failed!\n")
				fmt.Println("❌ You don't have the key needed to decrypt this secret.")
				fmt.Println()
				fmt.Println("The secret was encrypted with fingerprint:")
				fmt.Printf("  %s\n", *downloadResp.JSON200.RecipientKeyFingerprint)
				fmt.Println()
				fmt.Println("Your available keys:")
				if len(PigeonHoleConfig.Identity) == 0 {
					fmt.Println("  • No keys found in your configuration")
				} else {
					for email, identity := range PigeonHoleConfig.Identity {
						if identity.GPGKey != nil && identity.GPGKey.Fingerprint != nil {
							fmt.Printf("  • %s (fingerprint: %s)\n", email, *identity.GPGKey.Fingerprint)
						} else {
							fmt.Printf("  • %s\n", email)
						}
					}
				}
				fmt.Println()
				fmt.Println("To resolve this:")
				fmt.Println("  1. Verify the secret was encrypted for your email address")
				fmt.Println("  2. Check if you have the correct GPG keys from the device where the secret was sent")
				fmt.Println("  3. You may need to ask the sender to re-encrypt the secret with your current public key")
				return
			}
			fmt.Println(" Yes!")
		}

		// decrypt the bytes to the desired path
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
			fmt.Println("Failed to decrypt secret!")
			fmt.Println()

			// Check if we have any keys at all
			if len(PigeonHoleConfig.Identity) == 0 {
				fmt.Println("❌ No GPG keys found in your configuration.")
				fmt.Println()
				fmt.Println("To use PigeonHole, you need to initialize your GPG keys:")
				fmt.Println("  pigeonhole keys init")
				return
			}

			// Check if all decryption attempts failed due to incorrect key errors
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
				fmt.Println("⚠️  The secret was encrypted with a different GPG key pair.")
				fmt.Println()
				fmt.Println("This can happen if:")
				fmt.Println("  • The secret was encrypted on a different device")
				fmt.Println("  • Your GPG keys were regenerated after the secret was sent")
				fmt.Println("  • Someone encrypted the secret for a different recipient")
				fmt.Println()
				fmt.Println("Current GPG keys available for decryption:")
				for email, identity := range PigeonHoleConfig.Identity {
					if identity.GPGKey != nil && identity.GPGKey.Thumbprint != nil {
						fmt.Printf("  • %s (thumbprint: %s)\n", email, *identity.GPGKey.Thumbprint)
					} else {
						fmt.Printf("  • %s\n", email)
					}
				}
				fmt.Println()
				fmt.Println("To resolve this:")
				fmt.Println("  1. Verify the secret was encrypted for your email address")
				fmt.Println("  2. Check if you have the correct GPG keys from the device where the secret was sent")
				fmt.Println("  3. You may need to ask the sender to re-encrypt the secret with your current public key")
			} else {
				fmt.Println("❌ Unable to decrypt the secret with any available GPG keys.")
				fmt.Println()
				if len(decryptionErrors) > 0 {
					fmt.Println("Decryption errors:")
					for i, errMsg := range decryptionErrors {
						fmt.Printf("  %d. %s\n", i+1, errMsg)
					}
					fmt.Println()
				}
				fmt.Println("Try:")
				fmt.Println("  • Verify the secret reference is correct")
				fmt.Println("  • Run `pigeonhole keys list` to see your available keys")
				fmt.Println("  • Run `pigeonhole keys init` to regenerate your keys")
			}
			return
		}
		logrus.Debugf("decryptedFilePath: %s", decryptedFilePath)

		utils.DecompressFile(decryptedFilePath, downloadSecretPath)
		utils.ShredFile(decryptedFilePath, 3)
		fmt.Printf("done!\n📨 Decrypted %s to %s\n", *downloadResp.JSON200.SecretReference, downloadSecretPath)
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
			logrus.Debugf(err.Error())
			fmt.Println("Something went wrong with the PigeonHole API")
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
			logrus.Debugf(err.Error())
			fmt.Println("Something went wrong with the PigeonHole API")
		}
		code := f.StatusCode()

		logrus.Debugf("PigeonHole return status: %d", code)

		if f.StatusCode() == http.StatusOK && f.JSON200 != nil && f.JSON200.Secrets != nil && len(*f.JSON200.Secrets) > 0 {
			logrus.Debugf("PigeonHole return message: %s", *f.JSON200.Message)

			// Check each secret's fingerprint against user's keys
			for i, secret := range *f.JSON200.Secrets {
				canDecrypt := false

				// Check if secret has a recipient key fingerprint
				if secret.RecipientKeyFingerprint != nil && *secret.RecipientKeyFingerprint != "" {
					// Check against all user keys
					for _, identity := range PigeonHoleConfig.Identity {
						if identity.GPGKey != nil && identity.GPGKey.Fingerprint != nil {
							if *identity.GPGKey.Fingerprint == *secret.RecipientKeyFingerprint {
								canDecrypt = true
								break
							}
						}
					}
				} else {
					// If no fingerprint is stored, assume it can be decrypted (legacy support)
					canDecrypt = true
				}

				// Add decryption status to secret for display
				if !canDecrypt {
					(*f.JSON200.Secrets)[i].RecipientKeyFingerprint = nil // Hide fingerprint if can't decrypt
					// Mark with indicator that this secret can't be decrypted
					logrus.Debugf("Secret %s encrypted with different key - cannot decrypt", *secret.Reference)
				}
			}

			utils.OutputData(sdk.ToSecretViewSlice(*f.JSON200.Secrets))

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
		fileInfo, _ := os.Stdin.Stat()
		if (fileInfo.Mode() & os.ModeCharDevice) == 0 {

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
		fileInfo, _ := os.Stdin.Stat()
		isStdin := (fileInfo.Mode() & os.ModeCharDevice) == 0

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
		reference := utils.GenerateCodeWord(2)
		timeSecretExpiry, err := utils.ParseExpiration(secretExpiry)
		if err != nil {
			logrus.Debugf("Invlid Expiration: %s", err.Error())
			fmt.Println("Invalid expiration")
		}

		// Compress data BEFORE requesting envelope to calculate payload size
		fmt.Printf("Preparing secret...")
		var compressedData []byte
		if isStdin {
			logrus.Debug("Reading from stdin")
			stdinData, err := io.ReadAll(os.Stdin)
			if err != nil {
				fmt.Println("Error reading from stdin")
				logrus.Debugf("Error reading from stdin: %s", err.Error())
				return
			}

			logrus.Debug("Compressing stdin data into tar.gz")
			compressedData, err = compressStdinData(stdinData)
			if err != nil {
				fmt.Println("Error compressing stdin data")
				logrus.Debugf("Error compressing stdin data: %s", err.Error())
				return
			}
		} else {
			logrus.Debug("Compressing file/directory into tar.gz")
			compressedData, err = compressToBytes(filename)
			if err != nil {
				fmt.Println("Error compressing data")
				logrus.Debugf("Error compressing data: %s", err.Error())
				return
			}
		}
		fmt.Println("done!")

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

		fmt.Printf("Requesting a Secret Envelope from PigeonHole...")

		secretEnvelopeResponse, err := PigeonHoleClient.PostSecretWithResponse(GlobalCtx, newSecretRequest)

		// spew.Dump(s)
		if err != nil {
			logrus.Debugln(err.Error())
			fmt.Printf("failed!\n\nAdd --verbose for debug info\n")
			return
		} else {
			fmt.Println("done!")
		}

		if secretEnvelopeResponse.JSON201 != nil && secretEnvelopeResponse.StatusCode() == http.StatusCreated {
			logrus.Debugln("Secret envelope received, let's post this secret")

			fmt.Printf("Encrypting secret...")

			logrus.Debugf("Retrieving public keys")
			user_pubs, err := sdk.GetUserGPGArmoredPubKeysFromIdSlice(&GlobalCtx, secretEnvelopeResponse.JSON201)

			if err != nil {
				fmt.Println(err.Error())
				return
			}
			if len(user_pubs) == 0 {
				fmt.Printf("❌ - No public keys found for users.\n\nYou can use --use-ephemeral-keys (-e) to use an Ephemeral Key.\n\n")
				fmt.Printf("	pigeonhole secret post -r <email> -f ./myfile -e\n\n")
				fmt.Println("Visit https://pigeono.io/ephemeral-keys to find out more")
				return
			}
			logrus.Debugf("Found %d keys", len(user_pubs))
			for i := range user_pubs {
				logrus.Debugf("found public key: %s\n", user_pubs[i])
			}

			// Create temp file for encrypted data
			encryptedFile, err := os.CreateTemp(os.TempDir(), "pigeonhole-encrypted-")
			if err != nil {
				fmt.Println("Error creating temp file for encrypted data")
				logrus.Debugf("Error creating temp file: %s", err.Error())
				return
			}
			defer encryptedFile.Close()

			// Encrypt compressed data and write directly to file
			logrus.Debug("Encrypting compressed data")
			err = utils.EncryptStream(bytes.NewReader(compressedData), encryptedFile, user_pubs)
			if err != nil {
				fmt.Println("Encryption failed")
				logrus.Debugf("Encryption failed: %s", err.Error())
				return
			}

			encryptedFilePath := encryptedFile.Name()
			logrus.Debugf("Encrypted file created at: %s", encryptedFilePath)

			fmt.Println("done!")

			fmt.Printf("Posting secret...")
			errx := sdk.UploadFile(*secretEnvelopeResponse.JSON201, encryptedFilePath)
			if errx != nil {
				logrus.Debugln(errx.Error())
				fmt.Println("Failed to upload secret!")
			} else {
				fmt.Printf("done!\nSecret encrypted, posted and is en route as %s! 🚀\n\nA lot of time and effort goes into supporting PigeonHole.\nIf you like and find the service helpful, find out how you can support it at https://pigeono.io/about/contribute/\n", *secretEnvelopeResponse.JSON201.S3Info.Fields.XAmzMetaReference)
			}
			logrus.Debugf("Shredding encrypted temp file: %s", encryptedFilePath)
			utils.ShredFile(encryptedFilePath, 3)
		} else if secretEnvelopeResponse.StatusCode() == http.StatusNotAcceptable {
			// logrus.Debugf("Message from PigeonHole API: %s", *s.JSON204.Message)
			logrus.Debugf("PigeonHole API message: %s", *secretEnvelopeResponse.JSON406.Message)
			fmt.Printf("Some recipients are missing or haven't published a public key yet.\n\n")
			fmt.Printf("Add --use-ephemeral-keys (-e) to use ephemeral GPG keys\n\n	pigeonhole secret send -r <email> -f ./myfile -e\n\n")
			fmt.Printf("To find out more about ephemeral keys visit the website https://pigeono.io/keys/ephemeral-keys\n")
		} else if secretEnvelopeResponse.StatusCode() == http.StatusTooManyRequests {
			// Quota exceeded - too many secrets
			if secretEnvelopeResponse.JSON429 != nil {
				// fmt.Printf("- reach out to increase the quota\n")
				fmt.Printf("❌ Monthly active secret quota exceeded: %s\n", secretEnvelopeResponse.JSON429.Message)
				fmt.Println("You may;\n - Delete active unused secrets: pigeonhole secret delete -r <reference>\n - Request a quota increase: email quota@pigeono.io")
				// fmt.Printf("\nQuota Type: %s\n", secretEnvelopeResponse.JSON429.QuotaType)
				// fmt.Printf("Current Usage: %d\n", secretEnvelopeResponse.JSON429.CurrentUsage)
				// fmt.Printf("Limit: %d\n", secretEnvelopeResponse.JSON429.Limit)
			}
		} else if secretEnvelopeResponse.StatusCode() == http.StatusRequestEntityTooLarge {
			// Quota exceeded - file too large or total bytes exceeded
			if secretEnvelopeResponse.JSON413 != nil {
				fmt.Printf("❌ Monthly sent bytes quota exceeded: %s\n", secretEnvelopeResponse.JSON413.Message)
				if secretEnvelopeResponse.JSON413.Requested != nil {
					fmt.Printf("Requested: %s\n", formatBytes(*secretEnvelopeResponse.JSON413.Requested))
				}
			}
		} else if secretEnvelopeResponse.StatusCode() == 400 {
			fmt.Printf("failed: %s\n", *secretEnvelopeResponse.JSON400.Message)
		} else if secretEnvelopeResponse.StatusCode() == 401 {
			fmt.Printf("failed: %s\n", *secretEnvelopeResponse.JSON401.Message)
		} else if secretEnvelopeResponse.StatusCode() == 403 {
			fmt.Printf("failed: %s\n", *secretEnvelopeResponse.JSON403.Message)
		} else if secretEnvelopeResponse.StatusCode() == 404 {
			fmt.Printf("failed: %s\n", *secretEnvelopeResponse.JSON404.Message)
		} else if secretEnvelopeResponse.StatusCode() == 500 {
			logrus.Debugf("PigeonHole return message: %s", *secretEnvelopeResponse.JSON500.Message)
			fmt.Printf("🌭 The PigeonHole API is misbehaving: %s\n", *secretEnvelopeResponse.JSON500.Message)
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
				logrus.Debugln(*resp.JSON500.Message)
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
				logrus.Debugln(*respx.JSON200.Message)
				fmt.Printf("✅ Secret deleted for %s\n", *respx.JSON200.Secret.Reference)
			case http.StatusBadRequest:
				fmt.Printf("❌ No secret found for %s\n", secretQueryReference)
			case http.StatusInternalServerError:
				logrus.Debugln(*resp.JSON500.Message)
				fmt.Printf("Something went wrong deleting secret %s", secretQueryReference)
			case http.StatusNotFound:
				logrus.Debugln(*respx.JSON404.Message)
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
