package cmd

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/pigeonholeio/pigeonhole-cli/common"
	"github.com/pigeonholeio/pigeonhole-cli/logger"
	"github.com/pigeonholeio/pigeonhole-cli/sdk"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var SecretsDropCmd = &cobra.Command{
	Use:     "send",
	Aliases: []string{"post", "s", "drop", "ship"},
	Short:   "Post a secret securely",
	Long:    `Post a secret securely.`,
	PreRunE: func(cmd *cobra.Command, args []string) error {

		fileInfo, _ := os.Stdin.Stat()
		if (fileInfo.Mode() & os.ModeCharDevice) != 0 {
			requiredFlag, err := cmd.Flags().GetString("filepath")
			if err != nil || requiredFlag == "" {
				return fmt.Errorf(`You must specify a path '--filepath' or pipe from stdin like
	echo "HELLO" | pigeonhole secrets send -r recipient@domain.com
`)
			}
		}
		return nil
	},

	Run: func(cmd *cobra.Command, args []string) {
		recipients, _ := cmd.Flags().GetStringSlice("recipient")

		reference := common.GenerateCodeWord(3)
		newSecretRequest := sdk.CreateSecret{
			RecipientIds: recipients,
			Reference:    reference,
		}
		logger.Log.Debugf("Requesting secret upload payload")
		fmt.Print("Requesting the secret envolope...")

		s, err := common.GlobalPigeonHoleClient.SecretPostWithResponse(common.GlobalCtx, newSecretRequest)
		if err != nil {
			fmt.Println(err.Error())
		} else {
			fmt.Println("done!")
		}

		switch s.StatusCode() {
		case 400:
			logger.Log.Fatalf("[400] failed: %s\n", s.JSON400.Message)
		case 401:
			logger.Log.Fatalf("[401] failed: %s\n", s.JSON401.Message)
		case 403:
			logger.Log.Fatalf("[403] failed: %s\n", s.JSON403.Message)
		case 404:
			logger.Log.Fatalf("[404] failed: %s\n", s.JSON404.Message)
		case 500:
			logger.Log.Fatalf("[500] failed: %s\n", s.JSON500.Message)
		case 201:
			fmt.Print("Encrypting your message locally...")
			logger.Log.Debugf("Secret upload payload received %s/%s", *s.JSON201.S3Info.Url, *s.JSON201.S3Info.Fields.Key)
			secretSource, _ := os.Stdin.Stat()
			var filename string
			var isStdIn bool
			isStdIn = false
			if (secretSource.Mode() & os.ModeCharDevice) == 0 {
				logger.Log.Debugf("Secret source is stdin")
				tmpStdInPath, _ := os.CreateTemp(os.TempDir(), "pigeonhole-*.stdin.tmp")
				if err != nil {
					logger.Log.Fatal(err.Error())
				}
				defer tmpStdInPath.Close()
				if _, err := io.Copy(tmpStdInPath, os.Stdin); err != nil {
					logger.Log.Fatal(err.Error())
				}
				filename = tmpStdInPath.Name()
				logger.Log.Debugf("Wrote stdin to tmp file: %s", filename)
				isStdIn = true
			} else {
				logger.Log.Debugf("Secret source is filepath")
				filename, _ = cmd.Flags().GetString("filepath")
			}
			sourceFilePath, err := os.Stat(filename)

			if _, err := os.Stat(filename); err == nil {
				// File exists
			} else if os.IsNotExist(err) {
				fmt.Println("Path does not exist!")
				logger.Log.Debug("Path does not exist!")
				return
			} else {
				logger.Log.Debugf("Error: %s", err.Error())
			}

			tarballFile, _ := os.CreateTemp(os.TempDir(), "pigeonhole-*.tar.tmp")
			cwd, _ := os.Getwd()

			if sourceFilePath.IsDir() {
				logger.Log.Debugf("Found directory to compress and tar")
				os.Chdir(filename)
				common.CompressPath("./", tarballFile)
			} else {
				logger.Log.Debugf("Found file to compress and tar")
				parentDir := filepath.Dir(filename)
				os.Chdir(parentDir)
				common.CompressPath(filepath.Base(filename), tarballFile)
			}
			archivedFilename := tarballFile.Name()
			logger.Log.Debugf("Tar'd to file: %s", archivedFilename)
			os.Chdir(cwd)

			logger.Log.Debugf("Found %d recipients", len(recipients))
			user_pubs, err := common.GetUserGPGArmoredPubKeysFromIdSlice(recipients)

			if err != nil {
				fmt.Println(err.Error())
			}

			logger.Log.Debugf("Encrpyting with %d Public Keys", len(user_pubs))
			encFilename, errx := common.EncryptFile(archivedFilename, user_pubs)
			if errx != nil {
				fmt.Println(errx.Error())
			} else {
				fmt.Println("done!")
			}
			errx = uploadFile(*s.JSON201, encFilename)
			if errx != nil {
				logger.Log.Debugf("upload failed: %s", errx.Error())
				fmt.Println("upload failed")
				os.Exit(1)
			}

			if isStdIn {
				common.ShredFile(filename)
			}
			common.ShredFile(encFilename)
			common.ShredFile(archivedFilename)
			fmt.Printf("Secret posted as: %s\n", reference)
		default:
			logger.Log.Info("Something went wrong, check out the debug log.")
			logger.Log.Debugf("HTTP Status code was %s", s.StatusCode())
		}

	},
}

func init() {
	SecretsDropCmd.PersistentFlags().StringSliceP("recipient", "r", []string{}, "Email addresses or shorthand codes of the recipients")
	viper.BindPFlag("recipient", SecretsDropCmd.PersistentFlags().Lookup("recipient"))
	SecretsDropCmd.PersistentFlags().StringP("filepath", "f", "", "A path to a file or folder to send")
	SecretsDropCmd.Flags().StringP("name", "n", "", "If you want to override the encrypted secret code name for the secret drop")

}

func streamStdinToFile(response sdk.CreateSecretResponse) error {
	err := performUpload(os.Stdin, &response, *response.S3Info.Url)
	if err != nil {
		return fmt.Errorf("Error - " + err.Error())
	}
	return nil
}

func uploadFile(response sdk.CreateSecretResponse, filePath string) error {
	logger.Log.Debugf("Opening file for upload: %s", filePath)
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()
	err = performUpload(file, &response, *response.S3Info.Url)
	if err != nil {
		os.Exit(0)
	}
	return nil
}

func performUpload(reader io.Reader, response *sdk.CreateSecretResponse, callURL string) error {
	fmt.Print("Posting your secret...")
	var buffer bytes.Buffer
	mpWriter := multipart.NewWriter(&buffer)
	if err := addFieldsToWriter(mpWriter, response); err != nil {
		return err
	}
	part, err := mpWriter.CreatePart(textproto.MIMEHeader{
		"Content-Disposition": []string{"form-data; name=\"file\"; filename=\"" + *response.S3Info.Fields.Key + "\""},
		"Content-Type":        []string{"application/octet-stream"}, // Set the appropriate MIME type
	})

	if _, err = io.Copy(part, reader); err != nil {
		panic(err)
	}
	mpWriter.Close()

	// fmt.Println(callURL)
	contentSize := buffer.Len()
	logger.Log.Debugf("Secret size: %d", contentSize)
	request, err := http.NewRequest("POST", callURL, &buffer)
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", mpWriter.FormDataContentType())
	client := &http.Client{}
	responseHTTP, err := client.Do(request)
	if err != nil {
		return err
	}
	if responseHTTP.StatusCode == http.StatusBadRequest {
		fmt.Printf("failed!\nfailed: Secret too big. Check your account limits. Secret Size: %dMB\n", (contentSize / 1024 / 1024))
		bytes, _ := io.ReadAll(responseHTTP.Body)
		logger.Log.Debugf(string(bytes))
		return fmt.Errorf("Secret rejected, size too big")
	} else if responseHTTP.StatusCode != http.StatusNoContent {
		bytes, _ := io.ReadAll(responseHTTP.Body)
		logger.Log.Debugf(string(bytes))
		logger.Log.Fatalf("Something went wrong with the file upload")
		return fmt.Errorf("Something went wrong with the file upload")
	}
	fmt.Println("done!")
	return nil
}

func addFieldsToWriter(writer *multipart.Writer, response *sdk.CreateSecretResponse) error {

	fieldsValue := reflect.ValueOf(response.S3Info.Fields).Elem()
	for i := 0; i < fieldsValue.NumField(); i++ {
		field := fieldsValue.Field(i)

		fieldName := strings.Replace(fieldsValue.Type().Field(i).Tag.Get("json"), ",omitempty", "", 1)

		if field.Kind() == reflect.Ptr && !field.IsNil() {
			fieldValue := field.Elem().Interface()
			logger.Log.Debugf("ADDING: %s with value %s", fieldName, fieldValue)
			switch v := fieldValue.(type) {
			case string:
				if err := writer.WriteField(fieldName, v); err != nil {
					return err
				}
			case []string:
				for _, val := range v {
					if err := writer.WriteField(fieldName, val); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}
