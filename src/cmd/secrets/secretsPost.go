/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
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
	"github.com/pigeonholeio/pigeonhole-cli/sdk"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

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
				return fmt.Errorf("You must specify a path '-p' or pipe from stdin")
			}
		}
		return nil
	},

	Run: func(cmd *cobra.Command, args []string) {
		filename, _ := cmd.Flags().GetString("filepath")

		resolvedPath, err := filepath.Abs(filename)
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

		recipients, _ := cmd.Flags().GetStringSlice("recipient")

		newSecretRequest := sdk.CreateSecret{
			RecipientIds: recipients,
			Reference:    common.GenerateCodeWord(2),
		}
		logrus.Debugln("Retrieving a secret envelope from PigeonHole")

		fmt.Printf("📩 Retrieving a secret envolope from PigeonHole...")
		s, err := common.GlobalPigeonHoleClient.SecretPostWithResponse(common.GlobalCtx, newSecretRequest)
		if err != nil {
			logrus.Debug(err.Error())
			fmt.Println("Retrieving secret envelope failed! Add --verbose for debug info")
		} else {
			fmt.Println("done!")
		}

		bodyBytes, _ := io.ReadAll(s.HTTPResponse.Body)
		if s.StatusCode() == 400 {
			logrus.Debugf("Debug info: %s\n", string(bodyBytes))
			fmt.Printf("failed: %s\n", s.JSON400.Message)
		} else if s.StatusCode() == 401 {
			fmt.Printf("failed: %s\n", s.JSON401.Message)
			logrus.Debugf("Debug info: %s\n", string(bodyBytes))
		} else if s.StatusCode() == 403 {
			fmt.Printf("failed: %s\n", s.JSON403.Message)
			logrus.Debugf("Debug info: %s\n", string(bodyBytes))
		} else if s.StatusCode() == 500 {
			fmt.Printf("failed: %s\n", s.JSON500.Message)
			logrus.Debugf("Debug info: %s\n", string(bodyBytes))
		}
		if s.StatusCode() == 201 {
			logrus.Debugln("Secret envelope received, let's post this secret")
			viper.WriteConfig()
			fmt.Printf("🔐 Encrypting secret...")
			tarballFilePath, _ := os.CreateTemp(os.TempDir(), "pigeonhole")
			cwd, _ := os.Getwd()
			testFilePath, _ := os.Stat(filename)
			if testFilePath.IsDir() {
				logrus.Debug("Found directory, taring the directory")
				os.Chdir(filename)
				common.CompressPath("./", tarballFilePath)
			} else {
				logrus.Debug("Found a file, let's tar just the file")
				parentDir := filepath.Dir(filename)
				os.Chdir(parentDir)
				common.CompressPath(filepath.Base(filename), tarballFilePath)
			}
			filename = tarballFilePath.Name()
			os.Chdir(cwd)
			user_pubs, _ := common.GetUserGPGArmoredPubKeysFromIdSlice(recipients)
			filename, _ = common.EncryptFile(filename, user_pubs)
			fmt.Println("done!")
			fmt.Printf("🕊️  Posting secret to your recipient...")
			errx := uploadFile(*s.JSON201, filename)
			if errx != nil {
				fmt.Println(errx)
			} else {
				fmt.Println("done!")
				fmt.Printf(fmt.Sprintf("\nSecret encrypted and posted successfully as %s!\n", *s.JSON201.S3Info.Fields.XAmzMetaReference))

			}
			common.ShredFile(filename)

		}

	},
}

func init() {
	SecretsDropCmd.PersistentFlags().StringSliceP("recipient", "r", []string{}, "Email addresses or shorthand codes of the recipients")
	viper.BindPFlag("recipient", SecretsDropCmd.PersistentFlags().Lookup("recipient"))
	SecretsDropCmd.PersistentFlags().StringP("filepath", "f", "", "A path to a file or folder to send")
	SecretsDropCmd.Flags().StringP("name", "n", "", "If you want to override the encrypted secret code name for the secret drop")

}

func uploadStdin(response sdk.CreateSecretResponse) error {
	err := performUpload(os.Stdin, &response, *response.S3Info.Url)
	if err != nil {
		return fmt.Errorf("Oops! %s", err.Error())
	}
	return nil
}

func uploadFile(response sdk.CreateSecretResponse, filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	err = performUpload(file, &response, *response.S3Info.Url)
	if err != nil {
		return fmt.Errorf("Oops! %s", err.Error())
	}
	return nil
}

func performUpload(reader io.Reader, response *sdk.CreateSecretResponse, callURL string) error {
	var buffer bytes.Buffer

	mpWriter := multipart.NewWriter(&buffer)

	// fmt.Println(*response.S3Info.Fields.Key)
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
	logrus.Debugf("HTTP POST URL: %s", callURL)
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
		return fmt.Errorf("Secret rejected for exceeding your quota")
		// fmt.Println("")
	} else if responseHTTP.StatusCode != http.StatusNoContent {
		bytes, _ := io.ReadAll(responseHTTP.Body)
		fmt.Println(string(bytes))
		return fmt.Errorf("Something went wrong with the file upload")
	}
	// else {
	// 	fmt.Println(fmt.Sprintf("Secret encrypted and posted successfully as %s!", *response.S3Info.Fields.XAmzMetaReference))
	// }
	return nil
}

func addFieldsToWriter(writer *multipart.Writer, response *sdk.CreateSecretResponse) error {

	fieldsValue := reflect.ValueOf(response.S3Info.Fields).Elem()
	for i := 0; i < fieldsValue.NumField(); i++ {
		field := fieldsValue.Field(i)

		fieldName := strings.Replace(fieldsValue.Type().Field(i).Tag.Get("json"), ",omitempty", "", 1)

		if field.Kind() == reflect.Ptr && !field.IsNil() {
			fieldValue := field.Elem().Interface()
			logrus.Debug(fmt.Sprintf("ADDING: %s with value %s", fieldName, fieldValue))
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
