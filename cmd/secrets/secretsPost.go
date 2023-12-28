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
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"os"
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
	Aliases: []string{"send", "drop", "ship"},
	Short:   "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		// Check if there is data in stdin
		fileInfo, _ := os.Stdin.Stat()
		if (fileInfo.Mode() & os.ModeCharDevice) == 0 {
			// There is data in stdin
			// fmt.Println("Data is being piped to stdin.")
		} else {
			// No data in stdin, check if the flag is set
			requiredFlag, err := cmd.Flags().GetString("path")
			if err != nil || requiredFlag == "" {
				return fmt.Errorf("You must specify a path '-p' or pipe from stdin")
			}
		}
		return nil
	},

	Run: func(cmd *cobra.Command, args []string) {
		// fmt.Println(common.GenerateCodeWord(2))
		// fileInfo, _ := os.Stdin.Stat()
		recipients, _ := cmd.Flags().GetStringSlice("recipient")

		newSecretRequest := sdk.CreateSecret{
			RecipientIds: recipients,
			Reference:    common.GenerateCodeWord(2),
		}

		s, err := common.GlobalPigeonHoleClient.SecretPostWithResponse(common.GlobalCtx, newSecretRequest)
		if err != nil {
			fmt.Println(err.Error())
		}

		filename, _ := cmd.Flags().GetString("path")
		testFilePath, _ := os.Stat(filename)
		tarballFilePath, _ := ioutil.TempFile(os.TempDir(), "pigeonhole")
		if testFilePath.IsDir() {
			cwd, _ := os.Getwd()
			os.Chdir(filename)
			common.CompressPath("./", tarballFilePath)
			os.Chdir(cwd)
			filename = tarballFilePath.Name()
		} else {
			// var errx error
			// if (fileInfo.Mode() & os.ModeCharDevice) == 0 {
			// 	// There is data in stdin
			// 	errx = uploadStdin(*s.JSON200)
			// } else {

			// }
		}

		user_pubs, _ := common.GetUserGPGArmoredPubKeysFromIdSlice(recipients)
		filename, _ = common.EncryptFile(filename, user_pubs)

		errx := uploadFile(*s.JSON200, filename)
		if errx != nil {
			fmt.Println(errx)
		}
		common.ShredFile(filename)

	},
}

func init() {

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// dropCmd.PersistentFlags().StringP("recipient", "r", "", "Email address or shorthand code of the recipient")
	SecretsDropCmd.PersistentFlags().StringSliceP("recipient", "r", []string{}, "Email addresses or shorthand codes of the recipients")
	viper.BindPFlag("recipient", SecretsDropCmd.PersistentFlags().Lookup("recipient"))
	SecretsDropCmd.PersistentFlags().StringP("path", "p", "", "A help for foo")
	SecretsDropCmd.Flags().StringP("name", "n", "", "If you want to override the encrypted secret code name for the secret drop")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// dropCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

// func saveInput(cmd *cobra.Command, args []string) {
// 	filename := args[0]
// 	file, err := os.Create(filename)
// 	if err != nil {
// 		fmt.Fprintf(os.Stderr, "Failed to create file: %v\n", err)
// 		os.Exit(1)
// 	}
// 	defer file.Close()

// 	_, err = io.Copy(file, os.Stdin)
// 	if err != nil {
// 		fmt.Fprintf(os.Stderr, "Failed to write to file: %v\n", err)
// 		os.Exit(1)
// 	}
// }
func uploadStdin(response sdk.CreateSecretResponse) error {
	// fileInfo, _ := os.Stdin.Stat()
	// _, err := io.Copy(&buffer, os.Stdin)
	err := performUpload(os.Stdin, &response, *response.S3Info.Url)
	if err != nil {
		return fmt.Errorf("Error - " + err.Error())
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
		fmt.Println("Secret rejected, likely for being too large")
	} else if responseHTTP.StatusCode != http.StatusNoContent {
		bytes, _ := io.ReadAll(responseHTTP.Body)
		fmt.Println(string(bytes))
		return fmt.Errorf("Something went wrong with the file upload")
	} else {
		fmt.Println(fmt.Sprintf("Secret encrypted and posted successfully as %s!", *response.S3Info.Fields.XAmzMetaReference))
	}
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
