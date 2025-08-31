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

	"github.com/pigeonholeio/pigeonhole-cli/sdk"
	"github.com/pigeonholeio/pigeonhole-cli/utils"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// secretsCmd represents the secrets command
var secretsCmd = &cobra.Command{
	Use:     "secret",
	Aliases: []string{"secrets", "s"},
	Short:   "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		utils.DisplayHelp(cmd, args)
		// fmt.Println("secrets called")

		// fmt.Println(secrets.JSON200)
		// spew.Dump(secrets)
	},
}

// collectCmd represents the collect command
var SecretsCollectCmd = &cobra.Command{
	Use:     "collect",
	Aliases: []string{"c", "download", "get"},
	Short:   "Retrieve and decrypt secrets",
	Long:    `Retrieve and decrypt secrets`,
	Run: func(cmd *cobra.Command, args []string) {
		ref, _ := cmd.Flags().GetString("reference")
		path, _ := cmd.Flags().GetString("path")

		blob, _ := PigeonHoleClient.GetSecretSecretIdDownloadWithResponse(GlobalCtx, ref)
		var filename string
		if blob.StatusCode() == 404 {
			fmt.Println("No secret found")
			return
		} else {
			// bodyBytes, _ := ioutil.ReadAll(blob.Body)
			// fmt.Println(string(blob.Body))
		}
		filename, _ = utils.DecryptBytes(blob.Body, path)
		utils.DecompressFile(filename, path)
		utils.ShredFile(filename)
		// utils.DecompressFile()
		// spew.Dump(blob.HTTPResponse.Body)

		// spew.Dump(blob.Body) // pass this blob.Body to the decrypt function
		// reader := bytes.NewReader(blob.HTTPResponse.Body)

		// myString := string(blob.)

		// fmt.Println(myString)
	},
}

// secretsListCmd represents the secretsList command
var SecretsListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"l", "ls"},
	Short:   "List out your secrets",
	Long:    `List your secrets that you can collect and decrypt`,
	Run: func(cmd *cobra.Command, args []string) {
		query, _ := cmd.Flags().GetString("query")
		// fmt.Println(query)
		s := sdk.GetSecretParams{}
		if query != "" {
			s.Reference = &query
		}
		// f, _ := PigeonHoleClient.GetSecret()
		f, _ := PigeonHoleClient.GetSecretWithResponse(GlobalCtx, &s)

		if len(*f.JSON200.Secrets) > 0 {
			utils.OutputData(f.JSON200.Secrets)
		} else if f.StatusCode() == 400 {
			fmt.Printf("failed: %s\n", *f.JSON400.Message)
		} else if f.StatusCode() == 401 {
			fmt.Printf("failed: %s\n", *f.JSON401.Message)
		} else if f.StatusCode() == 403 {
			fmt.Printf("failed: %s\n", *f.JSON403.Message)
		} else if f.StatusCode() == 500 {
			fmt.Printf("failed: %s\n", *f.JSON500.Message)
		} else {
			fmt.Println("No secrets found")
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
			Reference:    utils.GenerateCodeWord(2),
		}
		logrus.Debugln("Retrieving a secret envelope from PigeonHole")

		fmt.Printf("📩 Retrieving a secret envolope from PigeonHole...")
		s, err := PigeonHoleClient.PostSecretWithResponse(GlobalCtx, newSecretRequest)
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
				utils.CompressPath("./", tarballFilePath)
			} else {
				logrus.Debug("Found a file, let's tar just the file")
				parentDir := filepath.Dir(filename)
				os.Chdir(parentDir)
				utils.CompressPath(filepath.Base(filename), tarballFilePath)
			}
			filename = tarballFilePath.Name()
			os.Chdir(cwd)
			// user_pubs, _ := utils.GetUserGPGArmoredPubKeysFromIdSlice(recipients)
			user_pubs, _ := sdk.GetUserGPGArmoredPubKeysFromIdSlice(GlobalCtx, &PigeonHoleClient, recipients)
			filename, _ = utils.EncryptFile(filename, user_pubs)
			fmt.Println("done!")
			fmt.Printf("🕊️  Posting secret to your recipient...")
			errx := uploadFile(*s.JSON201, filename)
			if errx != nil {
				fmt.Println(errx)
			} else {
				fmt.Println("done!")
				fmt.Printf(fmt.Sprintf("\nSecret encrypted and posted successfully as %s!\n", *s.JSON201.S3Info.Fields.XAmzMetaReference))

			}
			utils.ShredFile(filename)

		}

	},
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

var SecretsDeleteCmd = &cobra.Command{
	Use:     "delete",
	Aliases: []string{"del", "rm"},
	Short:   "Delete secrets you may no longer want or need",
	Long:    `Delete secrets you may no longer want or need.`,
	Run: func(cmd *cobra.Command, args []string) {

		all, _ := cmd.Flags().GetBool("all")
		id, _ := cmd.Flags().GetString("id")
		if id != "" && !all {
			utils.DisplayHelp(cmd, args)
		}
		// var resp DeleteSecretSecretIdResponse
		var statusCode int

		if all {
			resp, err := PigeonHoleClient.DeleteSecretWithResponse(GlobalCtx)
			if err != nil {
				logrus.Debugln(err.Error())
				return
			}
			statusCode = resp.StatusCode()
		} else {
			resp, err := PigeonHoleClient.DeleteSecretSecretIdWithResponse(GlobalCtx, id) // DeleteSecretWithResponse(GlobalCtx)
			if err != nil {
				logrus.Debugln(err.Error())
				return
			}
			statusCode = resp.StatusCode()
		}
		fmt.Println(statusCode)

		if statusCode == http.StatusOK && all {
			fmt.Println("All secrets deleted")
		} else if statusCode == http.StatusOK {
			fmt.Printf("Secret '%s' deleted", id)
		} else if statusCode != http.StatusOK {
			fmt.Println("Something went wrong")
			logrus.Debugln("Something went wrong: %d", statusCode)

		}
	},
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

func init() {
	rootCmd.AddCommand(secretsCmd)
	secretsCmd.AddCommand(SecretsListCmd)
	secretsCmd.AddCommand(SecretsDropCmd)
	secretsCmd.AddCommand(SecretsDeleteCmd)
	secretsCmd.AddCommand(SecretsCollectCmd)
	SecretsCollectCmd.PersistentFlags().StringP("reference", "r", "", "The id or reference of the secret")
	SecretsCollectCmd.MarkPersistentFlagRequired("reference")
	SecretsCollectCmd.PersistentFlags().StringP("path", "p", "", "The path where to download, decrypt and extract your secret")
	SecretsCollectCmd.MarkFlagRequired("path")
	SecretsDeleteCmd.Flags().BoolP("all", "a", false, "Delete all secrets that you have sent/received")
	SecretsListCmd.Flags().StringP("query", "q", "", "Query to find a secret")
	SecretsDropCmd.PersistentFlags().StringSliceP("recipient", "r", []string{}, "Email addresses or shorthand codes of the recipients")
	viper.BindPFlag("recipient", SecretsDropCmd.PersistentFlags().Lookup("recipient"))
	SecretsDropCmd.PersistentFlags().StringP("filepath", "f", "", "A path to a file or folder to send")
	SecretsDropCmd.Flags().StringP("name", "n", "", "If you want to override the encrypted secret code name for the secret drop")

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// secretsCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// secretsCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
