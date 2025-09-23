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
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/davecgh/go-spew/spew"
	"github.com/pigeonholeio/common/utils"
	"github.com/pigeonholeio/pigeonhole-cli/sdk"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

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
		f, err := PigeonHoleClient.GetSecretWithResponse(GlobalCtx, &s)
		if err != nil {
			logrus.Debugf(err.Error())
			fmt.Println("Something went wrong with the PigeonHole API")
		}
		code := f.StatusCode()

		logrus.Debugf("PigeonHole return status: %d", code)

		if *f.JSON200.Secrets != nil && len(*f.JSON200.Secrets) > 0 {
			logrus.Debugf("PigeonHole return message: %s", *f.JSON200.Message)

			utils.OutputData(sdk.ToSecretViewSlice(*f.JSON200.Secrets))

		} else if f.StatusCode() == 400 {
			fmt.Printf("failed: %s\n", *f.JSON400.Message)
		} else if f.StatusCode() == 401 {
			fmt.Printf("failed: %s\n", *f.JSON401.Message)
		} else if f.StatusCode() == 403 {
			fmt.Printf("failed: %s\n", *f.JSON403.Message)
		} else if f.StatusCode() == 404 {
			fmt.Printf("failed: %s\n", *f.JSON404.Message)
		} else if f.StatusCode() == 500 {
			logrus.Debugf("PigeonHole return message: %s", *f.JSON500.Message)
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
		reference := utils.GenerateCodeWord(2)

		newSecretRequest := sdk.CreateSecretEnvolopeOptions{ //PostSecretJSONRequestBody
			RecipientIds:  recipients,
			Reference:     reference,
			Ephemeralkeys: &useEpheralKeys,
		}

		fmt.Printf("📩 Requesting a Secret Envolope from PigeonHole...")

		secretEnvolopeResponse, err := PigeonHoleClient.PostSecretWithResponse(GlobalCtx, newSecretRequest)

		// spew.Dump(s)
		if err != nil {
			logrus.Debugln(err.Error())
			fmt.Printf("failed!\n\nAdd --verbose for debug info\n")
			return
		} else {
			fmt.Println("done!")
		}

		if secretEnvolopeResponse.JSON201 != nil && secretEnvolopeResponse.StatusCode() == http.StatusCreated {
			logrus.Debugln("Secret envelope received, let's post this secret")

			// viper.WriteConfig()
			fmt.Printf("🔐 Encrypting secret...")

			logrus.Debugf("Creating tmp file for tar archive: ")
			tarballFilePath, _ := os.CreateTemp(os.TempDir(), "pigeonhole-")
			logrus.Debugln(tarballFilePath.Name())

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

				logrus.Debugf("Compressing file: %s\n", tarballFilePath.Name())
				utils.CompressPath(filepath.Base(filename), tarballFilePath)
			}
			filename = tarballFilePath.Name()

			os.Chdir(cwd)
			logrus.Debugf("Retrieving public keys")
			if 0 == 1 {
				spew.Dump(secretEnvolopeResponse.JSON201.Users)

			}
			user_pubs, _ := sdk.GetUserGPGArmoredPubKeysFromIdSlice(&GlobalCtx, secretEnvolopeResponse.JSON201)

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

			filename, _ = utils.EncryptFile(filename, user_pubs)
			fmt.Println("done!")
			// fmt.Printf("🕊️  Posting secret to your recipient...")

			errx := sdk.UploadFile(*secretEnvolopeResponse.JSON201, filename)
			if errx != nil {
				logrus.Debugln(errx.Error())
				fmt.Println("Failed to upload secret!")
			} else {
				// fmt.Println("done!")
				fmt.Printf(fmt.Sprintf("🕊️  Secret encrypted and posted successfully as %s!\n", *secretEnvolopeResponse.JSON201.S3Info.Fields.XAmzMetaReference))

			}
			utils.ShredFile(filename)

		} else if secretEnvolopeResponse.StatusCode() == http.StatusNotAcceptable {

			// logrus.Debugf("Message from PigeonHole API: %s", *s.JSON204.Message)
			logrus.Debugf("PigeonHole API message: %s", *secretEnvolopeResponse.JSON406.Message)
			fmt.Printf("Some recipients are missing.\n\n")
			fmt.Printf("Add --use-ephemeral-keys (-e) to use ephemeral GPG keys\n\n	pigeonhole secret send -r <email> -f ./myfile -e\n\n")
			fmt.Printf("To find out more about ephemeral keys visit the website https://pigeono.io/keys/ephemeral-keys\n")
		} else if secretEnvolopeResponse.StatusCode() == 400 {
			fmt.Printf("failed: %s\n", *secretEnvolopeResponse.JSON400.Message)
		} else if secretEnvolopeResponse.StatusCode() == 401 {
			fmt.Printf("failed: %s\n", *secretEnvolopeResponse.JSON401.Message)
		} else if secretEnvolopeResponse.StatusCode() == 403 {
			fmt.Printf("failed: %s\n", *secretEnvolopeResponse.JSON403.Message)
		} else if secretEnvolopeResponse.StatusCode() == 404 {
			fmt.Printf("failed: %s\n", *secretEnvolopeResponse.JSON404.Message)
		} else if secretEnvolopeResponse.StatusCode() == 500 {
			logrus.Debugf("PigeonHole return message: %s", *secretEnvolopeResponse.JSON500.Message)
			fmt.Printf("🌭 The PigeonHole API is misbehaving: %s\n", *secretEnvolopeResponse.JSON500.Message)
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
				fmt.Printf("secret deleted for: %s\n", secretQueryReference)

			case http.StatusInternalServerError:
				logrus.Debugln(*resp.JSON500.Message)
				fmt.Printf("Something went wrong deleting secret: %s", secretQueryReference)
			case http.StatusNotFound:
				logrus.Debugln(*respx.JSON404.Message)
				fmt.Printf("No secret found for: %s\n", secretQueryReference)
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
)

func init() {
	rootCmd.AddCommand(secretsCmd)
	secretsCmd.AddCommand(SecretsCollectCmd)
	secretsCmd.AddCommand(SecretsDeleteCmd)
	secretsCmd.AddCommand(SecretsDropCmd)
	secretsCmd.AddCommand(SecretsListCmd)

	SecretsCollectCmd.Flags().StringVarP(&downloadSecretPath, "filepath", "f", "", "The path where to download, decrypt and extract your secret")
	SecretsCollectCmd.Flags().StringVarP(&secretQueryReference, "reference", "r", "", "The id or reference of the secret")
	SecretsCollectCmd.MarkFlagRequired("filepath")
	SecretsCollectCmd.MarkPersistentFlagRequired("reference")

	SecretsDeleteCmd.Flags().BoolVarP(&deleteAllSecrets, "all", "a", false, "Delete all secrets that you have sent/received")
	SecretsDeleteCmd.Flags().StringVarP(&secretQueryReference, "reference", "r", "", "The id or reference of the secret")

	SecretsDropCmd.Flags().BoolVarP(&useEpheralKeys, "use-ephemeral-keys", "e", false, "manage the use of ephemeral keys (Default: false)")
	SecretsDropCmd.Flags().StringSliceVarP(&recipients, "recipient", "r", nil, "Email addresses of the recipients (add multiple or separate with comma)")
	SecretsDropCmd.Flags().StringVarP(&filename, "filepath", "f", "", "A path to a file or folder to send")
	// SecretsDropCmd.Flags().StringVarP(&secretQueryReference, "reference", "r", "", "If you want to override the encrypted secret code name for the secret drop")
	SecretsDropCmd.MarkFlagRequired("filepath")
	SecretsDropCmd.MarkFlagRequired("recipient")
	SecretsListCmd.Flags().StringVarP(&secretQueryReference, "reference", "r", "", "The id or reference of the secret")
	// viper.BindPFlag("recipient", SecretsDropCmd.PersistentFlags().Lookup("recipient"))

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// secretsCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// secretsCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
