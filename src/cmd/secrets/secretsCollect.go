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

	"github.com/pigeonholeio/pigeonhole-cli/common"
	"github.com/spf13/cobra"
)

// collectCmd represents the collect command
var SecretsCollectCmd = &cobra.Command{
	Use:     "collect",
	Aliases: []string{"c", "download", "get"},
	Short:   "Retrieve and decrypt secrets",
	Long:    `Retrieve and decrypt secrets`,
	Run: func(cmd *cobra.Command, args []string) {
		ref, _ := cmd.Flags().GetString("reference")
		path, _ := cmd.Flags().GetString("path")
		blob, _ := common.GlobalPigeonHoleClient.DownloadSecretBlobWithResponse(common.GlobalCtx, ref)
		var filename string
		if blob.StatusCode() == 404 {
			fmt.Println("No secret found")
			return
		} else {
			// bodyBytes, _ := ioutil.ReadAll(blob.Body)
			// fmt.Println(string(blob.Body))
		}
		filename, _ = common.DecryptBytes(blob.Body, path)
		common.DecompressFile(filename, path)
		common.ShredFile(filename)
		// common.DecompressFile()
		// spew.Dump(blob.HTTPResponse.Body)

		// spew.Dump(blob.Body) // pass this blob.Body to the decrypt function
		// reader := bytes.NewReader(blob.HTTPResponse.Body)

		// myString := string(blob.)

		// fmt.Println(myString)
	},
}

func init() {

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	SecretsCollectCmd.PersistentFlags().StringP("reference", "r", "", "The id or reference of the secret")
	SecretsCollectCmd.MarkPersistentFlagRequired("reference")
	SecretsCollectCmd.PersistentFlags().StringP("path", "p", "", "The path where to download, decrypt and extract your secret")
	SecretsCollectCmd.MarkFlagRequired("path")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// collectCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
