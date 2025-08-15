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
	"github.com/pigeonholeio/pigeonhole-cli/sdk"
	"github.com/spf13/cobra"
)

// secretsListCmd represents the secretsList command
var SecretsListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"l", "ls"},
	Short:   "List out your secrets",
	Long:    `List your secrets that you can collect and decrypt`,
	Run: func(cmd *cobra.Command, args []string) {
		query, _ := cmd.Flags().GetString("query")
		// fmt.Println(query)
		s := sdk.SecretGetParams{}
		if query != "" {
			s.Reference = &query
		}
		f, _ := common.GlobalPigeonHoleClient.SecretGetWithResponse(common.GlobalCtx, &s)

		if len(*f.JSON200) > 0 {
			common.OutputData(f.JSON200)
		} else if f.StatusCode() == 400 {
			fmt.Printf("failed: %s\n", f.JSON400.Message)
		} else if f.StatusCode() == 401 {
			fmt.Printf("failed: %s\n", f.JSON401.Message)
		} else if f.StatusCode() == 403 {
			fmt.Printf("failed: %s\n", f.JSON403.Message)
		} else if f.StatusCode() == 500 {
			fmt.Printf("failed: %s\n", f.JSON500.Message)
		} else {
			fmt.Println("No secrets available")
		}

	},
}

func init() {
	SecretsListCmd.Flags().StringP("query", "q", "", "Query to find a secret")

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// secretsListCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// secretsListCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
