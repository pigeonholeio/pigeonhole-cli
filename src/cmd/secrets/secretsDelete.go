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

	"github.com/pigeonholeio/pigeonhole-cli/common"
	"github.com/spf13/cobra"
)

// deleteCmd represents the delete command
var SecretsDeleteCmd = &cobra.Command{
	Use:     "delete",
	Aliases: []string{"del", "rm"},
	Short:   "Delete secrets you may no longer want or need",
	Long:    `Delete secrets you may no longer want or need.`,
	Run: func(cmd *cobra.Command, args []string) {

		all, _ := cmd.Flags().GetBool("all")
		id, _ := cmd.Flags().GetString("id")

		if id != "" {
			fmt.Println("Testing")
		} else if all {
			resp, _ := common.GlobalPigeonHoleClient.SecretDeleteWithResponse(common.GlobalCtx)
			if resp.StatusCode() == http.StatusOK {
				fmt.Println("All secrets deleted")
			} else {
				fmt.Println("Something went wrong")
			}
		} else {
			common.DisplayHelp(cmd, args)
		}

	},
}

func init() {

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// deleteCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	SecretsDeleteCmd.Flags().BoolP("all", "a", false, "Delete all secrets that you have sent/received")
}
