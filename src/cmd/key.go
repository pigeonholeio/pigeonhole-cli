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
	cmd "github.com/pigeonholeio/pigeonhole-cli/cmd/keys"
	"github.com/pigeonholeio/pigeonhole-cli/common"
	"github.com/spf13/cobra"
)

// keysCmd represents the keys command
var keysCmd = &cobra.Command{
	Use:     "key",
	Aliases: []string{"keys"},
	Short:   "A collection of commands that handle your GPG keys",
	Long:    `Here you will find a collection of commands that can manage your GPG keys.`,
	Run: func(cmd *cobra.Command, args []string) {
		common.DisplayHelp(cmd, args)
	},
}

func init() {
	rootCmd.AddCommand(keysCmd)
	keysCmd.AddCommand(cmd.KeysInitCmd)
	keysCmd.AddCommand(cmd.KeysListCmd)
	keysCmd.AddCommand(cmd.KeysCreateCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// keysCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// keysCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
