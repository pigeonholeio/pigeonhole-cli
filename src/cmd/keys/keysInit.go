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
	"github.com/pigeonholeio/pigeonhole-cli/common"
	"github.com/spf13/cobra"
)

// keysInitCmd represents the init command
var KeysInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Force generate and push a new set of GPG keys - this will delete all your existing keys",
	Long:  `Use for the first time or if you want to wipe out all your keys.`,
	Run: func(cmd *cobra.Command, args []string) {
		common.GenerateKeys()
	},
}

func init() {

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// keysInitCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// keysInitCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
