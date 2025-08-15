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

// detailsCmd represents the details command
var MeShowCmd = &cobra.Command{
	Use:   "show",
	Short: "A brief overview of your details",
	Long:  `A brief overview of your details containging email, keys, id and shortcode`,
	Run: func(cmd *cobra.Command, args []string) {
		me, _ := common.GlobalPigeonHoleClient.UserMeGetWithResponse(common.GlobalCtx)
		// spew.Dump(me.JSON200)
		common.OutputData(me.JSON200)
	},
}

func init() {

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// detailsCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// detailsCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
