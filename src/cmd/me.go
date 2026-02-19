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

	"github.com/pigeonholeio/common/utils"

	"github.com/spf13/cobra"
)

// meCmd represents the me command
var meCmd = &cobra.Command{
	Use:   "me",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		utils.DisplayHelp(cmd, args)

	},
}

// resetCmd represents the reset command
// var MeResetCmd = &cobra.Command{
// 	Use:   "roll-shortcode",
// 	Short: "A command to role your shortcode id",
// 	Long: `A longer description that spans multiple lines and likely contains examples
// and usage of using your command. For example:

// Cobra is a CLI library for Go that empowers applications.
// This application is a tool to generate the needed files
// to quickly create a Cobra application.`,
// 	Run: func(cmd *cobra.Command, args []string) {
// 		fmt.Printf("Rolling your short code...")
// 		// time.Sleep(3 * time.Second)
// 		req, _ := PigeonHoleClient.PostUserMeRotateshortcodeWithResponse(GlobalCtx)
// 		req, _ := PigeonHoleClient.postuserme(GlobalCtx)
// 		if req.StatusCode() == 204 {
// 			fmt.Println("done!")
// 		} else {
// 			fmt.Println("failed")
// 			return
// 		}

// 	},
// }

// detailsCmd represents the details command
var MeShowCmd = &cobra.Command{
	Use:   "show",
	Short: "A brief overview of your details",
	Long:  `A brief overview of your details containging email, keys, id and shortcode`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Context()
		me, _ := PigeonHoleClient.GetUserMeWithResponse(GlobalCtx)

		if me.StatusCode() == 200 && me.JSON200 != nil && me.JSON200.User != nil {
			utils.OutputData(me.JSON200.User)
		} else {
			fmt.Println("Failed to retrieve user information")
		}
	},
}

func init() {
	rootCmd.AddCommand(meCmd)
	meCmd.AddCommand(MeShowCmd)
	// meCmd.AddCommand(MeResetCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// meCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// meCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
