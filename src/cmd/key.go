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
	"os"

	"github.com/pigeonholeio/common/utils"
	"github.com/pigeonholeio/pigeonhole-cli/sdk"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// keysCmd represents the keys command
var keysCmd = &cobra.Command{
	Use:     "key",
	Aliases: []string{"keys"},
	Short:   "A collection of commands that handle your GPG keys",
	Long:    `Here you will find a collection of commands that can manage your GPG keys.`,
	Run: func(cmd *cobra.Command, args []string) {
		utils.DisplayHelp(cmd, args)
	},
}

// keysInitCmd represents the init command
var KeysCreateCmd = &cobra.Command{
	Use:     "create",
	Aliases: []string{"new"},
	Short:   "Create a new GPG key",
	Long: `Sometimes you may find it neccessary to create another GPG key e.g. another device or a bot.
	
Example:
pigeonhole key create
`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Print("Creating and pushing your new GPG key...")
		// claims, _ := utils.DecodePigeonHoleJWT(PigeonHoleConfig.API.AccessToken)
		// pub, priv, _, _ := utils.CreateGPGKeyPair(claims["name"].(string), claims["preferred_username"].(string))
		email, err := PigeonHoleConfig.GetUserName()
		identity := PigeonHoleConfig.Identity[email]
		if identity.GPGKey.KeyExists() {
			fmt.Println("No key found for email")
		} else {
			logrus.Debugf(identity.GPGKey.DecodedPublicKey())
		}
		return
		// PigeonHoleConfig.GpgKeys[email]
		// PigeonHoleConfig.GpgKeys.PrivateKeyBase64 = utils.EncodeToBase64(priv)
		// PigeonHoleConfig.GpgKeys.PublicKeyBase64 = utils.EncodeToBase64(pub)

		reference, _ := cmd.Flags().GetString("reference")
		clear, _ := cmd.Flags().GetBool("clear")
		force, _ := cmd.Flags().GetBool("force")
		c := PigeonHoleConfig.Identity[email].GPGKey.PublicKey
		x := sdk.NewKey{
			KeyData: c,
		}

		if reference != "" {
			x.Reference = &reference
		} else {
			n, _ := os.Hostname()
			x.Reference = &n
		}
		x.Only = &clear
		x.Force = &force

		f, err := PigeonHoleClient.PostUserMeKeyWithResponse(GlobalCtx, x)
		// f, err := utils.UserMeKeyPostWithResponse(GlobalCtx, x)

		if err != nil {
			logrus.Debugln(err.Error())
		}
		if f.StatusCode() == 201 {
			viper.WriteConfig()
			fmt.Println("done!")
		} else {
			fmt.Println("Something went wrong")
		}
	},
}

var KeysInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Force generate and push a new set of GPG keys - this will delete all your existing keys",
	Long:  `Use for the first time or if you want to wipe out all your keys.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Not implemented yet")
		// utils.GenerateKeys()
	},
}

// listCmd represents the list command
var KeysListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"l", "ls"},
	Short:   "List out your keys",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		// fmt.Println("list called")utils.DisplayHelp(cmd, args)
		x, err := PigeonHoleClient.GetUserMeKeyWithResponse(GlobalCtx)
		if err != nil {
			// fmt.Printf("ERROR: %s", err.Error())
			fmt.Println("Something went wrong - could not list secrets!")
			logrus.Debugln(err.Error())
		}
		if x.StatusCode() == 200 {
			if len(*x.JSON200.Keys) > 0 {
				utils.OutputData(x.JSON200.Keys)
			} else {
				fmt.Printf("No keys found on the server!\nUse `pigeonhole-cli keys init` to a GPG key pair to use\n")
			}
		} else {
			fmt.Printf("failed to get keys")
		}
	},
}

func init() {
	// KeysCreateCmd.Flags().AddFlag().
	KeysCreateCmd.PersistentFlags().BoolP("force", "f", false, "Force overwrite key with same reference")
	KeysCreateCmd.PersistentFlags().Bool("clear", false, "Clear out all other keys")
	KeysCreateCmd.PersistentFlags().StringP("reference", "r", "", "Override the reference for the key i.e. where it'll be used or created")
	rootCmd.AddCommand(keysCmd)
	keysCmd.AddCommand(KeysInitCmd)
	keysCmd.AddCommand(KeysListCmd)
	keysCmd.AddCommand(KeysCreateCmd)
	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// keysInitCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// keysInitCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
