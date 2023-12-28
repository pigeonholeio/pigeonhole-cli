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
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// keysInitCmd represents the init command
var keysInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Force generate and push a new set of GPG keys",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Creating and pushing your new GPG keys")
		if viper.GetString("auth.token") == "" {
			logrus.Error("Not logged in")
		}
		// if viper.GetString("key.private") != nil {

		// }
		claims, _ := common.DecodePigeonHoleJWT()
		// spew.Dump(claims)
		// fmt.Println(claims["name"])/
		pub, priv, _ := common.CreateGPGKey(claims["name"].(string), claims["preferred_username"].(string))
		b64_priv := common.EncodeToBase64(priv)
		b64_pub := common.EncodeToBase64(pub)

		viper.Set("key.latest.public", b64_pub)
		viper.Set("key.latest.private", b64_priv)
		x := sdk.NewKey{}
		x.KeyData = &b64_pub
		f, err := GlobalPigeonHoleClient.UserMeKeyPostWithResponse(GlobalCtx, x)
		if err != nil {
			fmt.Println(err)
		}
		fmt.Println(f.StatusCode())
		viper.WriteConfig()
	},
}

func init() {
	keysCmd.AddCommand(keysInitCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// keysInitCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// keysInitCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
