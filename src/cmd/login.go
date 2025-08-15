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
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/pigeonholeio/pigeonhole-cli/auth"
	"github.com/pigeonholeio/pigeonhole-cli/common"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// loginCmd represents the login command
var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Log into Pigeonhole using your Identity Provider",
	Long: `Log into your Identity Provider.
	
Pigeonhole currently only supports Azure Active Directory.
`,
	Run: func(cmd *cobra.Command, args []string) {
		logrus.Debug("CALLED LOGIN")

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Optionally tie ctx to SIGINT/SIGTERM so Ctrl+C cancels login
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)
		go func() {
			<-c
			logrus.Warn("Interrupt received, cancelling authentication...")
			cancel()
		}()

		idToken, err := auth.AuthenticateWithAzureDeviceCode(ctx, timeoutSec)
		if err != nil {
			logrus.Fatalf("Login failed: %v", err)
		}
		fmt.Println(idToken)

		if viper.GetString("key.latest.private") != "" {
			fmt.Print("Keys already configured - ")
		} else {
			fmt.Print("Keys not configured - ")
			common.GenerateKeys()
		}

		fmt.Println("You are now logged in!")
		fmt.Println("Now try sending a secret via 'pigeonhole secret send -r recipient@domain.com -p ./myfile'")
	},
}

func init() {
	rootCmd.AddCommand(loginCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// loginCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// loginCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
