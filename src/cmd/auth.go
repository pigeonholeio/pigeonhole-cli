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
	"strings"

	"github.com/pigeonholeio/pigeonhole-cli/auth"
	"github.com/pigeonholeio/pigeonhole-cli/sdk"
	"github.com/pigeonholeio/pigeonhole-cli/utils"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// loginCmd represents the login command
var authListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available Identity Providers",
	Long: `List the available Identiy Providers, to allow you to log in with the correct Identity Provider.
`,
	Annotations: map[string]string{
		"skip-pre-run": "true",
	},
	Run: func(cmd *cobra.Command, args []string) {
		oidcProviders, err := PigeonHoleClient.GetAuthOidcProvidersWithResponse(GlobalCtx)
		if err != nil {
			logrus.Debugln(err.Error())
			fmt.Println("Something went wrong - could not retrieve a list of OIDC Providers")
			return
		}
		if len(*oidcProviders.JSON200.OidcProviders) > 0 {
			defaultProvider := *oidcProviders.JSON200.Default
			fmt.Println("List of available login providers (✅ is default)")

			for index, provider := range *oidcProviders.JSON200.OidcProviders {
				marker := ""
				detail := ""
				if index == defaultProvider {
					marker = "✅ "
				}
				if verbose {
					detail = fmt.Sprintf(":\n    Auth: %s\n    Token: %s\n    Device: %s\n", *provider.AuthUrl, *provider.TokenUrl, *provider.DeviceAuthURL)
				}
				fmt.Printf("- %s%s%s\n", marker, *provider.Name, detail)
			}

			fmt.Printf("\nYou can log in using the default provider with;\n")
			fmt.Printf("\n	pigeonhole auth login\n\n")
			fmt.Printf("or override with;\n")
			fmt.Printf("\n	pigeonhole auth login --provider %s\n\n", defaultProvider)
		} else {
			logrus.Debugln(oidcProviders.JSON200.Message)
			fmt.Println("No providers available")
		}
	},
}

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Log into PigeonHole with your Identity Provider",
	Long: `Use the auth command to manage the authentication with PigeonHole and your identity provider.

Use the following command to list the available identity providers.
Example:
	pigeonhole auth list
`,
	Annotations: map[string]string{
		"skip-pre-run": "true",
	},

	Run: func(cmd *cobra.Command, args []string) {
		utils.DisplayHelp(cmd, args)
	},
}

// loginCmd represents the login command
var authLoginCmd = &cobra.Command{
	Use:   "login",
	Short: "Log into Pigeonhole using your Identity Provider",
	Long: `Log into your Identity Provider.
	
Pigeonhole currently only supports Azure Active Directory.
`,
	Annotations: map[string]string{
		"skip-pre-run": "true",
	},
	Run: func(cmd *cobra.Command, args []string) {
		oidcProviders, err := PigeonHoleClient.GetAuthOidcProvidersWithResponse(GlobalCtx)
		if err != nil {
			logrus.Debugln(err.Error())
			fmt.Println("Something went wrong retrieving the default OIDC provider")
			return
		}
		var foundProvider sdk.OIDCProvider
		if DefaultOIDCProvider == "" {
			DefaultOIDCProvider = *oidcProviders.JSON200.Default
			foundProvider = (*oidcProviders.JSON200.OidcProviders)[DefaultOIDCProvider]

			// foundProvider = &oidcProviders.JSON200.OidcProviders[DefaultOIDCProvider]
		} else {
			DefaultOIDCProvider = strings.ToLower(DefaultOIDCProvider)
			if providers := oidcProviders.JSON200.OidcProviders; providers != nil {
				if provider, ok := (*providers)[DefaultOIDCProvider]; ok {
					foundProvider = provider
					logrus.Debugf("OIDC Provider found: [%s]{%s} %s", *provider.Name, *provider.ClientID, *provider.AuthUrl)
				} else {
					fmt.Println("Provider not found:", DefaultOIDCProvider)
					fmt.Printf("\nRun the following command to list available providers\n	pigeonhole auth list\n\n")
					return
				}
			}
		}

		logrus.Debugf("Using the provider: %s\n", DefaultOIDCProvider)
		// logrus.Debugf("Using the provider: %s", DefaultOIDCProvider)
		// oidcProviders, err := PigeonHoleClient.GetAuthOidcProvidersWithResponse(GlobalCtx)

		idPTok, err := auth.AuthenticateWithDeviceCode(GlobalCtx, *foundProvider.ClientID, &foundProvider)
		if err != nil {
			fmt.Printf("☠️  Could not authenticate with the identity provider: %s\n", *foundProvider.Name)
			logrus.Debugln(err.Error())
			return
		}
		logrus.Debugf("IdP Access Token: %s", idPTok.AccessToken)
		logrus.Debugf("IdP Token Type: %s", idPTok.TokenType)
		logrus.Debugf("IdP Token Expiry: %s", idPTok.Expiry)
		phTok := sdk.OIDCProviderToken{
			AccessToken: &idPTok.AccessToken,
		}
		// PigeonHoleClient.PostUserMeKeyWithResponse(GlobalCtx)
		pigeonHoleTokenresp, err := PigeonHoleClient.PostAuthOidcCleverHandlerWithResponse(GlobalCtx, &foundProvider, &phTok)
		if err != nil {
			logrus.Debugln(err.Error())
			fmt.Println("Error exchanging IdP token with PigeonHole")
			return
		}
		logrus.Debugf("PigeonHole Access Token: %s", pigeonHoleTokenresp.JSON201.AccessToken)
		// PigeonHoleClient.PostAuthOidcHandlerGeneric(GlobalCtx, phTok)
		// if err != nil {
		// 	logrus.Fatalf("Login failed: %v", err)
		// }
		// fmt.Println(idToken)

		// if viper.GetString("key.latest.private") != "" {
		// 	fmt.Print("Keys already configured - ")
		// } else {
		// 	fmt.Print("Keys not configured - ")
		// 	// utils.CreateGPGKeyPair()
		// 	// common.GenerateKeys()
		// }

		// fmt.Println("You are now logged in!")
		// fmt.Println("Now try sending a secret via 'pigeonhole secret send -r recipient@domain.com -p ./myfile'")
	},
}
var DefaultOIDCProvider string

func init() {
	authCmd.AddCommand(authListCmd)
	authCmd.AddCommand(authLoginCmd)
	rootCmd.AddCommand(authCmd)
	// // oidcProviders, err := PigeonHoleClient.GetAuthOidcProvidersWithResponse(GlobalCtx)

	authLoginCmd.PersistentFlags().StringVar(&DefaultOIDCProvider, "provider", "", "specify the identity provider you wish to authenticate with")

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// loginCmd.Flags().BoolP("list",, "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// loginCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
