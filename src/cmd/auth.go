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
	"os"
	"strings"

	"github.com/pigeonholeio/common/utils"
	"github.com/pigeonholeio/pigeonhole-cli/auth"
	"github.com/pigeonholeio/pigeonhole-cli/config"
	"github.com/pigeonholeio/pigeonhole-cli/sdk"

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
			fmt.Println("Available identity providers (✅ is default):")

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
			fmt.Printf("or with a specific provider;\n")
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
	Long:  `Log into your Identity Provider`,
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
		fmt.Printf("To view list of available Identity Providers use:\n	pigeonhole auth list\n\n")
		fmt.Printf("Using default provider: %s\n", *oidcProviders.JSON200.Default)
		var foundProvider sdk.OIDCProvider
		if DefaultOIDCProvider == "" {
			DefaultOIDCProvider = *oidcProviders.JSON200.Default
			foundProvider = (*oidcProviders.JSON200.OidcProviders)[DefaultOIDCProvider]
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
			fmt.Println("☠️  Error exchanging IdP token with PigeonHole")
			return
		}

		logrus.Debugf("PigeonHole Access Token Received: %s", pigeonHoleTokenresp.JSON201.AccessToken)
		PigeonHoleConfig.API.AccessToken = &pigeonHoleTokenresp.JSON201.AccessToken
		email, _ := PigeonHoleConfig.GetUserId()
		name, _ := PigeonHoleConfig.GetUserName()

		if PigeonHoleConfig.Identity == nil {
			logrus.Debugf("Identity is nil")
			PigeonHoleConfig.Identity = make(map[string]*config.UserIdentity)
		}

		if PigeonHoleConfig.Identity[email] == nil || PigeonHoleConfig.Identity[email].GPGKey == nil || !PigeonHoleConfig.Identity[email].GPGKey.KeyExists() {
			fmt.Printf("No GPG key pair found locally, generating keys for: %s (%s)\n", name, email)

			if PigeonHoleConfig.Identity[email] == nil {
				PigeonHoleConfig.Identity[email] = &config.UserIdentity{}
			}
			if PigeonHoleConfig.Identity[email].GPGKey == nil {
				PigeonHoleConfig.Identity[email].GPGKey = &config.GPGPair{}
			}

			if err := PigeonHoleConfig.Identity[email].GPGKey.EnsureKeyPair(&name, &email); err != nil {
				fmt.Println("failed to ensure keypair:", err)
				return
			}
			falsex := false
			reference, _ := os.Hostname()

			keyPost := sdk.PostUserMeKeyJSONRequestBody{
				Force:      &falsex,
				KeyData:    PigeonHoleConfig.Identity[email].GPGKey.PublicKey,
				Reference:  &reference,
				Thumbprint: PigeonHoleConfig.Identity[email].GPGKey.Thumbprint,
			}
			resp, err := PigeonHoleClient.PostUserMeKeyWithResponse(GlobalCtx, keyPost)
			if err != nil {
				logrus.Debugf(err.Error())
				fmt.Printf("Could not save new GPG Key\n")
			}
			switch resp.StatusCode() {
			case http.StatusCreated:
				fmt.Println("New keys saved")
			}

		} else {
			logrus.Debugf("local key already exists for: %s\n", email)
		}

		logrus.Debugf("Checking remote key exists for local key: %s\n\n", email)
		keysResponse, err := PigeonHoleClient.GetUserMeKeyValidateThumbprintWithResponse(GlobalCtx, *PigeonHoleConfig.Identity[email].GPGKey.Thumbprint)
		if err != nil {
			logrus.Debugf(err.Error())
		}
		if len(*keysResponse.JSON200.Keys) == 0 {
			logrus.Debugf("Pushing public key with fingerprint: %s ", *PigeonHoleConfig.Identity[email].GPGKey.Thumbprint)
			uploadKeyPayload := sdk.PostUserMeKeyJSONRequestBody{}
			uploadKeyPayload.KeyData = PigeonHoleConfig.Identity[email].GPGKey.PublicKey
			d, _ := os.Hostname()
			uploadKeyPayload.Reference = &d
			uploadKeyPayload.Thumbprint = PigeonHoleConfig.Identity[email].GPGKey.Thumbprint
			resp, err := PigeonHoleClient.PostUserMeKeyWithResponse(GlobalCtx, uploadKeyPayload)
			if err != nil {
				logrus.Debugf(err.Error())
				fmt.Printf("Failed to upload key to user %s with fingerprint: %s", email, *PigeonHoleConfig.Identity[email].GPGKey.Thumbprint)
				return
			}
			if resp.StatusCode() == http.StatusCreated {
				fmt.Printf("Key uploaded successfully with thumbprint: %s\n", *PigeonHoleConfig.Identity[email].GPGKey.Thumbprint)
			} else {
				logrus.Debugf("Response code: %d", resp.StatusCode())
				switch resp.StatusCode() {
				case http.StatusCreated:
					fmt.Printf("Key uploaded successfully with thumbprint: %s\n", *PigeonHoleConfig.Identity[email].GPGKey.Thumbprint)
				case http.StatusBadRequest:
					logrus.Debugln(*resp.JSON400.Message)
				case http.StatusInternalServerError:
					logrus.Debugln(*resp.JSON500.Message)
				}
				fmt.Println("Something went wrong")
				return
			}
		}

		PigeonHoleConfig.API.AccessToken = &pigeonHoleTokenresp.JSON201.AccessToken
		PigeonHoleConfig.API.AccessToken = &pigeonHoleTokenresp.JSON201.AccessToken
		err = PigeonHoleConfig.Save(v, &fullConfigPath)
		if err != nil {
			logrus.Debugf("config file not saved: %s", err.Error())
			fmt.Println("Failed to write config file!")
			return
		}

		fmt.Printf("\n🔐 Logged in as: %s!\n\n", email)
		fmt.Printf("Now try sending a secret;\n\n	pigeonhole secret send -r recipient@domain.com -f ./myfile\n")
	},
}
var DefaultOIDCProvider string

func init() {
	authCmd.AddCommand(authListCmd)
	authCmd.AddCommand(authLoginCmd)
	rootCmd.AddCommand(authCmd)

	authLoginCmd.PersistentFlags().StringVar(&DefaultOIDCProvider, "provider", "", "specify the identity provider you wish to authenticate with")
	rootCmd.AddCommand(authLoginCmd)

}
