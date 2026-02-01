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
	"time"

	"github.com/pigeonholeio/common/utils"
	"github.com/pigeonholeio/pigeonhole-cli/auth"
	"github.com/pigeonholeio/pigeonhole-cli/config"
	"github.com/pigeonholeio/pigeonhole-cli/sdk"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// loginCmd represents the login command
var authListCmd = &cobra.Command{
	Use:     "list-providers",
	Aliases: []string{"list", "providers", "list-idps", "idps"},
	Short:   "List available Identity Providers",
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

		if oidcProviders == nil || oidcProviders.JSON200 == nil {
			fmt.Println("☠️ Invalid response from PigeonHole servers - no providers available")
			return
		}

		var foundProvider sdk.OIDCProvider

		if UseOIDCProvider == "" { // assumes not set
			if oidcProviders.JSON200.Default == nil {
				fmt.Println("☠️ No default OIDC provider configured")
				fmt.Printf("To view list of available Identity Providers use:\n	pigeonhole auth list\n\n")
				return
			}
			fmt.Printf("To view list of available Identity Providers use:\n	pigeonhole auth list\n\n")
			fmt.Printf("Using default provider: %s\n", *oidcProviders.JSON200.Default)
			UseOIDCProvider = *oidcProviders.JSON200.Default
			foundProvider = (*oidcProviders.JSON200.OidcProviders)[UseOIDCProvider]
		} else {
			UseOIDCProvider = strings.ToLower(UseOIDCProvider)
			if providers := oidcProviders.JSON200.OidcProviders; providers != nil {
				if provider, ok := (*providers)[UseOIDCProvider]; ok {
					foundProvider = provider
					logrus.Debugf("OIDC Provider found: [%s]{%s} %s", *provider.Name, *provider.ClientID, *provider.AuthUrl)
				} else {
					fmt.Println("Provider not found:", UseOIDCProvider)
					fmt.Printf("\nRun the following command to list available providers\n	pigeonhole auth list\n\n")
					return
				}
			}
		}

		logrus.Debugf("Using the provider: %s\n", UseOIDCProvider)

		// Extract audience from PigeonHole API URL for IdP authentication
		// var audience string
		// if PigeonHoleConfig.API != nil && PigeonHoleConfig.API.Url != nil && *PigeonHoleConfig.API.Url != "" {
		// 	if parsedURL, err := url.Parse(*PigeonHoleConfig.API.Url); err == nil {
		// 		audience = parsedURL.Scheme + "://" + parsedURL.Host
		// 		logrus.Debugf("Audience determined: %s", audience)
		// 	} else {
		// 		logrus.Warnf("Failed to parse API URL for audience: %v", err)
		// 	}
		// }
		audience := "pigeonhole-toad"

		idPTok, err := auth.AuthenticateWithDeviceCode(GlobalCtx, *foundProvider.ClientID, &foundProvider, audience)
		if err != nil {
			fmt.Printf("☠️  Could not authenticate with the identity provider: %s\n", *foundProvider.Name)
			logrus.Debugln(err.Error())
			return
		}
		logrus.Debugf("IdP Access Token: %s", idPTok.AccessToken)
		logrus.Debugf("IdP Token Type: %s", idPTok.TokenType)
		logrus.Debugf("IdP Token Expiry: %s", idPTok.Expiry)

		// Store IdP access token directly
		PigeonHoleConfig.API.AccessToken = &idPTok.AccessToken
		logrus.Debugf("IdP Access Token stored locally")

		// Store IdP refresh token if available
		if idPTok.RefreshToken != "" {
			PigeonHoleConfig.API.RefreshToken = &idPTok.RefreshToken
			logrus.Debugf("IdP Refresh Token stored")
		}

		// Persist IdP token to config file
		viper.Set("auth.token", idPTok.AccessToken)
		if err := viper.WriteConfig(); err != nil {
			logrus.Warnf("Failed to persist token to config file: %v", err)
		}

		// Extract user info and expiry from IdP token
		email := ""
		name := ""
		if claims, err := utils.DecodePigeonHoleJWT(*PigeonHoleConfig.API.AccessToken); err == nil {
			// Try to extract email from various claims
			if emailClaim, ok := claims["email"].(string); ok && emailClaim != "" {
				email = emailClaim
			} else if subClaim, ok := claims["sub"].(string); ok && subClaim != "" {
				email = subClaim
			}

			// Try to extract name from various claims
			if nameClaim, ok := claims["name"].(string); ok && nameClaim != "" {
				name = nameClaim
			} else if prefUsernameClaim, ok := claims["preferred_username"].(string); ok && prefUsernameClaim != "" {
				name = prefUsernameClaim
			}

			// Extract token expiry
			if exp, ok := claims["exp"]; ok {
				if expFloat, ok := exp.(float64); ok {
					expInt64 := int64(expFloat)
					PigeonHoleConfig.API.TokenExpiry = &expInt64
					logrus.Debugf("Token expiry extracted: %d (expires at %s)", expInt64, time.Unix(expInt64, 0))
				}
			}
		} else {
			logrus.Debugf("Failed to decode IdP token claims: %v", err)
		}

		logrus.Debugf("IdP token obtained for %s", email)

		if PigeonHoleConfig.Identity == nil {
			logrus.Debugf("Identity is nil")
			PigeonHoleConfig.Identity = make(map[string]*config.UserIdentity)
		}

		identity := PigeonHoleConfig.Identity[email]
		needKey := identity == nil || identity.GPGKey == nil || !identity.GPGKey.KeyExists()

		if needKey {
			fmt.Printf("No GPG key pair found locally, generating keys for: %s (%s)\n", name, email)

			// Ensure identity and GPGKey are initialized
			if identity == nil {
				identity = &config.UserIdentity{}
				PigeonHoleConfig.Identity[email] = identity
			}
			if identity.GPGKey == nil {
				identity.GPGKey = &config.GPGPair{}
			}

			// Ensure keypair exists
			if err := identity.GPGKey.EnsureKeyPair(&name, &email); err != nil {
				fmt.Println("failed to ensure keypair:", err)
				return
			}

			// Prepare request
			force := false
			hostname, _ := os.Hostname()
			keyPost := sdk.PostUserMeKeyJSONRequestBody{
				Force:      &force,
				KeyData:    identity.GPGKey.PublicKey,
				Reference:  &hostname,
				Thumbprint: identity.GPGKey.Thumbprint,
			}

			// Send key to server
			resp, err := PigeonHoleClient.PostUserMeKeyWithResponse(GlobalCtx, keyPost)
			if err != nil {
				logrus.Debugf(err.Error())
				fmt.Println("Could not save new GPG Key")
				return
			}

			if resp.StatusCode() == http.StatusCreated {
				logrus.Debugf("New keys saved")
			}
		} else {
			logrus.Debugf("local key already exists for: %s", email)
		}

		logrus.Debugf("Checking remote key exists for local key: %s\n\n", email)
		keysResponse, err := PigeonHoleClient.GetUserMeKeyValidateThumbprintWithResponse(GlobalCtx, *PigeonHoleConfig.Identity[email].GPGKey.Thumbprint)
		if err != nil {
			logrus.Debugf("return response re. validating thumbprint: %s", err.Error())
		}

		switch keysResponse.StatusCode() {
		case http.StatusOK:
			if len(*keysResponse.JSON200.Keys) == 0 {
				logrus.Debugf("keys not found for %s with thumbprint:", email, *PigeonHoleConfig.Identity[email].GPGKey.Thumbprint)
				logrus.Debugf("Pushing public key with fingerprint: %s ", *PigeonHoleConfig.Identity[email].GPGKey.Thumbprint)
				uploadKeyPayload := sdk.PostUserMeKeyJSONRequestBody{}
				uploadKeyPayload.KeyData = PigeonHoleConfig.Identity[email].GPGKey.PublicKey
				d, _ := os.Hostname()
				uploadKeyPayload.Reference = &d
				uploadKeyPayload.Thumbprint = PigeonHoleConfig.Identity[email].GPGKey.Thumbprint
				resp, err := PigeonHoleClient.PostUserMeKeyWithResponse(GlobalCtx, uploadKeyPayload)
				if err != nil {
					logrus.Debugf("Failed to post new key: %s\n", err.Error())
					fmt.Printf("Failed to upload key to user %s with fingerprint: %s\n", email, *PigeonHoleConfig.Identity[email].GPGKey.Thumbprint)
					return
				}
				if resp.StatusCode() == http.StatusCreated {
					logrus.Debugf("Key uploaded successfully with thumbprint: %s\n", *PigeonHoleConfig.Identity[email].GPGKey.Thumbprint)
				} else {
					logrus.Debugf("Response code: %d", resp.StatusCode())
					switch resp.StatusCode() {
					case http.StatusBadRequest:
						logrus.Debugln(*resp.JSON400.Message)
					case http.StatusInternalServerError:
						logrus.Debugln(*resp.JSON500.Message)
					}
					fmt.Println("Something went wrong")
					return
				}
			} else {
				logrus.Debugf("response from keys validation: %s\n", *keysResponse.JSON200.Message)
				for i, k := range *keysResponse.JSON200.Keys {
					logrus.Debugf("%d: %s\n", i, *k.Thumbprint)

				}
			}

		case http.StatusInternalServerError:
			logrus.Debugf("Error returned checking key validation: %s", *keysResponse.JSON500.Message)
		case http.StatusBadRequest:
			logrus.Debugf("Error returned checking key validation: %s", *keysResponse.JSON500.Message)
			return
		}

		// AccessToken, RefreshToken, and TokenExpiry have already been set above
		// during token exchange and JWT decoding
		err = PigeonHoleConfig.Save(v, &fullConfigPath)
		if err != nil {
			logrus.Debugf("config file not saved: %s", err.Error())
			fmt.Println("Failed to write config file!")
			return
		}

		fmt.Printf("\n🔐 Logged in as: %s\n\n", email)
		fmt.Printf("Now try sending a secret;\n\n	pigeonhole secret send -r recipient@domain.com -f ./myfile\n")
	},
}
var UseOIDCProvider string

func init() {
	authCmd.AddCommand(authListCmd)
	authCmd.AddCommand(authLoginCmd)
	rootCmd.AddCommand(authCmd)

	authLoginCmd.PersistentFlags().StringVar(&UseOIDCProvider, "provider", "", "specify the identity provider you wish to authenticate with")
	rootCmd.AddCommand(authLoginCmd)

}
