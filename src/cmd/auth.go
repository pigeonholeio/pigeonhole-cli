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
	"github.com/pigeonholeio/pigeonhole-cli/credentialstore"
	"github.com/pigeonholeio/pigeonhole-cli/sdk"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
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
		if oidcProviders.JSON200 != nil && oidcProviders.JSON200.OidcProviders != nil && len(*oidcProviders.JSON200.OidcProviders) > 0 {
			defaultProvider := ""
			if oidcProviders.JSON200.Default != nil {
				defaultProvider = *oidcProviders.JSON200.Default
			}
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
			fmt.Printf("\n	pigeonhole login\n\n")
			fmt.Printf("or with a specific provider;\n")
			fmt.Printf("\n	pigeonhole login --provider %s\n\n", defaultProvider)
		} else {
			if oidcProviders.JSON200 != nil && oidcProviders.JSON200.Message != nil {
				logrus.Debugln(*oidcProviders.JSON200.Message)
			}
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

		idPTok, err := auth.AuthenticateWithDeviceCode(GlobalCtx, *foundProvider.ClientID, &foundProvider)
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

		// Recreate HTTP client with new token so key upload uses fresh credentials
		PigeonHoleClient = *sdk.PigeonholeClient(&PigeonHoleConfig, Version)

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
				logrus.Debugf("Error posting GPG key to server: %v", err)
				fmt.Printf("❌ Failed to upload GPG key to server\n")
				fmt.Printf("Error: %v\n\n", err)
				fmt.Println("This usually means:")
				fmt.Println("  - The server is temporarily unavailable")
				fmt.Println("  - Your network connection was interrupted")
				fmt.Println("  - The server URL is incorrect or unreachable")
				fmt.Printf("\nPlease check your connection and try again with:\n")
				fmt.Printf("  pigeonhole login\n")
				return
			}

			if resp.StatusCode() == http.StatusCreated {
				logrus.Debugf("New keys saved")
			} else {
				logrus.Debugf("Response code: %d", resp.StatusCode())
				fmt.Printf("⚠️  Warning: Unexpected response when uploading keys (status: %d)\n", resp.StatusCode())
			}
		} else {
			logrus.Debugf("local key already exists for: %s", email)
		}

		logrus.Debugf("Checking remote key exists for local key: %s\n\n", email)
		keysResponse, err := PigeonHoleClient.GetUserMeKeyValidateThumbprintWithResponse(GlobalCtx, *PigeonHoleConfig.Identity[email].GPGKey.Thumbprint)
		if err != nil {
			logrus.Debugf("Error validating thumbprint: %v", err)
			fmt.Printf("⚠️  Warning: Could not validate key on server: %v\n", err)
			fmt.Println("The login may succeed but key validation failed.")
		}

		if keysResponse == nil {
			logrus.Debugf("No response when validating thumbprint")
			fmt.Println("⚠️  Warning: No response from server when validating key")
		} else {
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
						logrus.Debugf("Error posting GPG key to server: %v", err)
						fmt.Printf("❌ Failed to upload key to server\n")
						fmt.Printf("Error: %v\n\n", err)
						fmt.Printf("Could not upload key for user %s\n", email)
						fmt.Println("Your login was successful, but the key could not be uploaded.")
						fmt.Println("Try again later or contact support if the problem persists.")
						return
					}
					if resp.StatusCode() == http.StatusCreated {
						logrus.Debugf("Key uploaded successfully with thumbprint: %s\n", *PigeonHoleConfig.Identity[email].GPGKey.Thumbprint)
					} else {
						logrus.Debugf("Response code: %d", resp.StatusCode())
						switch resp.StatusCode() {
						case http.StatusBadRequest:
							if resp.JSON400 != nil && resp.JSON400.Message != nil {
								logrus.Debugln(*resp.JSON400.Message)
								fmt.Printf("❌ Server validation error: %s\n", *resp.JSON400.Message)
							}
						case http.StatusInternalServerError:
							if resp.JSON500 != nil && resp.JSON500.Message != nil {
								logrus.Debugln(*resp.JSON500.Message)
								fmt.Printf("❌ Server error: %s\n", *resp.JSON500.Message)
							} else {
								fmt.Println("❌ Server error when uploading key (500)")
							}
						default:
							fmt.Printf("❌ Unexpected response from server (status: %d)\n", resp.StatusCode())
						}
						return
					}
				} else {
					if keysResponse.JSON200 != nil && keysResponse.JSON200.Message != nil {
						logrus.Debugf("response from keys validation: %s\n", *keysResponse.JSON200.Message)
					}
					if keysResponse.JSON200 != nil && keysResponse.JSON200.Keys != nil {
						for i, k := range *keysResponse.JSON200.Keys {
							logrus.Debugf("%d: %s\n", i, *k.Thumbprint)
						}
					}
				}

			case http.StatusInternalServerError:
				fmt.Println("❌ Server error when validating key")
				if keysResponse.JSON500 != nil && keysResponse.JSON500.Message != nil {
					logrus.Debugf("Error returned checking key validation: %s", *keysResponse.JSON500.Message)
					fmt.Printf("Error details: %s\n", *keysResponse.JSON500.Message)
				}
				return
			case http.StatusBadRequest:
				fmt.Println("❌ Invalid request when validating key")
				if keysResponse.JSON400 != nil && keysResponse.JSON400.Message != nil {
					logrus.Debugf("Error returned checking key validation: %s", *keysResponse.JSON400.Message)
					fmt.Printf("Error details: %s\n", *keysResponse.JSON400.Message)
				}
				return
			}
		}

		// AccessToken, RefreshToken, and TokenExpiry have already been set above
		// during token exchange and JWT decoding

		// Try to save credentials to credential store (PRIMARY)
		store, err := credentialstore.NewStore(&fullConfigPath)
		credentialStoreAvailable := err == nil

		if credentialStoreAvailable {
			// Credential store is available - save ONLY to it, not to config file
			logrus.Debugf("Credential store available (%s), saving credentials to it", store.Backend())

			if err := PigeonHoleConfig.SaveTokensToStore(store, email); err != nil {
				logrus.Debugf("failed to save tokens to credential store: %v", err)
				fmt.Println("Warning: Could not save tokens to credential store")
				credentialStoreAvailable = false // Fall back to config file
			} else {
				logrus.Debugf("Successfully saved tokens to credential store")
			}

			if credentialStoreAvailable {
				if err := PigeonHoleConfig.SaveGPGKeysToStore(store, email, identity); err != nil {
					logrus.Debugf("failed to save GPG keys to credential store: %v", err)
					fmt.Println("Warning: Could not save GPG keys to credential store")
				} else {
					logrus.Debugf("Successfully saved GPG keys to credential store")
				}
			}

			// Save active user to credential store
			if credentialStoreAvailable {
				if err := store.SaveActiveUser(email); err != nil {
					logrus.Debugf("failed to save active user to credential store: %v", err)
				} else {
					logrus.Debugf("Successfully saved active user to credential store: %s", email)
				}
			}

			// Reload credentials from store to ensure in-memory config has fresh tokens
			// This is important for subsequent API calls in the same command execution
			if err := PigeonHoleConfig.LoadTokensFromStore(store, email); err != nil {
				logrus.Debugf("failed to reload tokens from credential store: %v", err)
				// Continue - tokens are already in memory from login process
			}

			// Clear credentials from in-memory config before saving to file
			// Credentials are stored in credentialstore, not in the plaintext config file
			if credentialStoreAvailable {
				PigeonHoleConfig.API.AccessToken = nil
				PigeonHoleConfig.API.RefreshToken = nil
				// Also clear identity since GPG keys are stored in the credential store
				PigeonHoleConfig.Identity = nil
			}
		} else {
			// Credential store not available - credentials will be saved to config file (FALLBACK)
			logrus.Debugf("Credential store not available, credentials will be saved to config file: %v", err)
			fmt.Println("Warning: Could not use credential store, tokens will be saved to config file")
		}

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

// clearKeychainCmd represents the auth clear-keychain command
var authClearKeychainCmd = &cobra.Command{
	Use:   "clear",
	Short: "Clear all stored Pigeonhole credentials from local keychain",
	Long: `Clear all Pigeonhole credentials that are stored in your local keychain or credential store.
This will remove access tokens, refresh tokens, and GPG keys for the currently logged-in user.
You will need to log in again to continue using Pigeonhole.`,
	Annotations: map[string]string{
		"skip-pre-run": "true",
	},
	Run: func(cmd *cobra.Command, args []string) {
		force, _ := cmd.Flags().GetBool("force")
		clearKeychain(force)
	},
}

// clearKeychain removes all Pigeonhole credentials from the credential store
func clearKeychain(force bool) {
	// Ask for confirmation unless --force is used
	if !force {
		fmt.Println("⚠️  WARNING: This will clear ALL Pigeonhole credentials from your keychain.")
		fmt.Println("You will need to log in again to continue using Pigeonhole.")
		fmt.Print("\nDo you want to continue? (yes/no): ")

		if !getConfirmation() {
			fmt.Println("Clear keychain cancelled.")
			return
		}
	}

	// Try to clear from credential store first (PRIMARY)
	store, err := credentialstore.NewStore(&fullConfigPath)
	clearedFromStore := false
	storeBackend := ""

	if err == nil {
		storeBackend = store.Backend()
		logrus.Debugf("Credential store available (%s), clearing all Pigeonhole credentials", storeBackend)

		// Clear active user from credential store
		if err := store.DeleteActiveUser(); err != nil {
			logrus.Debugf("Warning: Could not delete active user: %v", err)
		} else {
			logrus.Debugf("Successfully deleted active user from credential store")
		}

		// For keyring backend, we need to clear all known keys
		if storeBackend == "keyring" {
			// Get all possible email entries from config and clear them
			// Also try to get from current config in case there are multiple users
			if PigeonHoleConfig.Identity != nil {
				for email := range PigeonHoleConfig.Identity {
					if err := store.DeleteAllCredentials(email); err != nil {
						logrus.Debugf("Error deleting from credential store for %s: %v", email, err)
					} else {
						clearedFromStore = true
						logrus.Debugf("Successfully cleared credentials from %s for %s", storeBackend, email)
					}
				}
			}

			// Also try to clear any other users that might be in the keychain
			if email, err := PigeonHoleConfig.GetUserEmail(); err == nil && email != "" {
				// Already handled in the loop above if present in Identity
			}
		} else {
			// For file backend, just use the current user email
			if email, err := PigeonHoleConfig.GetUserEmail(); err == nil && email != "" {
				logrus.Debugf("Clearing credentials from credential store (%s) for %s", storeBackend, email)
				if err := store.DeleteAllCredentials(email); err != nil {
					logrus.Debugf("Error deleting from credential store: %v", err)
				} else {
					clearedFromStore = true
					logrus.Debugf("Successfully cleared credentials from %s", storeBackend)
				}
			}
		}
	}

	// Also clear from config file as backup (in case credentials were stored there as fallback)
	logrus.Debugf("Clearing credentials from config file")
	PigeonHoleConfig.API.AccessToken = nil
	PigeonHoleConfig.API.RefreshToken = nil

	if PigeonHoleConfig.Identity != nil {
		for _, identity := range PigeonHoleConfig.Identity {
			if identity.GPGKey != nil {
				identity.GPGKey = nil
			}
		}
	}

	// Save the updated config (with credentials cleared)
	if err := PigeonHoleConfig.Save(v, &fullConfigPath); err != nil {
		logrus.Debugf("Warning: Could not save config file after clearing credentials: %v", err)
	} else {
		logrus.Debugf("Successfully cleared credentials from config file")
	}

	// Provide feedback to user
	if clearedFromStore {
		fmt.Printf("✅ Successfully cleared all Pigeonhole credentials from %s\n", storeBackend)
	} else {
		fmt.Println("✅ Successfully cleared all Pigeonhole credentials")
	}
	fmt.Println("\nYou are now logged out. Run 'pigeonhole login' to log in again.")
}

// authSwitchCmd represents the auth switch command
var authSwitchCmd = &cobra.Command{
	Use:   "switch <user-email>",
	Short: "Switch to a different authenticated user",
	Long: `Switch to a different authenticated user that has been previously logged in.
This command allows you to switch between multiple user accounts that have stored credentials.`,
	Annotations: map[string]string{
		"skip-pre-run": "true",
	},
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		userEmail := args[0]
		logrus.Debugf("Attempting to switch to user: %s", userEmail)

		// Ensure config is initialized
		if fullConfigPath == "" {
			InitConfig()
		}

		// Try to get credential store
		store, err := credentialstore.NewStore(&fullConfigPath)
		if err != nil {
			fmt.Printf("❌ Could not access credential store: %v\n", err)
			return
		}

		// Validate that the user has valid credentials in the store
		accessToken, err := store.GetAccessToken(userEmail)
		if err != nil || accessToken == "" {
			fmt.Printf("❌ No valid credentials found for %s\n", userEmail)
			fmt.Println("This user may not be logged in yet. Use 'pigeonhole login' first.")
			logrus.Debugf("Access token validation failed for %s: %v", userEmail, err)
			return
		}

		// Try to load credentials for the specified user
		if err := PigeonHoleConfig.LoadTokensFromStore(store, userEmail); err != nil {
			fmt.Printf("❌ Could not load credentials for %s: %v\n", userEmail, err)
			fmt.Println("This user may not be logged in yet. Use 'pigeonhole login' first.")
			return
		}

		// Save as active user
		if err := store.SaveActiveUser(userEmail); err != nil {
			fmt.Printf("❌ Could not save active user: %v\n", err)
			return
		}

		// Try to load GPG keys
		if identity, err := PigeonHoleConfig.LoadGPGKeysFromStore(store, userEmail); err != nil {
			logrus.Debugf("Could not load GPG keys: %v", err)
		} else if identity != nil {
			if PigeonHoleConfig.Identity == nil {
				PigeonHoleConfig.Identity = make(map[string]*config.UserIdentity)
			}
			PigeonHoleConfig.Identity[userEmail] = identity
		}

		fmt.Printf("✅ Switched to user: %s\n", userEmail)
	},
}

// authListUsersCmd represents the auth list-users command
var authListUsersCmd = &cobra.Command{
	Use:   "list-users",
	Short: "List all authenticated users",
	Long: `List all user accounts that have authenticated credentials stored.
This shows all users you have previously logged in as.`,
	Annotations: map[string]string{
		"skip-pre-run": "true",
	},
	Run: func(cmd *cobra.Command, args []string) {
		logrus.Debugf("Listing authenticated users")

		// Ensure config is initialized
		if fullConfigPath == "" {
			InitConfig()
		}

		// Try to get credential store
		store, err := credentialstore.NewStore(&fullConfigPath)
		if err != nil {
			fmt.Printf("❌ Could not access credential store: %v\n", err)
			return
		}

		logrus.Debugf("Using credential store backend: %s", store.Backend())

		// Get list of users
		users, err := store.DiscoverUsers()
		if err != nil {
			fmt.Printf("❌ Could not discover users: %v\n", err)
			return
		}

		// Validate each user has actual credentials
		validUsers := []string{}
		for _, user := range users {
			// Check if user has access token
			accessToken, err := store.GetAccessToken(user)
			if err == nil && accessToken != "" {
				validUsers = append(validUsers, user)
				logrus.Debugf("User %s has valid access token", user)
			} else {
				logrus.Debugf("User %s has no access token: %v", user, err)
			}
		}

		if len(validUsers) == 0 {
			fmt.Println("No authenticated users found.")
			fmt.Println("Use 'pigeonhole login' to log in as a user.")
			return
		}

		// Get active user
		activeUser, _ := store.GetActiveUser()

		fmt.Println("Authenticated users:")
		for _, user := range validUsers {
			marker := "  "
			if user == activeUser {
				marker = "✓ "
			}
			fmt.Printf("%s%s\n", marker, user)
		}
		if activeUser != "" {
			fmt.Printf("\nCurrent active user: %s\n", activeUser)
		}
	},
}

var UseOIDCProvider string

func init() {
	authCmd.AddCommand(authListCmd)
	authCmd.AddCommand(authLoginCmd)
	authCmd.AddCommand(authClearKeychainCmd)
	authCmd.AddCommand(authSwitchCmd)
	authCmd.AddCommand(authListUsersCmd)
	rootCmd.AddCommand(authCmd)

	authLoginCmd.PersistentFlags().StringVar(&UseOIDCProvider, "provider", "", "specify the identity provider you wish to authenticate with")
	authClearKeychainCmd.PersistentFlags().BoolP("force", "f", false, "Skip confirmation prompt")
	rootCmd.AddCommand(authLoginCmd)

}
