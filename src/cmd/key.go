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
	"bufio"
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/pigeonholeio/common/utils"
	"github.com/pigeonholeio/pigeonhole-cli/config"
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

var KeysRegenerateCmd = &cobra.Command{
	Use:   "regenerate",
	Short: "Regenerate your GPG key pair",
	Long: `Regenerate your local GPG key pair and upload the new key to the server.
This will replace your existing key on the server.

If you have secrets encrypted with your current key, you'll be asked to confirm
before proceeding. Use --force to skip confirmations.

Important: Your existing encrypted secrets will become unreadable with a new key.`,
	Run: func(cmd *cobra.Command, args []string) {
		force, _ := cmd.Flags().GetBool("force")
		regenerateKey(force)
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
			fmt.Println("Something went wrong - could not list keys!")
			logrus.Debugln(err.Error())
		}
		if x.StatusCode() == 200 && x.JSON200 != nil && x.JSON200.Keys != nil {
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

// regenerateKey handles the regeneration of a user's GPG key pair
func regenerateKey(force bool) {
	// Create a new context with longer timeout to account for user input delays
	// The default command context is 60s, but with user confirmations this may not be enough
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Get user email
	email, err := PigeonHoleConfig.GetUserEmail()
	if err != nil {
		fmt.Println("❌ Could not determine logged-in user email")
		fmt.Printf("Error: %v\n", err)
		fmt.Println("\nMake sure you are logged in with: pigeonhole login")
		logrus.Debugf("Error getting user email: %v", err)
		return
	}

	// Get user name
	name, err := PigeonHoleConfig.GetUserName()
	if err != nil {
		fmt.Println("❌ Could not determine user name")
		fmt.Printf("Error: %v\n", err)
		fmt.Println("\nMake sure you are logged in with: pigeonhole login")
		logrus.Debugf("Error getting user name: %v", err)
		return
	}

	// Ensure identity map exists
	if PigeonHoleConfig.Identity == nil {
		PigeonHoleConfig.Identity = make(map[string]*config.UserIdentity)
	}

	// Get local identity
	localIdentity := PigeonHoleConfig.Identity[email]
	if localIdentity == nil {
		localIdentity = &config.UserIdentity{
			GPGKey: &config.GPGPair{},
		}
		PigeonHoleConfig.Identity[email] = localIdentity
	}

	localKey := localIdentity.GPGKey

	// Check if local key exists
	if !localKey.KeyExists() {
		fmt.Println("❌ No local GPG key found for regeneration")
		return
	}

	localFingerprint := localKey.Thumbprint
	if localFingerprint == nil || *localFingerprint == "" {
		fmt.Println("❌ Local key fingerprint is missing")
		return
	}

	// Fetch remote key from server
	fmt.Print("Checking remote key...")
	remoteKeysResp, err := PigeonHoleClient.GetUserMeKeyWithResponse(ctx)
	if err != nil {
		fmt.Printf("\n❌ Failed to fetch remote keys: %v\n", err)
		logrus.Debugf("Error fetching remote keys: %v", err)
		return
	}

	if remoteKeysResp.StatusCode() != http.StatusOK || remoteKeysResp.JSON200 == nil {
		fmt.Printf("\n❌ Could not retrieve keys from server (status: %d)\n", remoteKeysResp.StatusCode())
		return
	}

	// Find matching remote key and check for other keys
	var remoteKey *sdk.Key
	remoteKeyCount := 0
	if remoteKeysResp.JSON200.Keys != nil && len(*remoteKeysResp.JSON200.Keys) > 0 {
		remoteKeyCount = len(*remoteKeysResp.JSON200.Keys)
		for _, k := range *remoteKeysResp.JSON200.Keys {
			if k.Thumbprint != nil && *k.Thumbprint == *localFingerprint {
				remoteKey = &k
				break
			}
		}
	}

	fmt.Println(" done!")

	// Check for secrets encrypted with current key - do this immediately after getting remote keys
	// Keep both API calls back-to-back to avoid idle connection timeouts
	fmt.Print("Checking for secrets encrypted with current key...")
	secretsResp, err := PigeonHoleClient.GetSecretWithResponse(ctx, &sdk.GetSecretParams{})
	if err != nil {
		fmt.Printf("\n⚠️  Could not check for secrets: %v\n", err)
		logrus.Debugf("Error checking secrets: %v", err)
		return
	}

	secretCount := 0
	if secretsResp != nil && secretsResp.StatusCode() == http.StatusOK && secretsResp.JSON200 != nil && secretsResp.JSON200.Secrets != nil {
		secretCount = len(*secretsResp.JSON200.Secrets)
	}

	fmt.Println(" done!")

	// NOW ask for confirmations after both initial API calls are done
	// This prevents idle connection timeouts during user input

	// Confirmation 1: Warn if local key not found but other keys exist
	if remoteKey == nil && remoteKeyCount > 0 {
		if !force {
			fmt.Print("\nDo you want to continue regenerating your local key? (yes/no): ")
			if !getConfirmation() {
				fmt.Println("Regeneration cancelled.")
				return
			}
		}
	}

	// Confirmation 2: Warn about secrets if they exist
	if secretCount > 0 && !force {
		fmt.Printf("\n⚠️  WARNING: You have %d active secret(s) encrypted with your current key.\n", secretCount)
		fmt.Println("Regenerating your key will make these secrets unreadable.")
		fmt.Print("\nDo you want to continue? (yes/no): ")

		if !getConfirmation() {
			fmt.Println("Regeneration cancelled.")
			return
		}
	}

	// Confirmation 3: Final confirmation
	if !force {
		fmt.Println("\n⚠️  You are about to regenerate your GPG key.")
		fmt.Println("This will:")
		fmt.Println("  1. Generate a new key pair locally")
		fmt.Println("  2. Upload the new key to the server")
		if remoteKey != nil {
			fmt.Println("  3. Delete the old key from the server to clean up")
		}
		fmt.Print("\nDo you want to continue? (yes/no): ")

		if !getConfirmation() {
			fmt.Println("Regeneration cancelled.")
			return
		}
	}

	// Now that we have confirmations, proceed with local operations and remaining API calls
	// All remaining operations happen without idle delays

	// Generate new key
	fmt.Print("Regenerating GPG key pair...")
	newKey := &config.GPGPair{}
	if err := newKey.CreateKeyPair(name, email); err != nil {
		fmt.Printf("\n❌ Failed to generate new key: %v\n", err)
		logrus.Debugf("Error generating new key: %v\n", err)
		return
	}
	// fmt.Println(" done!")

	// Get new key details
	newFingerprint := newKey.Thumbprint
	if newFingerprint == nil || *newFingerprint == "" {
		fmt.Println("❌ New key fingerprint is missing")
		return
	}

	logrus.Debugf("New key fingerprint: %s\n", *newFingerprint)

	// Upload new key to server
	logrus.Debugln("Uploading new key to server...")
	hostname, _ := os.Hostname()
	uploadPayload := sdk.PostUserMeKeyJSONRequestBody{
		Force:      nil,
		KeyData:    newKey.PublicKey,
		Reference:  &hostname,
		Thumbprint: newKey.Thumbprint,
	}

	uploadResp, err := PigeonHoleClient.PostUserMeKeyWithResponse(ctx, uploadPayload)
	if err != nil {
		fmt.Printf("\n❌ Failed to upload new key: %v\n", err)
		logrus.Debugf("Error uploading new key: %v", err)
		fmt.Println("New key was generated but not uploaded. Please try again.")
		return
	}

	if uploadResp.StatusCode() != http.StatusCreated {
		fmt.Printf("\n❌ Server rejected new key (status: %d)\n", uploadResp.StatusCode())
		if uploadResp.JSON400 != nil && uploadResp.JSON400.Message != nil {
			fmt.Printf("Error: %s\n", *uploadResp.JSON400.Message)
		}
		logrus.Debugf("Upload failed with status: %d", uploadResp.StatusCode())
		fmt.Println("New key was generated but not uploaded. Please try again.")
		return
	}

	// Delete old remote key only if we found a matching one
	if remoteKey != nil && remoteKey.Id != nil {
		logrus.Debugln("Deleting old key from server...")
		// Get user ID for delete request
		userID, err := PigeonHoleConfig.GetUserId()
		if err != nil {
			fmt.Printf("\n⚠️  Warning: Could not determine user ID for key deletion: %v\n", err)
			logrus.Debugf("Error getting user ID: %v", err)
		} else {
			keyID := remoteKey.Id.String()
			deleteResp, err := PigeonHoleClient.DeleteUserUserIdKeyKeyIdWithResponse(ctx, userID, keyID, sdk.Key{})
			if err != nil {
				fmt.Printf("\n⚠️  Warning: Failed to delete old remote key: %v\n", err)
				logrus.Debugf("Error deleting remote key: %v", err)
			} else if deleteResp.StatusCode() != http.StatusNoContent && deleteResp.StatusCode() != http.StatusOK {
				fmt.Printf("\n⚠️  Warning: Server rejected key deletion (status: %d)\n", deleteResp.StatusCode())
				logrus.Debugf("Delete failed with status: %d", deleteResp.StatusCode())
			} else {
				fmt.Println(" done!")
			}
		}
	}

	// Update local key
	logrus.Debugln("Updating local key...")
	localIdentity.GPGKey = newKey

	// Save config
	err = PigeonHoleConfig.Save(v, &fullConfigPath)
	if err != nil {
		fmt.Printf("\n❌ Failed to save config: %v\n", err)
		logrus.Debugf("Error saving config: %v", err)
		return
	}

	// fmt.Println(" done!")

	fmt.Printf("\n✅ Successfully regenerated your GPG key with fingerprint: %s\n", *newFingerprint)

	if remoteKey != nil {
		fmt.Println("\nYour old key has been replaced on the server.")
		fmt.Println("Secrets encrypted with your old key are no longer retrievable.")
	} else if remoteKeyCount > 0 {
		fmt.Printf("\nNew key uploaded to server. You have %d other key(s) still on the server.\n", remoteKeyCount)
		fmt.Println("Your old local key has been updated locally.")
	} else {
		fmt.Println("\nNew key uploaded to server.")
		fmt.Println("Your old local key has been updated locally.")
	}
}

// getConfirmation prompts the user for yes/no confirmation
func getConfirmation() bool {
	reader := bufio.NewReader(os.Stdin)
	response, _ := reader.ReadString('\n')
	response = strings.TrimSpace(strings.ToLower(response))
	return response == "yes" || response == "y"
}

func init() {

	KeysCreateCmd.PersistentFlags().BoolP("force", "f", false, "Force overwrite key with same reference")
	KeysCreateCmd.PersistentFlags().Bool("clear", false, "Clear out all other keys")
	KeysCreateCmd.PersistentFlags().StringP("reference", "r", "", "Override the reference for the key i.e. where it'll be used or created")

	KeysRegenerateCmd.PersistentFlags().BoolP("force", "f", false, "Skip confirmation prompts")

	rootCmd.AddCommand(keysCmd)

	keysCmd.AddCommand(KeysListCmd)
	keysCmd.AddCommand(KeysRegenerateCmd)

}
