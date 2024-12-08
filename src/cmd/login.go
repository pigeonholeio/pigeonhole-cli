package cmd

import (
	"fmt"

	auth "github.com/pigeonholeio/pigeonhole-cli/cmd/auth"
	"github.com/pigeonholeio/pigeonhole-cli/common"
	"github.com/pigeonholeio/pigeonhole-cli/logger"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Log into Pigeonhole using your Identity Provider",
	Long: `Log into your Identity Provider.
	
Pigeonhole currently only supports Azure Active Directory.
`,
	Run: func(cmd *cobra.Command, args []string) {
		viper.SafeWriteConfig()
		token, err := auth.AuthenticateWithAzureDeviceCode()
		if err != nil {
			fmt.Printf("Failed to login - %s\n", err)
			logger.Log.Debugf("Failed to login - %s", err)
			return
		}
		viper.Set("auth.token", token)
		common.GlobalPigeonHoleClient, common.GlobalCtx = common.NewPigeonHoleClient()

		if viper.GetString("key.latest.private") != "" {
			fmt.Println("GPG keys already configured... skipping!")
		} else {
			claims, _ := common.DecodePigeonHoleJWT()
			fmt.Printf("Generating new GPG key as %s...", claims["preferred_username"].(string))
			complete, err := common.GenerateKeys(claims["name"].(string), claims["preferred_username"].(string))
			if complete {
				fmt.Println("done!")
			} else {
				fmt.Printf("failed: %s\n", err)
			}
		}

		fmt.Printf("\n\nYou're logged in and ready to start sending secrets! 🔐🚀\n")
		fmt.Printf("Try sending a secret with this command:\n\tpigeonhole secrets send -r recipient@domain.com -f ./myfile\n")
	},
}

func init() {
	rootCmd.AddCommand(loginCmd)
}
