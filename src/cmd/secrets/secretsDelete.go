package cmd

import (
	"fmt"
	"net/http"
	"os"

	"github.com/pigeonholeio/pigeonhole-cli/common"
	"github.com/pigeonholeio/pigeonhole-cli/logger"
	"github.com/pigeonholeio/pigeonhole-cli/sdk"
	"github.com/spf13/cobra"
)

var SecretsDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete secrets you may no longer want or need",
	Long:  `Delete secrets you may no longer want or need.`,
	Run: func(cmd *cobra.Command, args []string) {
		all, _ := cmd.Flags().GetBool("all")
		reference, _ := cmd.Flags().GetString("reference")

		if all && reference != "" {
			fmt.Println("Error: --all, --reference flags are mutually exclusive")
		}
		var resp *sdk.SecretDeleteResponse
		s := sdk.SecretDeleteParams{}
		if reference != "" {
			s.Reference = &reference
		}
		if all {
			logger.Log.Debugf("Deleting all secrets...")
			resp, _ = common.GlobalPigeonHoleClient.SecretDeleteWithResponse(common.GlobalCtx, &s)
		} else if reference != "" {
			resp, _ = common.GlobalPigeonHoleClient.SecretDeleteWithResponse(common.GlobalCtx, &s)
			logger.Log.Debugf("Deleting secrets by reference: %s\n", reference)

		} else {
			fmt.Println("Error: You must specify one of --all or --reference\n")
			common.DisplayHelp(cmd, args)
			os.Exit(1)
		}
		if resp.StatusCode() == http.StatusOK {
			fmt.Println("Secrets deleted")
		} else {
			fmt.Println("Something went wrong")
		}
	},
}

func init() {
	SecretsDeleteCmd.Flags().BoolP("all", "a", false, "Delete all secrets that you have sent/received")
	SecretsDeleteCmd.Flags().StringP("reference", "r", "", "Delete secrets by reference or id")
}
