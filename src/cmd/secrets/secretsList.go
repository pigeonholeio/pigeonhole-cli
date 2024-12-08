package cmd

import (
	"fmt"

	"github.com/pigeonholeio/pigeonhole-cli/common"
	"github.com/pigeonholeio/pigeonhole-cli/logger"
	"github.com/pigeonholeio/pigeonhole-cli/sdk"
	"github.com/spf13/cobra"
)

var SecretsListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"l", "ls"},
	Short:   "List out your secrets",
	Long:    `List your secrets that you can collect and decrypt`,
	Run: func(cmd *cobra.Command, args []string) {

		ref, _ := cmd.Flags().GetString("reference")

		s := sdk.SecretGetParams{}
		if ref != "" {
			s.Reference = &ref
		}
		f, err := common.GlobalPigeonHoleClient.SecretGetWithResponse(common.GlobalCtx, &s)
		if err != nil {
			logger.Log.Fatalf("failed: %s", err.Error())
		}

		logger.Log.Debugf("SecretGetWithResponse StatusCode: %d", f.StatusCode())

		if f.StatusCode() == 200 && len(*f.JSON200) > 0 {
			common.OutputData(f.JSON200)
		} else if f.StatusCode() == 200 && len(*f.JSON200) == 0 {
			fmt.Println("No secrets available")
		} else if f.StatusCode() == 400 {
			fmt.Printf("failed: %s\n", f.JSON400.Message)
		} else if f.StatusCode() == 401 {
			fmt.Printf("failed: %s\n", f.JSON401.Message)
		} else if f.StatusCode() == 403 {
			fmt.Printf("failed: %s\n", f.JSON403.Message)
		} else if f.StatusCode() == 500 {
			fmt.Printf("failed: %s\n", f.JSON500.Message)
		} else {
			fmt.Printf("Something went wrong: %s\n", f.StatusCode())
		}
	},
}

func init() {
	SecretsListCmd.Flags().StringP("reference", "r", "", "Reference of a secret")
}
