package cmd

import (
	"fmt"

	"github.com/pigeonholeio/pigeonhole-cli/common"
	"github.com/spf13/cobra"
)

var AccountDetailsCmd = &cobra.Command{
	Use:     "details",
	Aliases: []string{"info", "show", "list"},
	Short:   "Manage your account",
	Long:    `A brief overview of your account.`,
	Run: func(cmd *cobra.Command, args []string) {
		resp, _ := common.GlobalPigeonHoleClient.UserMeGetWithResponse(common.GlobalCtx)
		if resp.StatusCode() == 200 {
			common.OutputData(resp.JSON200)
		} else if resp.StatusCode() == 400 {
			fmt.Printf("failed: %s\n", resp.JSON400.Message)
		} else if resp.StatusCode() == 401 {
			fmt.Printf("failed: %s\n", resp.JSON401.Message)
		} else if resp.StatusCode() == 403 {
			fmt.Printf("failed: %s\n", resp.JSON403.Message)
		} else if resp.StatusCode() == 500 {
			fmt.Printf("failed: %s\n", resp.JSON500.Message)
		}

	},
}

func init() {

}
