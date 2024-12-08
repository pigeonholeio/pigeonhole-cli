package cmd

import (
	"fmt"

	"github.com/pigeonholeio/pigeonhole-cli/common"
	"github.com/spf13/cobra"
)

// resetCmd represents the reset command
var MeResetCmd = &cobra.Command{
	Use:   "roll-shortcode",
	Short: "A command to role your shortcode id",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Rolling your short code...")
		// time.Sleep(3 * time.Second)
		req, _ := common.GlobalPigeonHoleClient.UserMeRotateshortcodePostWithResponse(common.GlobalCtx)
		if req.StatusCode() == 204 {
			fmt.Println("done!")
		} else {
			fmt.Println("failed")
			return
		}
	},
}

func init() {

}
