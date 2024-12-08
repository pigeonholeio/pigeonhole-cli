package cmd

import (
	"fmt"

	"github.com/pigeonholeio/pigeonhole-cli/common"
	"github.com/spf13/cobra"
)

// listCmd represents the list command
var KeysListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"l", "ls"},
	Short:   "List your remote keys",
	Long: `List your remote keys in case you need to troubleshoot key problems
Note: keydata is base64 encoded. To decode your key to reveal the PGP pub key you can chain it to yq e.g.

pigeonhole key list | yq '.[0].keydata' | base64 -d
	
`,
	Run: func(cmd *cobra.Command, args []string) {
		x, err := common.GlobalPigeonHoleClient.UserMeKeyGetWithResponse(common.GlobalCtx)
		if err != nil {
			fmt.Printf("ERROR: %s", err.Error())
		}
		if x.StatusCode() == 200 {
			if len(*x.JSON200) > 0 {
				common.OutputData(x.JSON200)
			} else {
				fmt.Printf("No keys found on the server!\nUse `pigeonhole keys init` to generate a GPG key pair to use\n")
			}
		} else {
			fmt.Printf("failed to get keys")
		}
	},
}

func init() {

}
