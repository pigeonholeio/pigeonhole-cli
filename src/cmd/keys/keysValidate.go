package cmd

import (
	"fmt"

	"github.com/pigeonholeio/pigeonhole-cli/common"
	"github.com/spf13/cobra"
)

var KeysValidateCmd = &cobra.Command{
	Use:     "validate",
	Aliases: []string{"check", "verify", "c", "v"},
	Short:   "Test if your local keys have been pushed",
	Long:    `Test if your local keys have been pushed`,
	Run: func(cmd *cobra.Command, args []string) {
		// common.DisplayHelp(cmd, args)
		if common.ValidateLocalKeys() {
			fmt.Println("Local and remote thumbprints match - this means you can send and decrypt secrets.")
		} else {
			fmt.Println(`Remote key does not match. You'll be unable to decrypt secrets sent to you. 

Run the following command to reset and sync keys:
	pigeonhole keys init`)
		}
	},
}

func init() {

}
