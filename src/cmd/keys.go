package cmd

import (
	cmd "github.com/pigeonholeio/pigeonhole-cli/cmd/keys"
	"github.com/pigeonholeio/pigeonhole-cli/common"
	"github.com/spf13/cobra"
)

var keysCmd = &cobra.Command{
	Use:     "key",
	Aliases: []string{"keys", "k"},
	Short:   "Manage all your GPG keys effortlessly",
	Long:    `Here you will find a collection of commands that can manage your GPG keys.`,
	Run: func(cmd *cobra.Command, args []string) {
		common.DisplayHelp(cmd, args)
	},
}

func init() {
	rootCmd.AddCommand(keysCmd)
	keysCmd.AddCommand(cmd.KeysInitCmd)
	keysCmd.AddCommand(cmd.KeysListCmd)
	keysCmd.AddCommand(cmd.KeysValidateCmd)

}
