package cmd

import (
	cmd "github.com/pigeonholeio/pigeonhole-cli/cmd/account"
	"github.com/pigeonholeio/pigeonhole-cli/common"

	"github.com/spf13/cobra"
)

var accountCmd = &cobra.Command{
	Use:   "account",
	Short: "Manage your account.",
	Long:  `This command provides a summary of your account and settings.`,
	Run: func(cmd *cobra.Command, args []string) {
		common.DisplayHelp(cmd, args)
	},
}

func init() {
	rootCmd.AddCommand(accountCmd)
	accountCmd.AddCommand(cmd.AccountDetailsCmd)
}
