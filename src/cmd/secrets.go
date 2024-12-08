package cmd

import (
	cmd "github.com/pigeonholeio/pigeonhole-cli/cmd/secrets"
	"github.com/pigeonholeio/pigeonhole-cli/common"
	"github.com/spf13/cobra"
)

var secretsCmd = &cobra.Command{
	Use:     "secrets",
	Aliases: []string{"secret", "s"},
	Short:   "Manage all your secrets effortlessly",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		common.DisplayHelp(cmd, args)
	},
}

func init() {
	rootCmd.AddCommand(secretsCmd)
	secretsCmd.AddCommand(cmd.SecretsListCmd)
	secretsCmd.AddCommand(cmd.SecretsDropCmd)
	secretsCmd.AddCommand(cmd.SecretsDeleteCmd)
	secretsCmd.AddCommand(cmd.SecretsCollectCmd)
}
