package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Creates the default config file",
	Long: `A command that creates the configuration folder and a default configuration file.

	This can be useful if you're using your own OIDC IdP and need the default configuration to override.
	
The default file includes the default OIDC provider config for Azure.
	`,
	Run: func(cmd *cobra.Command, args []string) {
		viper.SafeWriteConfig()
		fmt.Println("Generated default config at: $HOME/.pigeonhole/config.yaml")
	},
}

func init() {
	rootCmd.AddCommand(initCmd)

}
