package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var Version, BuildTime, CommitHash, BuiltBy string

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Find version and build info about the cli",
	Long:  `Find version and build info about the cli`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Version: %s\n", Version)
		fmt.Printf("BuildTime: %s\n", BuildTime)
		fmt.Printf("CommitHash: %s\n", CommitHash)
		fmt.Printf("BuiltBy: %s\n", BuiltBy)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
