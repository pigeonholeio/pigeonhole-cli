package cmd

import (
	"fmt"

	"github.com/pigeonholeio/pigeonhole-cli/tui"
	"github.com/spf13/cobra"
)

// tuiCmd represents the tui command
var tuiCmd = &cobra.Command{
	Use:   "tui",
	Short: "Start the interactive terminal user interface",
	Long: `Launch the Pigeonhole TUI for a k9s-like experience.

The TUI provides:
- Secret viewing with real-time filtering
- Multi-user support
- Secure credential storage

Note: You must authenticate via 'pigeonhole auth login' before using the TUI.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Config and client initialized in root's PersistentPreRun
		// Pass GlobalCtx so TUI uses same context as CLI
		if err := tui.RunTUI(GlobalCtx, &PigeonHoleConfig, &PigeonHoleClient, Version); err != nil {
			return fmt.Errorf("TUI error: %w", err)
		}
		return nil
	},
	Annotations: map[string]string{
		"skip-pre-run": "false",
	},
}

func init() {
	rootCmd.AddCommand(tuiCmd)

	// Optional flags for TUI
	tuiCmd.Flags().BoolP("help", "h", false, "help for tui")
}
