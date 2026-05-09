package tui

import (
	"context"
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/pigeonholeio/pigeonhole-cli/config"
	"github.com/pigeonholeio/pigeonhole-cli/sdk"
)

// RunTUI starts the Pigeonhole TUI
func RunTUI(ctx context.Context, cfg *config.PigeonHoleConfig, client *sdk.ClientWithResponses, version string) error {
	// Initialize app state
	app := NewApp(cfg, client, version)

	// Set the global context on app state for API calls
	app.state.GlobalCtx = ctx

	// Check if user is authenticated - TUI requires prior login via `auth login`
	email, err := cfg.GetUserEmail()
	if err != nil || email == "" || cfg.API.AccessToken == nil || *cfg.API.AccessToken == "" {
		return fmt.Errorf("not authenticated. Run 'pigeonhole auth login' first")
	}

	// User is authenticated - load their data
	app.state.Session.Email = email

	// Fetch secrets from API
	resp, err := client.GetSecretWithResponse(ctx, &sdk.GetSecretParams{})
	if err != nil {
		return fmt.Errorf("failed to fetch secrets: %w", err)
	}
	if resp.JSON200 != nil && resp.JSON200.Secrets != nil {
		app.state.Session.Secrets = *resp.JSON200.Secrets
	}

	// Load GPG keys from config (already loaded from credential store by root command)
	if cfg.Identity != nil && cfg.Identity[email] != nil {
		if cfg.Identity[email].GPGKey != nil {
			// Keys are already in config, ready to use
			// TUI will use them when needed for encryption/decryption
		}
	}

	// Create and run tea program
	p := tea.NewProgram(app, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		return fmt.Errorf("error running TUI: %w", err)
	}

	return nil
}
