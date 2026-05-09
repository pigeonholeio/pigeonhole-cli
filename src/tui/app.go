package tui

import (
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/pigeonholeio/pigeonhole-cli/config"
	"github.com/pigeonholeio/pigeonhole-cli/sdk"
)

// App is the main Bubble Tea model for the Pigeonhole TUI
type App struct {
	state *AppState

	// View-specific models
	secretListView   *SecretListView
	secretDetailView *SecretDetailView
	errorModalView   *ErrorModalView

	// Ticker for polling/animations
	ticker *time.Ticker
	done   chan struct{}
}

// NewApp creates a new App instance
func NewApp(cfg *config.PigeonHoleConfig, client *sdk.ClientWithResponses, version string) *App {
	appState := NewAppState(cfg, client, version)

	app := &App{
		state:  appState,
		ticker: time.NewTicker(500 * time.Millisecond),
		done:   make(chan struct{}),
	}

	// Initialize views
	app.secretListView = NewSecretListView(appState)
	app.secretDetailView = NewSecretDetailView(appState)
	app.errorModalView = NewErrorModalView(appState)

	return app
}

// Init initializes the app
func (a *App) Init() tea.Cmd {
	// User is authenticated (verified in RunTUI) - show secret list
	a.state.CurrentView = ViewSecretList
	return tea.Batch(
		a.secretListView.Init(),
		a.tickCmd(),
	)
}

// Update handles messages
func (a *App) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		return a.handleKeyPress(msg)

	case tea.WindowSizeMsg:
		// Handle terminal resize
		a.state.UI.TerminalWidth = msg.Width
		a.state.UI.TerminalHeight = msg.Height
		return a, nil

	case TickMsg:
		// Periodic tick - route to view for timeout checks, then keep ticker running
		_, _ = a.routeMessage(msg)
		return a, a.tickCmd()

	case SecretSelectedMsg:
		a.secretDetailView.secret = &msg.Secret
		a.state.TransitionView(ViewSecretDetail)
		return a, nil

	case ViewChangedMsg:
		a.state.TransitionView(msg.View)
		return a, a.getViewCmd(msg.View)

	case NextViewMsg:
		// Progress to next view based on context
		nextView := a.getNextView()
		a.state.TransitionView(nextView)
		return a, a.getViewCmd(nextView)

	case BackMsg:
		a.state.GoBack()
		return a, a.getViewCmd(a.state.CurrentView)

	case ErrorOccurredMsg:
		a.state.SetError(msg.Error, msg.Details)
		return a, nil

	case ErrorDismissedMsg:
		a.state.ClearError()
		a.state.GoBack()
		return a, nil

	case tea.QuitMsg:
		return a, tea.Quit
	}

	// Route message to appropriate view (this will also handle TickMsg for view-specific timeouts)
	return a.routeMessage(msg)
}

// View renders the current view
func (a *App) View() string {
	switch a.state.CurrentView {
	case ViewSecretList:
		return a.secretListView.View()
	case ViewSecretDetail:
		return a.secretDetailView.View()
	case ViewError:
		return a.errorModalView.View()
	case ViewEmpty:
		return a.renderEmptyState()
	default:
		return "Unknown view\n"
	}
}

// handleKeyPress processes keyboard input
func (a *App) handleKeyPress(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q":
		return a, tea.Quit
	case "?":
		// TODO: Show help modal
		return a, nil
	case "ctrl+c":
		if a.state.CurrentView == ViewError {
			a.state.ClearError()
			a.state.GoBack()
		} else {
			return a, tea.Quit
		}
		return a, nil
	}

	// Route key to view-specific handler
	return a.routeMessage(msg)
}

// routeMessage routes a message to the appropriate view
func (a *App) routeMessage(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch a.state.CurrentView {
	case ViewSecretList:
		_, cmd = a.secretListView.Update(msg)
	case ViewSecretDetail:
		_, cmd = a.secretDetailView.Update(msg)
	case ViewError:
		_, cmd = a.errorModalView.Update(msg)
	}

	// If this is a TickMsg, also keep the app ticker running
	if _, isTickMsg := msg.(TickMsg); isTickMsg && cmd == nil {
		cmd = a.tickCmd()
	}

	return a, cmd
}

// getNextView determines the next view based on current context
func (a *App) getNextView() ViewType {
	switch a.state.CurrentView {
	case ViewSecretList:
		if len(a.state.Session.Secrets) == 0 {
			return ViewEmpty
		}
		return ViewSecretList
	default:
		return a.state.CurrentView
	}
}

// getViewCmd returns the initialization command for a view
func (a *App) getViewCmd(view ViewType) tea.Cmd {
	switch view {
	case ViewSecretList:
		return a.secretListView.Init()
	case ViewSecretDetail:
		return a.secretDetailView.Init()
	case ViewError:
		return nil
	default:
		return nil
	}
}

// renderEmptyState renders the empty state view
func (a *App) renderEmptyState() string {
	width := a.state.UI.TerminalWidth
	if width < 80 {
		width = 80
	}

	output := strings.Builder{}

	// Top border
	output.WriteString("┌")
	output.WriteString(strings.Repeat("─", width-2))
	output.WriteString("┐\n")

	// Title
	title := "Pigeonhole - Secrets"
	titleRow := "│ " + title + strings.Repeat(" ", width-len(title)-4) + " │\n"
	output.WriteString(titleRow)

	// Divider
	output.WriteString("├")
	output.WriteString(strings.Repeat("─", width-2))
	output.WriteString("┤\n")

	// Content
	content := []string{
		"",
		"                    No secrets yet",
		"",
		"     Use the web app to send yourself a secret, or:",
		"",
		"     Command line:",
		"       pigeonhole-cli secret send -r alice@example.com -f myfile.txt",
		"",
		"     Press 'r' to refresh or 'q' to quit",
		"",
	}

	for _, line := range content {
		contentRow := "│ " + line + strings.Repeat(" ", width-len(line)-4) + " │\n"
		output.WriteString(contentRow)
	}

	// Bottom border
	output.WriteString("└")
	output.WriteString(strings.Repeat("─", width-2))
	output.WriteString("┘\n")

	return output.String()
}

// tickCmd returns a command for the periodic ticker
func (a *App) tickCmd() tea.Cmd {
	return func() tea.Msg {
		<-a.ticker.C
		return TickMsg{Time: time.Now()}
	}
}
