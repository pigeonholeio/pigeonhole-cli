package tui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/pigeonholeio/pigeonhole-cli/sdk"
	"github.com/pigeonholeio/pigeonhole-cli/tui/styles"
)

// SecretDetailView displays secret metadata in a modal
type SecretDetailView struct {
	state             *AppState
	secret            *sdk.Secret
	statusMsg         string
	statusMsgTime     time.Time
	statusMsgTimeout  time.Duration
}

// NewSecretDetailView creates a new secret detail view
func NewSecretDetailView(state *AppState) *SecretDetailView {
	return &SecretDetailView{
		state:             state,
		secret:            nil,
		statusMsg:         "",
		statusMsgTime:     time.Time{},
		statusMsgTimeout:  5 * time.Second,
	}
}

// Init initializes the secret detail view
func (v *SecretDetailView) Init() tea.Cmd {
	return nil
}

// Update handles messages
func (v *SecretDetailView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "escape":
			return v, func() tea.Msg { return BackMsg{} }
		case "c":
			if v.secret != nil {
				v.statusMsg = fmt.Sprintf("Retrieving %s...", deref(v.secret.Reference))
				v.statusMsgTime = time.Now()
				// Create a temporary SecretListView to get the retrieve function
				tempView := NewSecretListView(v.state)
				return v, tempView.retrieveSecretCmd(*v.secret)
			}
		case "d":
			if v.secret != nil {
				tempView := NewSecretListView(v.state)
				return v, tempView.deleteSecretCmd(*v.secret)
			}
		}

	case SecretRetrievedMsg:
		v.statusMsg = fmt.Sprintf("Saved to %s", msg.Path)
		v.statusMsgTime = time.Now()
		return v, nil

	case SecretRetrieveFailedMsg:
		v.statusMsg = fmt.Sprintf("Retrieve failed: %s", msg.Error)
		v.statusMsgTime = time.Now()
		return v, nil

	case SecretDeletedMsg:
		// Go back after delete
		return v, func() tea.Msg { return BackMsg{} }

	case SecretDeleteFailedMsg:
		v.statusMsg = fmt.Sprintf("Error: %s", msg.Error)
		v.statusMsgTime = time.Now()
		return v, nil

	case TickMsg:
		// Check if status message has timed out (5 seconds)
		if v.statusMsg != "" && !v.statusMsgTime.IsZero() {
			if time.Since(v.statusMsgTime) >= v.statusMsgTimeout {
				v.statusMsg = ""
				v.statusMsgTime = time.Time{}
			}
		}
		// Don't return a command - let the app handle the ticker
		return v, nil
	}

	return v, nil
}

// View renders the secret detail view
func (v *SecretDetailView) View() string {
	if v.secret == nil {
		return "No secret selected\n"
	}

	width := v.state.UI.TerminalWidth
	if width < styles.MinWidth {
		width = styles.MinWidth
	}

	output := strings.Builder{}

	// Top border with title
	output.WriteString("┌─ Secret Details ")
	output.WriteString(strings.Repeat("─", width-18))
	output.WriteString("┐\n")

	// Reference
	output.WriteString("│ ")
	output.WriteString(fmt.Sprintf("%-*s │\n", width-4, "Reference:  "+deref(v.secret.Reference)))

	// From
	output.WriteString("│ ")
	output.WriteString(fmt.Sprintf("%-*s │\n", width-4, "From:       "+deref(v.secret.Sender)))

	// To
	output.WriteString("│ ")
	output.WriteString(fmt.Sprintf("%-*s │\n", width-4, "To:         "+deref(v.secret.Recipient)))

	// Size
	size := formatSize(v.secret.Size)
	output.WriteString("│ ")
	output.WriteString(fmt.Sprintf("%-*s │\n", width-4, "Size:       "+size))

	// Sent
	sent := formatTime(v.secret.SentAt)
	output.WriteString("│ ")
	output.WriteString(fmt.Sprintf("%-*s │\n", width-4, "Sent:       "+sent))

	// Expires
	expires := "Never"
	if v.secret.Expiration != nil {
		if time.Now().After(*v.secret.Expiration) {
			expires = "Expired"
		} else {
			expires = v.secret.Expiration.Format("Jan 02, 2006")
		}
	}
	output.WriteString("│ ")
	output.WriteString(fmt.Sprintf("%-*s │\n", width-4, "Expires:    "+expires))

	// One-time
	onetime := "No"
	if v.secret.Onetime != nil && *v.secret.Onetime {
		onetime = "Yes"
	}
	output.WriteString("│ ")
	output.WriteString(fmt.Sprintf("%-*s │\n", width-4, "One-time:   "+onetime))

	// Status divider
	output.WriteString("├")
	output.WriteString(strings.Repeat("─", width-2))
	output.WriteString("┤\n")

	// Bottom border
	output.WriteString("└")
	output.WriteString(strings.Repeat("─", width-2))
	output.WriteString("┘\n")

	// Status line
	var statusLine string
	if v.statusMsg != "" {
		if strings.HasPrefix(v.statusMsg, "Error") || strings.HasPrefix(v.statusMsg, "Retrieve failed") {
			statusLine = styles.ErrorStyle.Render("  " + v.statusMsg)
		} else {
			statusLine = styles.SuccessStyle.Render("  " + v.statusMsg)
		}
	} else {
		statusBindings := []string{
			"c retrieve",
			"d delete",
			"esc back",
		}
		statusLine = styles.DimStyle.Render("  " + strings.Join(statusBindings, "  "))
	}
	output.WriteString(statusLine)
	output.WriteString("\n")

	return output.String()
}
