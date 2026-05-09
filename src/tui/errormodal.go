package tui

import (
	"fmt"

	"github.com/charmbracelet/lipgloss"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/pigeonholeio/pigeonhole-cli/tui/styles"
)

// ErrorModalView displays error information in a modal
type ErrorModalView struct {
	state *AppState
}

// NewErrorModalView creates a new error modal view
func NewErrorModalView(state *AppState) *ErrorModalView {
	return &ErrorModalView{
		state: state,
	}
}

// Init initializes the error modal view
func (v *ErrorModalView) Init() tea.Cmd {
	return nil
}

// Update handles messages
func (v *ErrorModalView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "enter", "escape":
			return v, func() tea.Msg { return ErrorDismissedMsg{} }
		}
	}

	return v, nil
}

// View renders the error modal view
func (v *ErrorModalView) View() string {
	width := v.state.UI.TerminalWidth
	if width < 40 {
		width = 40
	}

	inner := width - 4 // account for border + padding

	title := styles.ErrorStyle.Render("✗  Error")
	msg := lipgloss.NewStyle().Width(inner).Render(v.state.UI.ErrorMessage)
	details := styles.DimStyle.Width(inner).Render(v.state.UI.ErrorDetails)
	hint := styles.DimStyle.Width(inner).Align(lipgloss.Center).Render("press enter or esc to dismiss")

	content := fmt.Sprintf("%s\n\n%s\n\n%s\n\n%s", title, msg, details, hint)

	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(styles.ErrorColor).
		Padding(1, 2).
		Width(width - 2).
		Render(content)

	return "\n" + box + "\n"
}
