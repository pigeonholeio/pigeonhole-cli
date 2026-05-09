package tui

// Keybindings for the TUI (inspired by k9s)

type KeyBinding struct {
	Keys        string
	Description string
	Action      string
}

var GlobalKeybindings = []KeyBinding{
	{Keys: "q", Description: "Quit", Action: "quit"},
	{Keys: "?", Description: "Show help", Action: "help"},
	{Keys: "ctrl+c", Description: "Cancel/Escape", Action: "cancel"},
}

var SecretListKeybindings = []KeyBinding{
	{Keys: "↑/↓", Description: "Navigate rows", Action: "navigate"},
	{Keys: "PgUp/PgDn", Description: "Scroll by page", Action: "scroll_page"},
	{Keys: "Home/End", Description: "Jump to first/last", Action: "jump_ends"},
	{Keys: "/", Description: "Filter by reference", Action: "filter_start"},
	{Keys: "Backspace", Description: "Delete filter char", Action: "filter_delete"},
	{Keys: "Escape", Description: "Clear filter", Action: "filter_clear"},
	{Keys: "Enter", Description: "View secret details", Action: "view_secret"},
	{Keys: "d", Description: "Delete secret", Action: "delete_secret"},
	{Keys: "c", Description: "Copy reference", Action: "copy_reference"},
	{Keys: "r", Description: "Refresh list", Action: "refresh"},
	{Keys: "s", Description: "Sort by column", Action: "sort_toggle"},
	{Keys: "ctrl+u", Description: "Switch user", Action: "switch_user"},
	{Keys: "ctrl+l", Description: "Logout", Action: "logout"},
}


// HelpText returns the full help text for the current view
func HelpText(viewType ViewType) string {
	helpText := "┌────────────────────────────────────────────────────────────────────┐\n"
	helpText += "│ Pigeonhole TUI - Help                                              │\n"
	helpText += "├────────────────────────────────────────────────────────────────────┤\n"
	helpText += "│                                                                    │\n"

	var keybindings []KeyBinding

	switch viewType {
	case ViewSecretList:
		keybindings = SecretListKeybindings
	}

	keybindings = append(keybindings, GlobalKeybindings...)

	for _, kb := range keybindings {
		line := "│  " + padRight(kb.Keys, 15) + " " + kb.Description + "\n"
		helpText += line
	}

	helpText += "│                                                                    │\n"
	helpText += "│                         [Close]                                    │\n"
	helpText += "└────────────────────────────────────────────────────────────────────┘\n"

	return helpText
}

// Helper function to pad strings
func padRight(s string, length int) string {
	for len(s) < length {
		s += " "
	}
	return s
}
