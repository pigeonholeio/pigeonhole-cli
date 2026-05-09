package styles

import "github.com/charmbracelet/lipgloss"

// "Pigeon" Theme - Professional dark-themed design with teal/cyan accents
// Color definitions for the TUI theme

var (
	// Primary colors - Pigeon Theme
	PrimaryColor    = lipgloss.Color("62")   // Teal (#3FA796) - Headers, highlights
	SecondaryColor  = lipgloss.Color("51")   // Cyan (#00D7FF) - Table headers, emphasis
	AccentColor     = lipgloss.Color("206")  // Magenta (#FF00FF) - Alerts, important

	// Semantic colors
	SuccessColor = lipgloss.Color("10")   // Green (#00FF00) - Positive actions
	WarningColor = lipgloss.Color("220")  // Yellow (#FFFF00) - Warnings
	ErrorColor   = lipgloss.Color("196")  // Red (#FF0000) - Errors

	// Neutral colors
	FgColor       = lipgloss.Color("255") // White (#FFFFFF) - Text
	FgDimColor    = lipgloss.Color("243") // Gray (#767676) - Inactive, muted
	BgColor       = lipgloss.Color("235") // Dark gray (#1C1C1C) - Background
	BorderColor   = lipgloss.Color("238") // Gray (#444444) - Box borders
)

// Styles for different UI elements

// HeaderStyle for titles and headers
var HeaderStyle = lipgloss.NewStyle().
	Foreground(PrimaryColor).
	Bold(true)

// SubheaderStyle for column headers - uses cyan from Pigeon theme
var SubheaderStyle = lipgloss.NewStyle().
	Foreground(SecondaryColor).
	Bold(true).
	Underline(false)

// SelectedStyle for selected rows/items
var SelectedStyle = lipgloss.NewStyle().
	Foreground(BgColor).
	Background(PrimaryColor).
	Bold(true)

// ErrorStyle for error messages
var ErrorStyle = lipgloss.NewStyle().
	Foreground(ErrorColor).
	Bold(true)

// SuccessStyle for success messages
var SuccessStyle = lipgloss.NewStyle().
	Foreground(SuccessColor).
	Bold(true)

// DimStyle for dimmed/inactive text
var DimStyle = lipgloss.NewStyle().
	Foreground(FgDimColor)

// BorderStyle for table/box borders
var BorderStyle = lipgloss.NewStyle().
	Foreground(BorderColor)

// HighlightStyle for highlighted text
var HighlightStyle = lipgloss.NewStyle().
	Foreground(AccentColor).
	Bold(true)
