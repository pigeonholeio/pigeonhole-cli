package styles

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// Box renders a bordered container with content
func Box(content string, title string, width int) string {
	style := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(BorderColor).
		Padding(PaddingTop, PaddingLeft, PaddingBottom, PaddingRight)

	if title != "" {
		style = style.BorderTop(true)
	}

	return style.Render(content)
}

// Table renders a data grid with headers, rows, and selection
func Table(headers []string, rows [][]string, selectedIdx int, width int) string {
	if width < MinWidth {
		width = MinWidth
	}

	output := strings.Builder{}

	// Top border
	output.WriteString("┌")
	output.WriteString(strings.Repeat("─", width-2))
	output.WriteString("┐\n")

	// Header row with padding
	headerRow := "│ " + strings.Join(headers, " │ ") + " │"
	headerRow = truncateRow(headerRow, width)
	output.WriteString(HeaderStyle.Render(headerRow))
	output.WriteString("\n")

	// Header divider
	output.WriteString("├")
	output.WriteString(strings.Repeat("─", width-2))
	output.WriteString("┤\n")

	// Data rows
	for i, row := range rows {
		prefix := "  "
		if i == selectedIdx {
			prefix = "▶ "
		}

		// Build row with proper spacing
		rowStr := "│ " + prefix + strings.Join(row, " │ ") + " │"
		rowStr = truncateRow(rowStr, width)

		if i == selectedIdx {
			output.WriteString(SelectedStyle.Render(rowStr))
		} else {
			output.WriteString(rowStr)
		}
		output.WriteString("\n")
	}

	// Bottom border
	output.WriteString("└")
	output.WriteString(strings.Repeat("─", width-2))
	output.WriteString("┘")

	return output.String()
}

// Header renders a full-width header with title and optional subtitle
func Header(title string, subtitle string, width int) string {
	if width < MinWidth {
		width = MinWidth
	}

	style := lipgloss.NewStyle().
		Foreground(PrimaryColor).
		Bold(true).
		Padding(0, PaddingLeft)

	headerText := title
	if subtitle != "" {
		// Right-align subtitle
		padding := width - len(title) - len(subtitle) - 4
		if padding > 0 {
			headerText = title + strings.Repeat(" ", padding) + subtitle
		} else {
			headerText = title
		}
	}

	return "┌─ " + style.Render(headerText) + " " + strings.Repeat("─", width-len(title)-8) + "┐"
}

// Footer renders a status bar with left, center, and right sections
func Footer(left, center, right string, width int) string {
	if width < MinWidth {
		width = MinWidth
	}

	style := lipgloss.NewStyle().
		Foreground(FgDimColor).
		Padding(0, PaddingLeft)

	// Calculate spacing
	leftPart := style.Render(left)
	rightPart := style.Render(right)
	centerPart := style.Render(center)

	// Approximate widths (accounting for ANSI codes)
	leftWidth := lipgloss.Width(left)
	rightWidth := lipgloss.Width(right)
	centerWidth := lipgloss.Width(center)

	totalPadding := width - leftWidth - rightWidth - centerWidth - 6
	if totalPadding < 1 {
		totalPadding = 1
	}

	footer := " │ " + leftPart + strings.Repeat(" ", totalPadding/2) + centerPart +
		strings.Repeat(" ", totalPadding/2) + rightPart + " │"

	return footer
}

// StatusLine renders interactive key hints at the bottom
func StatusLine(bindings []string, width int) string {
	if width < MinWidth {
		width = MinWidth
	}

	content := strings.Join(bindings, "  ")
	style := lipgloss.NewStyle().
		Foreground(FgDimColor).
		Padding(0, PaddingLeft)

	line := "  " + style.Render(content)
	if lipgloss.Width(line) > width {
		line = line[:width-3] + "..."
	}

	return line
}

// InfoBox renders a centered information box with optional border
func InfoBox(title, content string, width int) string {
	if width < MinWidth {
		width = MinWidth
	}

	lines := strings.Split(content, "\n")
	output := strings.Builder{}

	// Top border
	output.WriteString("┌")
	output.WriteString(strings.Repeat("─", width-2))
	output.WriteString("┐\n")

	// Title if provided
	if title != "" {
		titleRow := "│ " + HeaderStyle.Render(title) + strings.Repeat(" ", width-len(title)-4) + " │"
		output.WriteString(titleRow)
		output.WriteString("\n")

		output.WriteString("├")
		output.WriteString(strings.Repeat("─", width-2))
		output.WriteString("┤\n")
	}

	// Content lines
	for _, line := range lines {
		contentRow := "│ " + line + strings.Repeat(" ", width-len(line)-4) + " │"
		if lipgloss.Width(contentRow) > width {
			contentRow = contentRow[:width-1] + "│"
		}
		output.WriteString(contentRow)
		output.WriteString("\n")
	}

	// Bottom border
	output.WriteString("└")
	output.WriteString(strings.Repeat("─", width-2))
	output.WriteString("┘")

	return output.String()
}

// truncateRow ensures row doesn't exceed width
func truncateRow(row string, width int) string {
	if lipgloss.Width(row) > width {
		return row[:width-1] + "│"
	}
	return row
}

// Padding for table columns
type ColumnConfig struct {
	Title string
	Width int
}

// FormatTableRow formats a row with specified column widths
func FormatTableRow(values []string, columns []ColumnConfig, selected bool) string {
	var parts []string

	for i, val := range values {
		if i < len(columns) {
			width := columns[i].Width
			padded := padString(val, width)
			parts = append(parts, padded)
		}
	}

	prefix := "  "
	if selected {
		prefix = "▶ "
	}

	row := prefix + strings.Join(parts, " ")
	return row
}

// padString pads or truncates string to exact width
func padString(s string, width int) string {
	if len(s) > width {
		if width > 3 {
			return s[:width-1] + "…"
		}
		return s[:width]
	}
	return s + strings.Repeat(" ", width-len(s))
}
