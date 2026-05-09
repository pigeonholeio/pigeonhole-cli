package styles

// Layout constants for consistent spacing
const (
	// Padding
	PaddingTop    = 1
	PaddingBottom = 1
	PaddingLeft   = 2
	PaddingRight  = 2

	// Spacing
	SpaceSmall  = 1
	SpaceMedium = 2
	SpaceLarge  = 3

	// Borders
	BorderWidth = 1

	// Minimums
	MinWidth  = 80
	MinHeight = 20

	// Table
	TablePageSize = 20
	TableRowGap   = 1
)

// WidgetWidths for consistent column widths
const (
	ReferenceWidth  = 25
	FromWidth       = 20
	ToWidth         = 20
	SizeWidth       = 10
	SentWidth       = 12
	ExpiresWidth    = 12
	OneTimeWidth    = 3
	StatusWidth     = 12
)

// ColumnWidths holds dynamically calculated column widths
type ColumnWidths struct {
	Reference int
	From      int
	To        int
	Size      int
	Sent      int
	OneTime   int
}

// CalculateColumnWidths computes column widths based on terminal width
// Format: │ <prefix(2)> <ref> <from> <to> <size> <sent> <1x> │
// With spaces between columns: 5 spaces between 6 columns
func CalculateColumnWidths(terminalWidth int) ColumnWidths {
	if terminalWidth < MinWidth {
		terminalWidth = MinWidth
	}

	// Total: 2 borders + 2 spaces (left/right) + 5 spaces (between cols) + prefix(2) = 13 fixed chars
	availableWidth := terminalWidth - 13

	// For very wide terminals (120+), use full fixed widths
	minRequired := ReferenceWidth + FromWidth + ToWidth + SizeWidth + SentWidth + OneTimeWidth
	if availableWidth >= minRequired {
		return ColumnWidths{
			Reference: ReferenceWidth,
			From:      FromWidth,
			To:        ToWidth,
			Size:      SizeWidth,
			Sent:      SentWidth,
			OneTime:   OneTimeWidth,
		}
	}

	// For narrow terminals, scale proportionally
	// Scale ratio: available / minimum required
	scale := float64(availableWidth) / float64(minRequired)

	return ColumnWidths{
		Reference: maxInt(8, int(float64(ReferenceWidth)*scale)),
		From:      maxInt(8, int(float64(FromWidth)*scale)),
		To:        maxInt(8, int(float64(ToWidth)*scale)),
		Size:      maxInt(6, int(float64(SizeWidth)*scale)),
		Sent:      maxInt(6, int(float64(SentWidth)*scale)),
		OneTime:   maxInt(2, OneTimeWidth),
	}
}

// Helper function
func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
