package ui

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/mattn/go-isatty"
	"github.com/pigeonholeio/pigeonhole-cli/tui/styles"
)

var isTTY = isatty.IsTerminal(os.Stdout.Fd())

var (
	successStyle = lipgloss.NewStyle().Foreground(styles.SuccessColor).Bold(true)
	errorStyle   = lipgloss.NewStyle().Foreground(styles.ErrorColor).Bold(true)
	warnStyle    = lipgloss.NewStyle().Foreground(styles.WarningColor).Bold(true)
	dimStyle     = lipgloss.NewStyle().Foreground(styles.FgDimColor)
	headerStyle  = lipgloss.NewStyle().Foreground(styles.PrimaryColor).Bold(true)
	labelStyle   = lipgloss.NewStyle().Foreground(styles.FgColor)
)

var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// Header prints a prominent header line, e.g. "🔑 Authenticating via OIDC..."
func Header(icon, msg string) {
	fmt.Printf("%s %s\n", icon, headerStyle.Render(msg))
}

// Success prints a green ✓ success line.
func Success(msg string) {
	fmt.Printf("%s  %s\n", successStyle.Render("✓"), labelStyle.Render(msg))
}

// Error prints a red ✗ error line.
func Error(msg string) {
	fmt.Printf("%s  %s\n", errorStyle.Render("✗"), labelStyle.Render(msg))
}

// Warn prints a yellow ⚠ warning line.
func Warn(msg string) {
	fmt.Printf("%s  %s\n", warnStyle.Render("⚠"), labelStyle.Render(msg))
}

// Info prints a dim informational line.
func Info(msg string) {
	fmt.Printf("   %s\n", dimStyle.Render(msg))
}

// Step starts an animated spinner for label and returns a resolve func.
// Call resolve(nil) to show ✓, resolve(err) to show ✗ with the error.
func Step(label string) func(err error) {
	if !isTTY {
		fmt.Printf("   %s...\n", label)
		return func(err error) {
			if err != nil {
				Error(label + ": " + err.Error())
			}
		}
	}

	var mu sync.Mutex
	done := make(chan struct{})
	frameIdx := 0

	// Pre-render the spinner text once so ANSI codes are consistent across frames.
	spinnerText := dimStyle.Render(label + "...")

	// print initial frame
	fmt.Printf("   %s %s", spinnerFrames[0], spinnerText)

	go func() {
		ticker := time.NewTicker(80 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				mu.Lock()
				frameIdx = (frameIdx + 1) % len(spinnerFrames)
				// \r returns to col 0; \033[K erases to end of line before reprinting.
				fmt.Printf("\r\033[K   %s %s", spinnerFrames[frameIdx], spinnerText)
				mu.Unlock()
			}
		}
	}()

	return func(err error) {
		mu.Lock()
		defer mu.Unlock()
		close(done)
		// clear the spinner line then print result
		if err != nil {
			fmt.Printf("\r\033[K%s  %s: %s\n", errorStyle.Render("✗"), labelStyle.Render(label), dimStyle.Render(err.Error()))
		} else {
			fmt.Printf("\r\033[K%s  %s\n", successStyle.Render("✓"), labelStyle.Render(label))
		}
	}
}
