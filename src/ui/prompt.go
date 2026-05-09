package ui

import (
	"fmt"
	"os"
	"syscall"

	"github.com/charmbracelet/lipgloss"
	"github.com/pigeonholeio/pigeonhole-cli/tui/styles"
	"golang.org/x/term"
)

var promptStyle = lipgloss.NewStyle().Foreground(styles.SecondaryColor).Bold(true)

// SecretPrompt displays a labelled masked input prompt and returns the entered value.
// Characters are echoed as • while typing; the terminal is restored on return.
func SecretPrompt(label string) (string, error) {
	fmt.Printf("%s %s\n", promptStyle.Render("?"), labelStyle.Render(label))
	fmt.Printf("   ")

	// Switch terminal to raw mode to intercept keystrokes for masking
	fd := int(os.Stdin.Fd())
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		// Fallback: read without masking
		var line string
		fmt.Scanln(&line)
		return line, nil
	}
	defer term.Restore(fd, oldState)

	var buf []byte
	tmp := make([]byte, 1)
	for {
		_, err := syscall.Read(fd, tmp)
		if err != nil {
			break
		}
		ch := tmp[0]
		switch {
		case ch == '\r' || ch == '\n':
			fmt.Print("\n")
			return string(buf), nil
		case ch == 127 || ch == '\b': // backspace / delete
			if len(buf) > 0 {
				buf = buf[:len(buf)-1]
				fmt.Print("\b \b")
			}
		case ch == 3: // ctrl+c
			fmt.Print("\n")
			return "", fmt.Errorf("interrupted")
		default:
			buf = append(buf, ch)
			fmt.Print("•")
		}
	}
	return string(buf), nil
}
