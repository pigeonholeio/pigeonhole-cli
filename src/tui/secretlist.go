package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/pigeonholeio/common/utils"
	"github.com/pigeonholeio/pigeonhole-cli/sdk"
	"github.com/pigeonholeio/pigeonhole-cli/tui/styles"
)

// SecretListView displays the main secrets table
type SecretListView struct {
	state *AppState

	secrets          []sdk.Secret
	filtered         []sdk.Secret
	selectedIdx      int
	filterText       string
	sortBy           string
	sortDesc         bool
	loading          bool
	error            string
	pageSize         int
	currentPage      int
	confirmPending   bool
	confirmTarget    *sdk.Secret
	statusMsg        string
	statusMsgTime    time.Time
	statusMsgTimeout time.Duration
}

// NewSecretListView creates a new secret list view
func NewSecretListView(state *AppState) *SecretListView {
	return &SecretListView{
		state:            state,
		secrets:          []sdk.Secret{},
		filtered:         []sdk.Secret{},
		selectedIdx:      0,
		filterText:       "",
		sortBy:           "sent_at",
		sortDesc:         true,
		loading:          true,
		error:            "",
		pageSize:         20,
		currentPage:      0,
		confirmPending:   false,
		confirmTarget:    nil,
		statusMsg:        "",
		statusMsgTime:    time.Time{},
		statusMsgTimeout: 5 * time.Second,
	}
}

// Init initializes the secret list view
func (v *SecretListView) Init() tea.Cmd {
	return v.fetchSecretsCmd()
}

// Update handles messages
func (v *SecretListView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		return v.handleKeyPress(msg)

	case SecretsLoadedMsg:
		v.secrets = msg.Secrets
		v.filtered = msg.Secrets
		v.loading = false
		v.state.UI.LastRefresh = time.Now()
		return v, nil

	case SecretsFailedMsg:
		v.error = msg.Error
		v.loading = false
		return v, nil

	case SecretDeletedMsg:
		v.secrets = removeByRef(v.secrets, msg.Reference)
		v.filtered = removeByRef(v.filtered, msg.Reference)
		if v.selectedIdx >= len(v.filtered) {
			v.selectedIdx = maxInt(0, len(v.filtered)-1)
		}
		v.statusMsg = fmt.Sprintf("Deleted: %s", msg.Reference)
		v.statusMsgTime = time.Now()
		return v, nil

	case SecretDeleteFailedMsg:
		v.statusMsg = fmt.Sprintf("Error: %s", msg.Error)
		v.statusMsgTime = time.Now()
		return v, nil

	case SecretRetrievedMsg:
		v.statusMsg = fmt.Sprintf("Saved to %s", msg.Path)
		v.statusMsgTime = time.Now()
		return v, nil

	case SecretRetrieveFailedMsg:
		v.statusMsg = fmt.Sprintf("Retrieve failed: %s", msg.Error)
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

// View renders the secret list view
func (v *SecretListView) View() string {
	if v.loading {
		return "Loading secrets...\n"
	}

	if v.error != "" {
		return "Error loading secrets: " + v.error + "\n"
	}

	if len(v.secrets) == 0 {
		return v.renderEmptyState()
	}

	return v.renderTable()
}

// handleKeyPress processes keyboard input
func (v *SecretListView) handleKeyPress(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up":
		if !v.confirmPending && v.selectedIdx > 0 {
			v.selectedIdx--
		}
		return v, nil

	case "down":
		if !v.confirmPending && v.selectedIdx < len(v.filtered)-1 {
			v.selectedIdx++
		}
		return v, nil

	case "enter":
		if !v.confirmPending && len(v.filtered) > 0 {
			return v, func() tea.Msg {
				return SecretSelectedMsg{Secret: v.filtered[v.selectedIdx]}
			}
		}
		return v, nil

	case "c":
		if !v.confirmPending && len(v.filtered) > 0 {
			selected := v.filtered[v.selectedIdx]
			v.statusMsg = fmt.Sprintf("Retrieving %s...", deref(selected.Reference))
			v.statusMsgTime = time.Now()
			return v, v.retrieveSecretCmd(selected)
		}
		return v, nil

	case "d":
		if !v.confirmPending && len(v.filtered) > 0 {
			v.confirmPending = true
			target := v.filtered[v.selectedIdx]
			v.confirmTarget = &target
		}
		return v, nil

	case "y":
		if v.confirmPending && v.confirmTarget != nil {
			target := *v.confirmTarget
			v.confirmPending = false
			v.confirmTarget = nil
			return v, v.deleteSecretCmd(target)
		}
		return v, nil

	case "n", "escape":
		if v.confirmPending {
			v.confirmPending = false
			v.confirmTarget = nil
		}
		return v, nil

	case "/":
		// Enter filter mode (stub)
		return v, nil

	case "r":
		if !v.confirmPending {
			v.loading = true
			return v, v.fetchSecretsCmd()
		}
		return v, nil

	case "q":
		return v, tea.Quit
	}

	return v, nil
}

// renderTable renders the secrets table with styling
func (v *SecretListView) renderTable() string {
	// Get terminal width or use default
	width := v.state.UI.TerminalWidth
	if width < styles.MinWidth {
		width = styles.MinWidth
	}

	// Calculate dynamic column widths based on terminal width
	cols := styles.CalculateColumnWidths(width)

	output := strings.Builder{}

	// Top border
	output.WriteString("┌")
	output.WriteString(strings.Repeat("─", width-2))
	output.WriteString("┐\n")

	// Title with count - build with exact width calculation
	title := fmt.Sprintf("Pigeonhole - Secrets (%d total)", len(v.secrets))
	email := v.state.Session.Email
	// Width breakdown: | (1) + space (1) + title + padding + email + space (1) + | (1)
	innerWidth := width - 2 // subtract left and right borders
	titleEmail := title + " " + email
	padding := innerWidth - 1 - 1 - len(titleEmail) // -1 for space after title, -1 for final space
	if padding < 1 {
		padding = 1
	}
	titleContent := " " + title + strings.Repeat(" ", padding) + email + " "
	// Ensure exact width
	if len(titleContent) < innerWidth {
		titleContent = titleContent + strings.Repeat(" ", innerWidth-len(titleContent))
	} else if len(titleContent) > innerWidth {
		titleContent = titleContent[:innerWidth]
	}
	output.WriteString("│" + titleContent + "│\n")

	// Column headers divider
	output.WriteString("├")
	output.WriteString(strings.Repeat("─", width-2))
	output.WriteString("┤\n")

	// Build header row with exact width
	headers := []string{
		padString("Reference", cols.Reference),
		padString("From", cols.From),
		padString("To", cols.To),
		padString("Size", cols.Size),
		padString("Sent", cols.Sent),
		padString("1x", cols.OneTime),
	}
	headerContent := " " + strings.Join(headers, " ") + " "
	// Ensure exact width
	if len(headerContent) < innerWidth {
		headerContent = headerContent + strings.Repeat(" ", innerWidth-len(headerContent))
	} else if len(headerContent) > innerWidth {
		headerContent = headerContent[:innerWidth]
	}
	output.WriteString("│" + headerContent + "│\n")

	// Data divider
	output.WriteString("├")
	output.WriteString(strings.Repeat("─", width-2))
	output.WriteString("┤\n")

	// Secret rows
	if len(v.filtered) == 0 {
		// Empty state in table
		emptyRow := fmt.Sprintf("│ %-*s │\n", width-4, "No secrets to display")
		output.WriteString(emptyRow)
	} else {
		for i, secret := range v.filtered {
			prefix := "  "
			if i == v.selectedIdx {
				prefix = "▶ "
			}

			// Format fields with dynamic column widths
			ref := truncate(deref(secret.Reference), cols.Reference)
			from := truncate(deref(secret.Sender), cols.From)
			to := truncate(deref(secret.Recipient), cols.To)
			size := formatSize(secret.Size)
			sent := formatTime(secret.SentAt)
			oneTime := ""
			if secret.Onetime != nil && *secret.Onetime {
				oneTime = "✓"
			}

			// Build row content (without borders for now)
			content := fmt.Sprintf("%s%-*s %-*s %-*s %-*s %-*s %*s",
				prefix,
				cols.Reference, ref,
				cols.From, from,
				cols.To, to,
				cols.Size, size,
				cols.Sent, sent,
				cols.OneTime, oneTime)

			// Pad or truncate to exact width minus 2 for left/right borders
			innerWidth := width - 2
			if len(content) < innerWidth {
				content = content + strings.Repeat(" ", innerWidth-len(content))
			} else if len(content) > innerWidth {
				content = content[:innerWidth]
			}

			// Build final row with borders and apply styling
			row := "│" + content + "│"

			// Apply styling AFTER building the exact-width row
			if i == v.selectedIdx {
				row = styles.SelectedStyle.Render(row)
			}

			output.WriteString(row)
			output.WriteString("\n")
		}
	}

	// Bottom border
	output.WriteString("└")
	output.WriteString(strings.Repeat("─", width-2))
	output.WriteString("┘\n")

	// Status line - context dependent
	var statusLine string
	if v.confirmPending && v.confirmTarget != nil {
		statusLine = styles.ErrorStyle.Render(fmt.Sprintf(`  Delete "%s"? (y/N)`, deref(v.confirmTarget.Reference)))
	} else if v.statusMsg != "" {
		// Determine style based on message content
		if strings.HasPrefix(v.statusMsg, "Error") || strings.HasPrefix(v.statusMsg, "Retrieve failed") {
			statusLine = styles.ErrorStyle.Render("  " + v.statusMsg)
		} else {
			statusLine = styles.SuccessStyle.Render("  " + v.statusMsg)
		}
	} else {
		// Default key hints
		statusBindings := []string{
			"↑↓ navigate",
			"enter details",
			"c retrieve",
			"d delete",
			"r refresh",
			"q quit",
		}
		statusLine = styles.DimStyle.Render("  " + strings.Join(statusBindings, "  "))
	}
	output.WriteString(statusLine)
	output.WriteString("\n")

	return output.String()
}

// buildHeaderRow creates the header row with column labels
func buildHeaderRow(width int) string {
	headers := []string{
		padString("Reference", styles.ReferenceWidth),
		padString("From", styles.FromWidth),
		padString("To", styles.ToWidth),
		padString("Size", styles.SizeWidth),
		padString("Sent", styles.SentWidth),
		"One Time",
	}

	row := "│ " + strings.Join(headers, " ") + " │"

	// Apply header styling
	return styles.SubheaderStyle.Render(row)
}

// Helper functions for formatting
func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func truncate(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen-1] + "…"
	}
	return s
}

func formatSize(size *int64) string {
	if size == nil {
		return "-"
	}
	// Use SDK's ToSecretView which already has humanize
	view := sdk.ToSecretView(sdk.Secret{Size: size})
	if view.Size != nil {
		return *view.Size
	}
	return "-"
}

func formatTime(t *time.Time) string {
	if t == nil {
		return "-"
	}
	now := time.Now()
	diff := now.Sub(*t)

	if diff < time.Minute {
		return "now"
	} else if diff < time.Hour {
		return fmt.Sprintf("%dm ago", int(diff.Minutes()))
	} else if diff < 24*time.Hour {
		return fmt.Sprintf("%dh ago", int(diff.Hours()))
	} else {
		days := int(diff.Hours() / 24)
		return fmt.Sprintf("%dd ago", days)
	}
}

func formatShortTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Format("15:04:05")
}

// padString pads or truncates a string to exact width
func padString(s string, width int) string {
	if len(s) > width {
		if width > 3 {
			return s[:width-1] + "…"
		}
		return s[:width]
	}
	return s + strings.Repeat(" ", width-len(s))
}

// removeByRef removes a secret with matching reference from a slice
func removeByRef(secrets []sdk.Secret, ref string) []sdk.Secret {
	result := []sdk.Secret{}
	for _, s := range secrets {
		if deref(s.Reference) != ref {
			result = append(result, s)
		}
	}
	return result
}

// maxInt returns the maximum of two integers
func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// renderEmptyState renders the empty state
func (v *SecretListView) renderEmptyState() string {
	width := v.state.UI.TerminalWidth
	if width < styles.MinWidth {
		width = styles.MinWidth
	}

	output := strings.Builder{}

	// Top border
	output.WriteString("┌")
	output.WriteString(strings.Repeat("─", width-2))
	output.WriteString("┐\n")

	// Title
	title := "Pigeonhole - Secrets"
	titleRow := "│ " + styles.HeaderStyle.Render(title) + strings.Repeat(" ", width-len(title)-4) + " │\n"
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
		"     Use the CLI to send someone a secret:",
		"",
		"       pigeonhole secret send -r email@example.com -f myfile.txt",
		"",
		"     Press 'r' to refresh or 'q' to quit",
		"",
	}

	for _, line := range content {
		contentRow := "│ " + line + strings.Repeat(" ", width-len(line)-4) + " │\n"
		output.WriteString(contentRow)
	}

	// Bottom border with user info
	output.WriteString("└")
	output.WriteString(strings.Repeat("─", width-2))
	output.WriteString("┘\n")

	// Status line
	lastSyncStr := formatShortTime(v.state.UI.LastRefresh)
	statusLine := "  " + styles.DimStyle.Render("User: "+v.state.Session.Email+" | Last sync: "+lastSyncStr)
	output.WriteString(statusLine)
	output.WriteString("\n")

	return output.String()
}

// retrieveSecretCmd downloads and decrypts a secret
func (v *SecretListView) retrieveSecretCmd(secret sdk.Secret) tea.Cmd {
	return func() tea.Msg {
		ref := deref(secret.Reference)

		// 1. Get presigned download URL from API
		resp, err := v.state.Client.GetSecretSecretIdDownloadWithResponse(v.state.GlobalCtx, ref)
		if err != nil || resp.JSON200 == nil {
			return SecretRetrieveFailedMsg{Reference: ref, Error: "failed to get download URL"}
		}

		// 2. Output dir: ./decrypted/<ref>/
		outPath, _ := filepath.Abs(filepath.Join("decrypted", ref))
		if err := os.MkdirAll(outPath, 0744); err != nil {
			return SecretRetrieveFailedMsg{Reference: ref, Error: "failed to create output directory"}
		}

		// 3. Download to temp file, read bytes, remove temp
		tmpFile, err := utils.DownloadFile(resp.JSON200.DownloadUrl)
		if err != nil {
			return SecretRetrieveFailedMsg{Reference: ref, Error: "download failed"}
		}
		inputBytes, err := os.ReadFile(tmpFile)
		os.Remove(tmpFile)
		if err != nil {
			return SecretRetrieveFailedMsg{Reference: ref, Error: "failed to read downloaded file"}
		}

		// 4. Decrypt: try each identity in Config.Identity
		var decryptedPath string
		if v.state.Config.Identity == nil || len(v.state.Config.Identity) == 0 {
			return SecretRetrieveFailedMsg{Reference: ref, Error: "no GPG keys configured"}
		}

		for _, identity := range v.state.Config.Identity {
			if identity.GPGKey == nil || !identity.GPGKey.KeyExists() {
				continue
			}
			key, err := identity.GPGKey.DecodedPrivateKey()
			if err != nil {
				continue
			}
			decryptedPath, err = utils.DecryptBytes(inputBytes, &outPath, &key)
			if err == nil {
				break
			}
		}
		if decryptedPath == "" {
			return SecretRetrieveFailedMsg{Reference: ref, Error: "decryption failed - no matching GPG key"}
		}

		// 5. Decompress tar.gz → outPath
		if err := utils.DecompressFile(decryptedPath, outPath); err != nil {
			return SecretRetrieveFailedMsg{Reference: ref, Error: "decompression failed"}
		}

		// 6. Shred temp decrypted file
		if err := utils.ShredFile(decryptedPath, 3); err != nil {
			// Log but don't fail - file cleanup is secondary
		}

		return SecretRetrievedMsg{Reference: ref, Path: outPath}
	}
}

// deleteSecretCmd deletes a secret via API
func (v *SecretListView) deleteSecretCmd(secret sdk.Secret) tea.Cmd {
	return func() tea.Msg {
		ref := deref(secret.Reference)
		resp, err := v.state.Client.DeleteSecretSecretIdWithResponse(v.state.GlobalCtx, ref)
		if err != nil || resp.JSON200 == nil {
			return SecretDeleteFailedMsg{Reference: ref, Error: "delete failed"}
		}
		return SecretDeletedMsg{Reference: ref}
	}
}

// Command to fetch secrets
func (v *SecretListView) fetchSecretsCmd() tea.Cmd {
	return func() tea.Msg {
		// Use pre-fetched secrets from state (loaded by main.go before TUI launch)
		secrets := v.state.Session.Secrets
		if secrets == nil {
			secrets = []sdk.Secret{}
		}
		return SecretsLoadedMsg{
			Secrets: secrets,
			Total:   len(secrets),
		}
	}
}
