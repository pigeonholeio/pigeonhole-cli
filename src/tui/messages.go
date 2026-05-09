package tui

import (
	"time"

	"github.com/pigeonholeio/pigeonhole-cli/sdk"
)

// Message types for the TUI state machine

// Navigation messages
type ViewChangedMsg struct {
	View ViewType
}

type NextViewMsg struct{}
type BackMsg struct{}

// Secret messages
type SecretsLoadedMsg struct {
	Secrets []sdk.Secret
	Total   int
}

type SecretsFailedMsg struct {
	Error string
}

type SecretsFilteredMsg struct {
	Filtered []sdk.Secret
}

type SecretSelectedMsg struct {
	Secret sdk.Secret
}

type SecretDeletedMsg struct {
	Reference string
}

type SecretDeleteFailedMsg struct {
	Reference string
	Error     string
}

type SecretRetrievedMsg struct {
	Reference string
	Path      string
}

type SecretRetrieveFailedMsg struct {
	Reference string
	Error     string
}

// UI messages
type KeyPressMsg struct {
	Key string
}

type FilterUpdatedMsg struct {
	Text string
}

type RowSelectedMsg struct {
	Index int
}

type ScrolledMsg struct {
	Direction int // -1 for up, 1 for down
}

type RefreshMsg struct{}

// Error messages
type ErrorOccurredMsg struct {
	Error   string
	Details string
}

type ErrorDismissedMsg struct{}

// Status messages
type StatusUpdatedMsg struct {
	Message string
}

type SyncStartedMsg struct{}

type SyncCompletedMsg struct {
	LastSync time.Time
}

// Tick messages for animations/polling
type TickMsg struct {
	Time time.Time
}
