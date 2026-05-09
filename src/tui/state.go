package tui

import (
	"context"
	"time"

	"github.com/pigeonholeio/pigeonhole-cli/config"
	"github.com/pigeonholeio/pigeonhole-cli/sdk"
)

// ViewType represents the current view being displayed
type ViewType int

const (
	ViewSecretList ViewType = iota
	ViewSecretDetail
	ViewError
	ViewEmpty
)

// UserSession holds the current user's session state
type UserSession struct {
	Email      string
	Keys       []sdk.Key
	Secrets    []sdk.Secret
	FilterText string
}

// UIState holds UI-specific state
type UIState struct {
	SelectedRow     int
	ScrollOffset    int
	FilterText      string
	LastRefresh     time.Time
	SyncInProgress  bool
	ErrorMessage    string
	ErrorDetails    string
	ConfirmPending  bool
	ConfirmCallback func()
	TerminalWidth   int
	TerminalHeight  int
}

// AppState holds all global state for the TUI
type AppState struct {
	// Configuration and clients
	Config    *config.PigeonHoleConfig
	Client    *sdk.ClientWithResponses
	GlobalCtx context.Context
	Version   string

	// Current view and navigation
	CurrentView ViewType
	PreviousView ViewType

	// User session
	Session UserSession

	// UI state
	UI UIState

	// Timestamps
	CreatedAt time.Time
	UpdatedAt time.Time
}

// NewAppState creates a new app state with initial values
func NewAppState(cfg *config.PigeonHoleConfig, client *sdk.ClientWithResponses, version string) *AppState {
	now := time.Now()

	return &AppState{
		Config:       cfg,
		Client:       client,
		Version:      version,
		CurrentView:  ViewSecretList,
		PreviousView: ViewSecretList,
		Session: UserSession{
			Email:      "",
			Keys:       []sdk.Key{},
			Secrets:    []sdk.Secret{},
			FilterText: "",
		},
		UI: UIState{
			SelectedRow:    0,
			ScrollOffset:   0,
			FilterText:     "",
			LastRefresh:    now,
			SyncInProgress: false,
			ErrorMessage:   "",
			ErrorDetails:   "",
			ConfirmPending: false,
			TerminalWidth:  80,
			TerminalHeight: 24,
		},
		CreatedAt: now,
		UpdatedAt: now,
	}
}

// SetError sets an error message and transitions to error view
func (s *AppState) SetError(message, details string) {
	s.UI.ErrorMessage = message
	s.UI.ErrorDetails = details
	s.PreviousView = s.CurrentView
	s.CurrentView = ViewError
}

// ClearError clears the error message
func (s *AppState) ClearError() {
	s.UI.ErrorMessage = ""
	s.UI.ErrorDetails = ""
}

// TransitionView changes the current view
func (s *AppState) TransitionView(view ViewType) {
	s.PreviousView = s.CurrentView
	s.CurrentView = view
	s.UpdatedAt = time.Now()
}

// GoBack returns to the previous view
func (s *AppState) GoBack() {
	temp := s.CurrentView
	s.CurrentView = s.PreviousView
	s.PreviousView = temp
	s.UpdatedAt = time.Now()
}

// UpdateUI updates the updated timestamp
func (s *AppState) UpdateUI() {
	s.UpdatedAt = time.Now()
}

