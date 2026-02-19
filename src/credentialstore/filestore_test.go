package credentialstore

import (
	"path/filepath"
	"testing"
)

// TestFileStore_SaveAndLoadActiveUser tests saving and loading the active user
func TestFileStore_SaveAndLoadActiveUser(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	store := NewFileStore(&configPath)

	// Initially no active user
	activeUser, err := store.GetActiveUser()
	if err != ErrCredentialNotFound {
		t.Fatalf("expected ErrCredentialNotFound, got %v", err)
	}

	// Save an active user
	testEmail := "user@example.com"
	if err := store.SaveActiveUser(testEmail); err != nil {
		t.Fatalf("SaveActiveUser failed: %v", err)
	}

	// Load the active user
	activeUser, err = store.GetActiveUser()
	if err != nil {
		t.Fatalf("GetActiveUser failed: %v", err)
	}
	if activeUser != testEmail {
		t.Fatalf("expected %s, got %s", testEmail, activeUser)
	}
}

// TestFileStore_SaveAndLoadAccessToken tests saving and loading access token
func TestFileStore_SaveAndLoadAccessToken(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	store := NewFileStore(&configPath)
	userEmail := "user@example.com"
	testToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiVGVzdCBVc2VyIiwiZW1haWwiOiJ1c2VyQGV4YW1wbGUuY29tIiwiaWF0IjoxNjAwMDAwMDAwLCJleHAiOjk5OTk5OTk5OTl9.fake"

	// Save access token
	if err := store.SaveAccessToken(userEmail, testToken); err != nil {
		t.Fatalf("SaveAccessToken failed: %v", err)
	}

	// Load access token
	token, err := store.GetAccessToken(userEmail)
	if err != nil {
		t.Fatalf("GetAccessToken failed: %v", err)
	}
	if token != testToken {
		t.Fatalf("token mismatch: expected %s, got %s", testToken, token)
	}
}

// TestFileStore_DiscoverUsers tests discovering users from file store
func TestFileStore_DiscoverUsers(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	store := NewFileStore(&configPath)
	user1 := "user1@example.com"
	user2 := "user2@example.com"

	// Save credentials for two users
	if err := store.SaveAccessToken(user1, "token1"); err != nil {
		t.Fatalf("SaveAccessToken failed: %v", err)
	}
	if err := store.SaveAccessToken(user2, "token2"); err != nil {
		t.Fatalf("SaveAccessToken failed: %v", err)
	}

	// Discover users
	users, err := store.DiscoverUsers()
	if err != nil {
		t.Fatalf("DiscoverUsers failed: %v", err)
	}

	t.Logf("Discovered users: %v", users)
	if len(users) != 2 {
		t.Fatalf("expected 2 users, got %d: %v", len(users), users)
	}

	// Check that both users are in the list
	found := make(map[string]bool)
	for _, user := range users {
		found[user] = true
	}

	if !found[user1] {
		t.Fatalf("user1 (%s) not found in discovered users: %v", user1, users)
	}
	if !found[user2] {
		t.Fatalf("user2 (%s) not found in discovered users: %v", user2, users)
	}
}

// TestFileStore_DeleteActiveUser tests clearing the active user
func TestFileStore_DeleteActiveUser(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	store := NewFileStore(&configPath)
	testEmail := "user@example.com"

	// Save an active user
	if err := store.SaveActiveUser(testEmail); err != nil {
		t.Fatalf("SaveActiveUser failed: %v", err)
	}

	// Verify it's saved
	activeUser, err := store.GetActiveUser()
	if err != nil {
		t.Fatalf("GetActiveUser failed: %v", err)
	}
	if activeUser != testEmail {
		t.Fatalf("expected %s, got %s", testEmail, activeUser)
	}

	// Delete the active user
	if err := store.DeleteActiveUser(); err != nil {
		t.Fatalf("DeleteActiveUser failed: %v", err)
	}

	// Verify it's deleted
	_, err = store.GetActiveUser()
	if err != ErrCredentialNotFound {
		t.Fatalf("expected ErrCredentialNotFound after delete, got %v", err)
	}
}

// TestFileStore_SaveAndLoadRefreshToken tests saving and loading refresh token
func TestFileStore_SaveAndLoadRefreshToken(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	store := NewFileStore(&configPath)
	userEmail := "user@example.com"
	testRefreshToken := "refresh-token-xyz"

	// Save refresh token
	if err := store.SaveRefreshToken(userEmail, testRefreshToken); err != nil {
		t.Fatalf("SaveRefreshToken failed: %v", err)
	}

	// Load refresh token
	token, err := store.GetRefreshToken(userEmail)
	if err != nil {
		t.Fatalf("GetRefreshToken failed: %v", err)
	}
	if token != testRefreshToken {
		t.Fatalf("token mismatch: expected %s, got %s", testRefreshToken, token)
	}
}
