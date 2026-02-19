package credentialstore

import (
	"path/filepath"
	"testing"
)

func TestNewStore(t *testing.T) {
	tmpfile := filepath.Join(t.TempDir(), "test-config.yaml")
	store, err := NewStore(&tmpfile)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}

	if store == nil {
		t.Fatal("NewStore returned nil store")
	}

	backend := store.Backend()
	if backend != "keyring" && backend != "file" {
		t.Fatalf("unexpected backend: %s", backend)
	}
}

func TestNewFileStore(t *testing.T) {
	tmpfile := filepath.Join(t.TempDir(), "test-creds.yaml")
	store := NewFileStore(&tmpfile)
	if store == nil {
		t.Fatal("NewFileStore returned nil")
	}

	backend := store.Backend()
	if backend != "file" {
		t.Fatalf("expected 'file' backend, got '%s'", backend)
	}
}

func TestNewKeyringStore(t *testing.T) {
	var configPath *string
	store := NewKeyringStore(configPath)
	if store == nil {
		t.Fatal("NewKeyringStore returned nil")
	}

	backend := store.Backend()
	if backend != "keyring" {
		t.Fatalf("expected 'keyring' backend, got '%s'", backend)
	}
}

func TestStoreInterface(t *testing.T) {
	tmpfile := filepath.Join(t.TempDir(), "test-creds.yaml")
	store := NewFileStore(&tmpfile)

	// Verify all methods exist by checking signatures
	var _ Store = store
}

func TestCredentialNotFoundError(t *testing.T) {
	if ErrCredentialNotFound == nil {
		t.Fatal("ErrCredentialNotFound is nil")
	}

	expected := "credential not found"
	if ErrCredentialNotFound.Error() != expected {
		t.Fatalf("unexpected error message: expected '%s', got '%s'", expected, ErrCredentialNotFound.Error())
	}
}

func TestFileStoreBackendName(t *testing.T) {
	tmpfile := filepath.Join(t.TempDir(), "test-creds.yaml")
	store := NewFileStore(&tmpfile)
	if store.Backend() != "file" {
		t.Fatal("FileStore backend should be 'file'")
	}
}

func TestKeyringStoreBackendName(t *testing.T) {
	var configPath *string
	store := NewKeyringStore(configPath)
	if store.Backend() != "keyring" {
		t.Fatal("KeyringStore backend should be 'keyring'")
	}
}
