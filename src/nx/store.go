// Package nx is the Cloudflare-era PigeonHole client (new API at api.pigeono.io):
// keypair identity, capability uploads/downloads, OpenPGP E2EE.
package nx

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Identity is the locally-stored device identity. The private key never leaves
// this machine (PLAN: zero-knowledge; accept-loss recovery).
type Identity struct {
	Email       string `json:"email"`
	Token       string `json:"token"`
	PublicKey   string `json:"public_key"`
	PrivateKey  string `json:"private_key"`
	Thumbprint  string `json:"thumbprint"`
}

func dir() (string, error) {
	h, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	d := filepath.Join(h, ".pigeonhole")
	return d, os.MkdirAll(d, 0o700)
}

func identityPath() (string, error) {
	d, err := dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "identity.json"), nil
}

func LoadIdentity() (*Identity, error) {
	p, err := identityPath()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("not logged in (run `pigeonhole login`): %w", err)
	}
	var id Identity
	if err := json.Unmarshal(b, &id); err != nil {
		return nil, err
	}
	return &id, nil
}

func SaveIdentity(id *Identity) error {
	p, err := identityPath()
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, b, 0o600)
}
