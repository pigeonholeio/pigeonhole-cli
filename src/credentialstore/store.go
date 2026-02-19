package credentialstore

import (
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/zalando/go-keyring"
)

// Store defines the interface for credential storage
type Store interface {
	// SaveAccessToken saves the access token
	SaveAccessToken(userEmail string, token string) error

	// GetAccessToken retrieves the access token
	GetAccessToken(userEmail string) (string, error)

	// SaveRefreshToken saves the refresh token
	SaveRefreshToken(userEmail string, token string) error

	// GetRefreshToken retrieves the refresh token
	GetRefreshToken(userEmail string) (string, error)

	// SaveGPGPrivateKey saves the GPG private key
	SaveGPGPrivateKey(userEmail string, key string) error

	// GetGPGPrivateKey retrieves the GPG private key
	GetGPGPrivateKey(userEmail string) (string, error)

	// SaveGPGPublicKey saves the GPG public key
	SaveGPGPublicKey(userEmail string, key string) error

	// GetGPGPublicKey retrieves the GPG public key
	GetGPGPublicKey(userEmail string) (string, error)

	// SaveGPGThumbprint saves the GPG key thumbprint
	SaveGPGThumbprint(userEmail string, thumbprint string) error

	// GetGPGThumbprint retrieves the GPG key thumbprint
	GetGPGThumbprint(userEmail string) (string, error)

	// DeleteAllCredentials removes all credentials for a user
	DeleteAllCredentials(userEmail string) error

	// SaveActiveUser saves the currently active user email
	SaveActiveUser(userEmail string) error

	// GetActiveUser retrieves the currently active user email
	GetActiveUser() (string, error)

	// DeleteActiveUser clears the active user
	DeleteActiveUser() error

	// DiscoverUsers returns a list of all stored user emails
	DiscoverUsers() ([]string, error)

	// Backend returns the name of the storage backend being used
	Backend() string
}

// ErrCredentialNotFound is returned when a credential cannot be found
var ErrCredentialNotFound = fmt.Errorf("credential not found")

// credentialStoreEncodeEmail encodes an email for use as a viper key
func credentialStoreEncodeEmail(email string) string {
	// Replace @ and . with _ to avoid issues with viper's dot delimiter
	encoded := email
	encoded = stringReplace(encoded, "@", "_at_")
	encoded = stringReplace(encoded, ".", "_dot_")
	return encoded
}

// credentialStoreDecodeEmail decodes an email from a viper key
func credentialStoreDecodeEmail(encoded string) string {
	decoded := encoded
	decoded = stringReplace(decoded, "_at_", "@")
	decoded = stringReplace(decoded, "_dot_", ".")
	return decoded
}

// stringReplace is a helper function since we want to avoid importing strings package
func stringReplace(s, old, new string) string {
	result := ""
	i := 0
	for i < len(s) {
		if i+len(old) <= len(s) && s[i:i+len(old)] == old {
			result += new
			i += len(old)
		} else {
			result += string(s[i])
			i++
		}
	}
	return result
}

// NewStore creates a new credential store, attempting keyring first then falling back to file
func NewStore(configPath *string) (Store, error) {
	// Try keyring first - use a direct keyring test to avoid side effects like users_index updates
	testKey := "pigeonhole-test"
	testVal := "test-value"
	testService := "pigeonhole"

	// Try to directly set and get from keyring
	err := keyring.Set(testService, testKey, testVal)
	if err == nil {
		// Keyring works, clean up test value and use keyring store
		_ = keyring.Delete(testService, testKey)
		return NewKeyringStore(configPath), nil
	}

	// Keyring failed, fall back to file storage
	logrus.Debugf("Keyring not available, falling back to file storage: %v", err)
	return NewFileStore(configPath), nil
}
