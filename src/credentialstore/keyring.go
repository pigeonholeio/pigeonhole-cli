package credentialstore

import (
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/zalando/go-keyring"
	"gopkg.in/yaml.v3"
)

const serviceName = "pigeonhole"

// KeyringStore implements Store interface using zalando/go-keyring
type KeyringStore struct {
	configPath *string
	viper      *viper.Viper
}

// NewKeyringStore creates a new keyring-based credential store
func NewKeyringStore(configPath *string) *KeyringStore {
	return &KeyringStore{
		configPath: configPath,
		viper:      viper.New(),
	}
}

// SaveAccessToken saves the access token to keyring
func (ks *KeyringStore) SaveAccessToken(userEmail string, token string) error {
	logrus.Debugf("Saving access token for %s to keyring", userEmail)
	if err := keyring.Set(serviceName, fmt.Sprintf("token:%s", userEmail), token); err != nil {
		return err
	}
	// Also add to users index
	return ks.addUserToIndex(userEmail)
}

// GetAccessToken retrieves the access token from keyring
func (ks *KeyringStore) GetAccessToken(userEmail string) (string, error) {
	logrus.Debugf("Retrieving access token for %s from keyring", userEmail)
	return keyring.Get(serviceName, fmt.Sprintf("token:%s", userEmail))
}

// SaveRefreshToken saves the refresh token to keyring
func (ks *KeyringStore) SaveRefreshToken(userEmail string, token string) error {
	logrus.Debugf("Saving refresh token for %s to keyring", userEmail)
	return keyring.Set(serviceName, fmt.Sprintf("refresh-token:%s", userEmail), token)
}

// GetRefreshToken retrieves the refresh token from keyring
func (ks *KeyringStore) GetRefreshToken(userEmail string) (string, error) {
	logrus.Debugf("Retrieving refresh token for %s from keyring", userEmail)
	return keyring.Get(serviceName, fmt.Sprintf("refresh-token:%s", userEmail))
}

// SaveGPGPrivateKey saves the GPG private key to keyring
func (ks *KeyringStore) SaveGPGPrivateKey(userEmail string, key string) error {
	logrus.Debugf("Saving GPG private key for %s to keyring", userEmail)
	return keyring.Set(serviceName, fmt.Sprintf("gpg-private:%s", userEmail), key)
}

// GetGPGPrivateKey retrieves the GPG private key from keyring
func (ks *KeyringStore) GetGPGPrivateKey(userEmail string) (string, error) {
	logrus.Debugf("Retrieving GPG private key for %s from keyring", userEmail)
	return keyring.Get(serviceName, fmt.Sprintf("gpg-private:%s", userEmail))
}

// SaveGPGPublicKey saves the GPG public key to keyring
func (ks *KeyringStore) SaveGPGPublicKey(userEmail string, key string) error {
	logrus.Debugf("Saving GPG public key for %s to keyring", userEmail)
	return keyring.Set(serviceName, fmt.Sprintf("gpg-public:%s", userEmail), key)
}

// GetGPGPublicKey retrieves the GPG public key from keyring
func (ks *KeyringStore) GetGPGPublicKey(userEmail string) (string, error) {
	logrus.Debugf("Retrieving GPG public key for %s from keyring", userEmail)
	return keyring.Get(serviceName, fmt.Sprintf("gpg-public:%s", userEmail))
}

// SaveGPGThumbprint saves the GPG key thumbprint to keyring
func (ks *KeyringStore) SaveGPGThumbprint(userEmail string, thumbprint string) error {
	logrus.Debugf("Saving GPG thumbprint for %s to keyring", userEmail)
	return keyring.Set(serviceName, fmt.Sprintf("gpg-thumbprint:%s", userEmail), thumbprint)
}

// GetGPGThumbprint retrieves the GPG key thumbprint from keyring
func (ks *KeyringStore) GetGPGThumbprint(userEmail string) (string, error) {
	logrus.Debugf("Retrieving GPG thumbprint for %s from keyring", userEmail)
	return keyring.Get(serviceName, fmt.Sprintf("gpg-thumbprint:%s", userEmail))
}

// DeleteAllCredentials removes all credentials for a user from keyring
func (ks *KeyringStore) DeleteAllCredentials(userEmail string) error {
	keys := []string{
		fmt.Sprintf("token:%s", userEmail),
		fmt.Sprintf("refresh-token:%s", userEmail),
		fmt.Sprintf("gpg-private:%s", userEmail),
		fmt.Sprintf("gpg-public:%s", userEmail),
		fmt.Sprintf("gpg-thumbprint:%s", userEmail),
	}

	logrus.Debugf("Deleting all credentials for %s from keyring", userEmail)
	var lastErr error
	for _, key := range keys {
		err := keyring.Delete(serviceName, key)
		if err != nil {
			logrus.Debugf("Error deleting key %s: %v", key, err)
			lastErr = err
		} else {
			logrus.Debugf("Successfully deleted key %s", key)
		}
	}

	// If at least one deletion failed, return the last error
	// But this is not fatal - keys might not exist
	if lastErr != nil {
		logrus.Debugf("Some credentials may not have been deleted for %s (this is normal if they didn't exist)", userEmail)
	}

	// Also remove from users index
	_ = ks.removeUserFromIndex(userEmail)

	return nil
}

// removeUserFromIndex removes a user from the users index file
func (ks *KeyringStore) removeUserFromIndex(userEmail string) error {
	if ks.configPath == nil || *ks.configPath == "" {
		return nil // Skip if no config path
	}

	if err := ks.readConfig(); err != nil {
		logrus.Debugf("Could not read config for user index removal: %v", err)
		return err
	}

	// Get existing users
	usersIndex := ks.viper.GetStringSlice("users_index")

	// Remove the user
	newIndex := []string{}
	for _, u := range usersIndex {
		if u != userEmail {
			newIndex = append(newIndex, u)
		}
	}

	ks.viper.Set("users_index", newIndex)
	return ks.writeConfig()
}

// SaveActiveUser saves the currently active user email to config file
func (ks *KeyringStore) SaveActiveUser(userEmail string) error {
	logrus.Debugf("Saving active user to config file: %s", userEmail)
	if err := ks.readConfig(); err != nil {
		logrus.Debugf("Could not read config before saving active user: %v", err)
	}
	ks.viper.Set("active_user", userEmail)
	return ks.writeConfig()
}

// GetActiveUser retrieves the currently active user email from config file
func (ks *KeyringStore) GetActiveUser() (string, error) {
	logrus.Debugf("Retrieving active user from config file")
	if err := ks.readConfig(); err != nil {
		logrus.Debugf("Could not read config: %v", err)
	}
	activeUser := ks.viper.GetString("active_user")
	if activeUser == "" {
		return "", fmt.Errorf("no active user set")
	}
	return activeUser, nil
}

// DeleteActiveUser clears the active user from config file
func (ks *KeyringStore) DeleteActiveUser() error {
	logrus.Debugf("Deleting active user from config file")
	if err := ks.readConfig(); err != nil {
		logrus.Debugf("Could not read config: %v", err)
	}
	ks.viper.Set("active_user", "")
	return ks.writeConfig()
}

// DiscoverUsers returns a list of all stored user emails
func (ks *KeyringStore) DiscoverUsers() ([]string, error) {
	logrus.Debugf("Discovering users from keyring")
	users := []string{}

	if ks.configPath == nil || *ks.configPath == "" {
		logrus.Debugf("Config path not set, returning empty users list")
		return users, nil
	}

	logrus.Debugf("Config path: %s", *ks.configPath)

	// Read the config file
	if err := ks.readConfig(); err != nil {
		logrus.Debugf("Could not read config for users discovery: %v", err)
		return users, nil
	}

	// Try to get users from the index first
	usersIndex := ks.viper.GetStringSlice("users_index")
	if len(usersIndex) > 0 {
		logrus.Debugf("Found %d users in users index", len(usersIndex))
		return usersIndex, nil
	}

	logrus.Debugf("Users index is empty, discovering from credentials in config file")

	// Fallback: discover users by scanning credentials in config file
	// This handles the case where the users index hasn't been populated yet
	userSet := make(map[string]bool)
	allSettings := ks.viper.AllSettings()

	// Parse credentials - same logic as FileStore
	if credentialsRaw, ok := allSettings["credentials"]; ok {
		if credMap, ok := credentialsRaw.(map[string]interface{}); ok {
			for encodedEmail := range credMap {
				// Decode the email
				email := credentialStoreDecodeEmail(encodedEmail)
				userSet[email] = true
				logrus.Debugf("Found user in credentials: %s", email)
			}
		}
	}

	// Parse identity
	if identityRaw, ok := allSettings["identity"]; ok {
		if identityMap, ok := identityRaw.(map[string]interface{}); ok {
			for email := range identityMap {
				userSet[email] = true
				logrus.Debugf("Found user in identity: %s", email)
			}
		}
	}

	// Convert to slice
	for user := range userSet {
		users = append(users, user)
	}

	if len(users) > 0 {
		logrus.Debugf("Discovered %d users from credentials", len(users))
		// Update the users index for next time
		ks.viper.Set("users_index", users)
		_ = ks.writeConfig() // Ignore errors on index update
	}

	return users, nil
}

// addUserToIndex adds a user to the users index file
func (ks *KeyringStore) addUserToIndex(userEmail string) error {
	if ks.configPath == nil || *ks.configPath == "" {
		return nil // Skip if no config path
	}

	if err := ks.readConfig(); err != nil {
		logrus.Debugf("Could not read config for user index: %v", err)
		// Continue anyway - if file doesn't exist, we'll create it
	}

	// Get existing users
	usersIndex := ks.viper.GetStringSlice("users_index")

	// Check if user already exists
	for _, u := range usersIndex {
		if u == userEmail {
			return nil // Already in index
		}
	}

	// Add to index
	usersIndex = append(usersIndex, userEmail)
	ks.viper.Set("users_index", usersIndex)

	return ks.writeConfig()
}

// readConfig reads the config file into viper
func (ks *KeyringStore) readConfig() error {
	if ks.configPath == nil || *ks.configPath == "" {
		return fmt.Errorf("config path not set")
	}

	ks.viper.SetConfigFile(*ks.configPath)
	ks.viper.SetConfigType("yaml")

	if err := ks.viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			logrus.Debugf("Error reading config: %v", err)
		}
	}
	return nil
}

// writeConfig writes the viper config to file
func (ks *KeyringStore) writeConfig() error {
	if ks.configPath == nil || *ks.configPath == "" {
		return fmt.Errorf("config path not set")
	}

	// Ensure viper has the config file path set
	ks.viper.SetConfigFile(*ks.configPath)
	ks.viper.SetConfigType("yaml")

	// Ensure directory exists
	dir := ""
	for i := len(*ks.configPath) - 1; i >= 0; i-- {
		if (*ks.configPath)[i] == '/' {
			dir = (*ks.configPath)[:i]
			break
		}
	}
	if dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}

	// Use the same approach as FileStore: directly marshal and write
	data := ks.viper.AllSettings()

	// Convert to YAML and write
	yamlData, err := yaml.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal config to YAML: %w", err)
	}

	if err := os.WriteFile(*ks.configPath, yamlData, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// Backend returns the name of the storage backend
func (ks *KeyringStore) Backend() string {
	return "keyring"
}
