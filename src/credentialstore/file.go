package credentialstore

import (
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

// FileStore implements Store interface using YAML file storage (fallback)
type FileStore struct {
	configPath *string
	viper      *viper.Viper
}

// NewFileStore creates a new file-based credential store
func NewFileStore(configPath *string) *FileStore {
	return &FileStore{
		configPath: configPath,
		viper:      viper.New(),
	}
}

// getCredentialsKey builds the key path for a credential in the viper structure
// Uses encoded email to avoid issues with dots in email addresses being treated as key separators
func (fs *FileStore) getCredentialsKey(credType, userEmail string) string {
	// Encode email by replacing @ and . with _ to avoid viper's dot-delimiter issues
	encodedEmail := credentialStoreEncodeEmail(userEmail)
	return fmt.Sprintf("credentials.%s.%s", encodedEmail, credType)
}

// SaveAccessToken saves the access token to YAML file
func (fs *FileStore) SaveAccessToken(userEmail string, token string) error {
	key := fs.getCredentialsKey("access_token", userEmail)
	logrus.Debugf("Saving access token for %s to file store", userEmail)
	fs.viper.Set(key, token)
	return fs.writeConfig()
}

// GetAccessToken retrieves the access token from YAML file
func (fs *FileStore) GetAccessToken(userEmail string) (string, error) {
	key := fs.getCredentialsKey("access_token", userEmail)
	fs.readConfig()
	val := fs.viper.GetString(key)
	if val == "" {
		return "", ErrCredentialNotFound
	}
	return val, nil
}

// SaveRefreshToken saves the refresh token to YAML file
func (fs *FileStore) SaveRefreshToken(userEmail string, token string) error {
	key := fs.getCredentialsKey("refresh_token", userEmail)
	logrus.Debugf("Saving refresh token for %s to file store", userEmail)
	fs.viper.Set(key, token)
	return fs.writeConfig()
}

// GetRefreshToken retrieves the refresh token from YAML file
func (fs *FileStore) GetRefreshToken(userEmail string) (string, error) {
	key := fs.getCredentialsKey("refresh_token", userEmail)
	fs.readConfig()
	val := fs.viper.GetString(key)
	if val == "" {
		return "", ErrCredentialNotFound
	}
	return val, nil
}

// SaveGPGPrivateKey saves the GPG private key to YAML file
func (fs *FileStore) SaveGPGPrivateKey(userEmail string, key string) error {
	keyPath := fs.getCredentialsKey("gpg_private_key", userEmail)
	logrus.Debugf("Saving GPG private key for %s to file store", userEmail)
	fs.viper.Set(keyPath, key)
	return fs.writeConfig()
}

// GetGPGPrivateKey retrieves the GPG private key from YAML file
func (fs *FileStore) GetGPGPrivateKey(userEmail string) (string, error) {
	keyPath := fs.getCredentialsKey("gpg_private_key", userEmail)
	fs.readConfig()
	val := fs.viper.GetString(keyPath)
	if val == "" {
		return "", ErrCredentialNotFound
	}
	return val, nil
}

// SaveGPGPublicKey saves the GPG public key to YAML file
func (fs *FileStore) SaveGPGPublicKey(userEmail string, key string) error {
	keyPath := fs.getCredentialsKey("gpg_public_key", userEmail)
	logrus.Debugf("Saving GPG public key for %s to file store", userEmail)
	fs.viper.Set(keyPath, key)
	return fs.writeConfig()
}

// GetGPGPublicKey retrieves the GPG public key from YAML file
func (fs *FileStore) GetGPGPublicKey(userEmail string) (string, error) {
	keyPath := fs.getCredentialsKey("gpg_public_key", userEmail)
	fs.readConfig()
	val := fs.viper.GetString(keyPath)
	if val == "" {
		return "", ErrCredentialNotFound
	}
	return val, nil
}

// SaveGPGThumbprint saves the GPG key thumbprint to YAML file
func (fs *FileStore) SaveGPGThumbprint(userEmail string, thumbprint string) error {
	keyPath := fs.getCredentialsKey("gpg_thumbprint", userEmail)
	logrus.Debugf("Saving GPG thumbprint for %s to file store", userEmail)
	fs.viper.Set(keyPath, thumbprint)
	return fs.writeConfig()
}

// GetGPGThumbprint retrieves the GPG key thumbprint from YAML file
func (fs *FileStore) GetGPGThumbprint(userEmail string) (string, error) {
	keyPath := fs.getCredentialsKey("gpg_thumbprint", userEmail)
	fs.readConfig()
	val := fs.viper.GetString(keyPath)
	if val == "" {
		return "", ErrCredentialNotFound
	}
	return val, nil
}

// DeleteAllCredentials removes all credentials for a user from YAML file
func (fs *FileStore) DeleteAllCredentials(userEmail string) error {
	logrus.Debugf("Deleting all credentials for %s from file store", userEmail)

	// Read current config first to ensure we have the latest state
	if err := fs.readConfig(); err != nil {
		logrus.Debugf("Error reading config for deletion: %v", err)
		// Continue anyway - if file doesn't exist, setting to nil will still work
	}

	// Delete all credential keys for this user
	credRoot := fmt.Sprintf("credentials.%s", userEmail)
	fs.viper.Set(credRoot, nil)

	return fs.writeConfig()
}

// SaveActiveUser saves the currently active user email
func (fs *FileStore) SaveActiveUser(userEmail string) error {
	logrus.Debugf("Saving active user to file store: %s", userEmail)
	// Read config first to ensure viper is properly initialized
	if err := fs.readConfig(); err != nil {
		logrus.Debugf("Could not read config before saving active user: %v", err)
		// Continue anyway - if file doesn't exist, we'll create it
	}
	fs.viper.Set("active_user", userEmail)
	return fs.writeConfig()
}

// GetActiveUser retrieves the currently active user email
func (fs *FileStore) GetActiveUser() (string, error) {
	fs.readConfig()
	val := fs.viper.GetString("active_user")
	if val == "" {
		return "", ErrCredentialNotFound
	}
	return val, nil
}

// DeleteActiveUser clears the active user from file
func (fs *FileStore) DeleteActiveUser() error {
	logrus.Debugf("Deleting active user from file store")
	if err := fs.readConfig(); err != nil {
		logrus.Debugf("Could not read config before deleting active user: %v", err)
		// Continue anyway
	}
	fs.viper.Set("active_user", "")
	return fs.writeConfig()
}

// DiscoverUsers returns a list of all stored user emails
func (fs *FileStore) DiscoverUsers() ([]string, error) {
	fs.readConfig()
	userSet := make(map[string]bool)

	// AllSettings returns all settings as a flat map with dot-separated keys
	// We need to parse this to extract unique emails
	allSettings := fs.viper.AllSettings()

	// Parse credentials
	if credentialsRaw, ok := allSettings["credentials"]; ok {
		if credMap, ok := credentialsRaw.(map[string]interface{}); ok {
			for encodedEmail := range credMap {
				// Decode the email
				email := credentialStoreDecodeEmail(encodedEmail)
				userSet[email] = true
			}
		}
	}

	// Parse identity
	if identityRaw, ok := allSettings["identity"]; ok {
		if identityMap, ok := identityRaw.(map[string]interface{}); ok {
			for email := range identityMap {
				userSet[email] = true
			}
		}
	}

	// Convert to slice
	users := []string{}
	for user := range userSet {
		users = append(users, user)
	}
	return users, nil
}

// Backend returns the name of the storage backend
func (fs *FileStore) Backend() string {
	return "file"
}

// readConfig reads the config file into viper
func (fs *FileStore) readConfig() error {
	if fs.configPath == nil || *fs.configPath == "" {
		return fmt.Errorf("config path not set")
	}

	fs.viper.SetConfigFile(*fs.configPath)
	fs.viper.SetConfigType("yaml")

	if err := fs.viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			logrus.Debugf("Error reading config: %v", err)
		}
	}
	return nil
}

// writeConfig writes the viper config to file
func (fs *FileStore) writeConfig() error {
	if fs.configPath == nil || *fs.configPath == "" {
		return fmt.Errorf("config path not set")
	}

	// Ensure viper has the config file path set
	fs.viper.SetConfigFile(*fs.configPath)
	fs.viper.SetConfigType("yaml")

	// Ensure directory exists
	dir := ""
	for i := len(*fs.configPath) - 1; i >= 0; i-- {
		if (*fs.configPath)[i] == '/' {
			dir = (*fs.configPath)[:i]
			break
		}
	}
	if dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}

	// Try to write the config file
	// Use a workaround for viper WriteConfig limitation - directly marshal and write
	data := fs.viper.AllSettings()

	// Convert to YAML and write
	yamlData, err := yaml.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal config to YAML: %w", err)
	}

	if err := os.WriteFile(*fs.configPath, yamlData, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}
