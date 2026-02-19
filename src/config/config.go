package config

import (
	"fmt"
	"os"
	"time"

	"github.com/pigeonholeio/common/utils"
	"github.com/pigeonholeio/pigeonhole-cli/credentialstore"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

type PigeonHoleConfig struct {
	API      *ApiConfig               `mapstructure:"api"`
	Identity map[string]*UserIdentity `mapstructure:"identity"`
}

type ApiConfig struct {
	Url          *string `mapstructure:"url"`
	AccessToken  *string `mapstructure:"accessToken"`
	RefreshToken *string `mapstructure:"refreshToken"`
	TokenExpiry  *int64  `mapstructure:"tokenExpiry"`
}
type UserIdentity struct {
	// AccessToken *string  `ma	pstructure:"accessToken"`
	GPGKey *GPGPair `mapstructure:"gpgKey"`
}

type GPGPair struct {
	PublicKey   *string `mapstructure:"publicKey"`
	PrivateKey  *string `mapstructure:"privateKey"`
	Thumbprint  *string `mapstructure:"thumbprint"`
	Fingerprint *string `mapstructure:"fingerprint"`
}

func (c *GPGPair) KeyExists() bool {
	if c == nil {
		logrus.Debugf("GPGPair is nil")
		return false
	}

	if c.PublicKey == nil || c.PrivateKey == nil {
		logrus.Debugf("PublicKey or PrivateKey is nil")
		return false
	}

	if *c.PublicKey == "" || *c.PrivateKey == "" {
		logrus.Debugf("no key material found")
		return false
	}
	logrus.Debugf("key material found")
	return true
}

func (c *GPGPair) VerifyEmail(email string) (bool, error) {
	logrus.Debugf("Calling VerifyEmail")

	// check for nil receiver
	if c == nil {
		return false, fmt.Errorf("GPGPair is nil")
	}

	// check for nil PublicKeyBase64 pointer
	if c.PublicKey == nil || *c.PublicKey == "" {
		return false, nil
	}

	s, err := utils.DecodeFromBase64(*c.PublicKey)
	if err != nil {
		return false, err
	}
	if s == "" {
		return false, fmt.Errorf("no key material found")
	}

	testEmail, _ := utils.ExtractEmail(s)
	logrus.Debugf("Email on gpg pub key: %s\n", testEmail)
	logrus.Debugf("Email on access key: %s\n", email)

	return testEmail == email, nil
}

func (c *GPGPair) DecodedPrivateKey() (string, error) {
	s, _ := utils.DecodeFromBase64(*c.PrivateKey)
	return s, nil
}

func (c *GPGPair) DecodedPublicKey() (string, error) {
	s, _ := utils.DecodeFromBase64(*c.PrivateKey)
	return s, nil
}

func (c *GPGPair) EncodePrivateKey(armoredKey string) error {
	return nil
}

func (c *GPGPair) EncodePublicKey(armoredKey string) error {
	return nil
}

func (c *GPGPair) EnsureKeyPair(name, email *string) error {
	logrus.Debugf("Calling EnsureKeyPair with %s (%s)", *name, *email)
	if c == nil {
		*c = GPGPair{}
	}
	emailFound, err := c.VerifyEmail(*email)
	if err != nil {
		return err
	}
	logrus.Debugf("Ensuring Key Pair: %s/%s - Email on public key: %t\n", *name, *email, emailFound)
	if !emailFound {
		err = c.CreateKeyPair(*name, *email)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *GPGPair) CreateKeyPair(name, email string) error {
	if c == nil {
		return fmt.Errorf("GPGPair receiver is nil")
	}

	pub, priv, fingerprint := utils.CreateGPGKeyPair(name, email)
	logrus.Debugf("assigning keys to GPGKeyPair instance")

	// ensure the pointers are allocated
	if c.PrivateKey == nil {
		c.PrivateKey = new(string)
	}
	if c.PublicKey == nil {
		c.PublicKey = new(string)
	}
	if c.Thumbprint == nil {
		c.Thumbprint = new(string)
	}
	if c.Fingerprint == nil {
		c.Fingerprint = new(string)
	}

	*c.PrivateKey = utils.EncodeToBase64(priv)
	*c.PublicKey = utils.EncodeToBase64(pub)
	*c.Thumbprint = fingerprint
	*c.Fingerprint = fingerprint

	return nil
}

// func (c *GPGPair) CreateKeyPair(name, email string) error {
// 	pub, priv, _ := utils.CreateGPGKeyPair(name, email)
// 	logrus.Debugf("assigning keys to struct instance")
// 	*c.PrivateKeyBase64 = utils.EncodeToBase64(priv)
// 	*c.PublicKeyBase64 = utils.EncodeToBase64(pub)

// 	logrus.Debugf("returning nil")
// 	return nil
// }

func NewConfig(pigeonholeServerUrl, access_token *string) *PigeonHoleConfig {
	api := ApiConfig{
		Url: pigeonholeServerUrl,
	}
	return &PigeonHoleConfig{
		API: &api,
	}
}

func (c *PigeonHoleConfig) getClaimByName(claimName string) (string, error) {
	if c == nil || c.API == nil || c.API.AccessToken == nil || *c.API.AccessToken == "" {
		return "", fmt.Errorf("not logged in")
	}

	claims, err := utils.DecodePigeonHoleJWT(*c.API.AccessToken)
	if err != nil {
		return "", fmt.Errorf("not logged in")
	}

	// Safely get the claim value
	claimValue, exists := claims[claimName]
	if !exists {
		return "", fmt.Errorf("claim '%s' not found in token", claimName)
	}

	// Safely convert to string
	claimStr, ok := claimValue.(string)
	if !ok {
		return "", fmt.Errorf("claim '%s' is not a string", claimName)
	}

	return claimStr, nil
}
func (c *PigeonHoleConfig) Save(v *viper.Viper, fullConfigPath *string) error {
	// Ask viper what file it's using

	logrus.Debugf("Writing yaml configuration to: %s", *fullConfigPath)
	// Marshal struct into YAML
	data, err := yaml.Marshal(c)

	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Write file with safe perms
	if err := os.WriteFile(*fullConfigPath, data, 0o600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	logrus.Debugf("Config written to %s", *fullConfigPath)
	return nil
}

// MarshalYAML ensures email addresses with dots are quoted in the YAML output
// This prevents YAML interpreting dots as key separators (e.g. user.name@example.com)
func (c *PigeonHoleConfig) MarshalYAML() (interface{}, error) {
	// Build the root mapping with properly quoted identity keys
	root := &yaml.Node{
		Kind: yaml.MappingNode,
	}

	// Add api section
	if c.API != nil {
		apiKeyNode := &yaml.Node{Kind: yaml.ScalarNode, Value: "api"}
		apiNode := &yaml.Node{Kind: yaml.MappingNode}

		if c.API.Url != nil {
			apiNode.Content = append(apiNode.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: "url"})
			apiNode.Content = append(apiNode.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: *c.API.Url})
		}
		if c.API.AccessToken != nil {
			apiNode.Content = append(apiNode.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: "accessToken"})
			apiNode.Content = append(apiNode.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: *c.API.AccessToken})
		}
		if c.API.RefreshToken != nil {
			apiNode.Content = append(apiNode.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: "refreshToken"})
			apiNode.Content = append(apiNode.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: *c.API.RefreshToken})
		}
		if c.API.TokenExpiry != nil {
			apiNode.Content = append(apiNode.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: "tokenExpiry"})
			apiNode.Content = append(apiNode.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: fmt.Sprintf("%d", *c.API.TokenExpiry)})
		}

		root.Content = append(root.Content, apiKeyNode, apiNode)
	}

	// Add identity section with quoted email keys
	if c.Identity != nil && len(c.Identity) > 0 {
		identityKeyNode := &yaml.Node{Kind: yaml.ScalarNode, Value: "identity"}
		identityNode := &yaml.Node{Kind: yaml.MappingNode}

		for email, identity := range c.Identity {
			// Quote the email key to preserve dots
			emailKeyNode := &yaml.Node{
				Kind:  yaml.ScalarNode,
				Value: email,
				Style: yaml.DoubleQuotedStyle,
			}

			identityValueNode := &yaml.Node{Kind: yaml.MappingNode}

			if identity != nil && identity.GPGKey != nil {
				gpgKeyNode := &yaml.Node{Kind: yaml.MappingNode}

				if identity.GPGKey.PublicKey != nil {
					gpgKeyNode.Content = append(gpgKeyNode.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: "publicKey"})
					gpgKeyNode.Content = append(gpgKeyNode.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: *identity.GPGKey.PublicKey})
				}
				if identity.GPGKey.PrivateKey != nil {
					gpgKeyNode.Content = append(gpgKeyNode.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: "privateKey"})
					gpgKeyNode.Content = append(gpgKeyNode.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: *identity.GPGKey.PrivateKey})
				}
				if identity.GPGKey.Thumbprint != nil {
					gpgKeyNode.Content = append(gpgKeyNode.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: "thumbprint"})
					gpgKeyNode.Content = append(gpgKeyNode.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: *identity.GPGKey.Thumbprint})
				}
				if identity.GPGKey.Fingerprint != nil {
					gpgKeyNode.Content = append(gpgKeyNode.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: "fingerprint"})
					gpgKeyNode.Content = append(gpgKeyNode.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: *identity.GPGKey.Fingerprint})
				}

				identityValueNode.Content = append(identityValueNode.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: "gpgKey"})
				identityValueNode.Content = append(identityValueNode.Content, gpgKeyNode)
			}

			identityNode.Content = append(identityNode.Content, emailKeyNode, identityValueNode)
		}

		root.Content = append(root.Content, identityKeyNode, identityNode)
	}

	return root, nil
}

// func (c *PigeonHoleConfig) Save(v *viper.Viper) {
// 	if c == nil || v == nil {
// 		logrus.Fatalf("Cannot save nil config or nil viper instance")
// 	}

// 	if c.API != nil {
// 		v.Set("api", c.API)
// 	} else {
// 		v.Set("api", map[string]interface{}{})
// 	}

// 	if c.Identity != nil {
// 		v.Set("identity", c.Identity)
// 	} else {
// 		v.Set("identity", map[string]*UserIdentity{})
// 	}

// 	if err := v.SafeWriteConfig(); err != nil {
// 		if _, ok := err.(viper.ConfigFileAlreadyExistsError); ok {
// 			if err := v.WriteConfig(); err != nil {
// 				logrus.Fatalf("Unable to write config: %v", err)
// 			}
// 		} else {
// 			logrus.Fatalf("Unable to write config: %v", err)
// 		}
// 	}
// }

func (c *PigeonHoleConfig) GetUserId() (string, error) {
	return c.getClaimByName("sub")
}
func (c *PigeonHoleConfig) GetUserName() (string, error) {
	return c.getClaimByName("name")
}
func (c *PigeonHoleConfig) GetUserEmail() (string, error) {
	return c.getClaimByName("email")
}

// IsTokenExpired checks if the access token has expired
func (c *PigeonHoleConfig) IsTokenExpired() bool {
	if c == nil || c.API == nil || c.API.TokenExpiry == nil {
		return false
	}
	return time.Now().Unix() > *c.API.TokenExpiry
}

// IsTokenNearExpiry checks if token is near expiry (within 5 minutes)
func (c *PigeonHoleConfig) IsTokenNearExpiry() bool {
	if c == nil || c.API == nil || c.API.TokenExpiry == nil {
		return false
	}
	expiryTime := time.Unix(*c.API.TokenExpiry, 0)
	return time.Now().Add(5 * time.Minute).After(expiryTime)
}

// CanRefresh checks if refresh token is available
func (c *PigeonHoleConfig) CanRefresh() bool {
	if c == nil || c.API == nil || c.API.RefreshToken == nil {
		return false
	}
	return *c.API.RefreshToken != ""
}

// SaveTokensToStore saves access and refresh tokens to the credential store
func (c *PigeonHoleConfig) SaveTokensToStore(store credentialstore.Store, userEmail string) error {
	logrus.Debugf("Saving tokens to credential store for %s", userEmail)

	if c == nil || c.API == nil {
		return fmt.Errorf("config or API config is nil")
	}

	if c.API.AccessToken != nil && *c.API.AccessToken != "" {
		if err := store.SaveAccessToken(userEmail, *c.API.AccessToken); err != nil {
			logrus.Errorf("failed to save access token: %v", err)
			return err
		}
	}

	if c.API.RefreshToken != nil && *c.API.RefreshToken != "" {
		if err := store.SaveRefreshToken(userEmail, *c.API.RefreshToken); err != nil {
			logrus.Errorf("failed to save refresh token: %v", err)
			return err
		}
	}

	return nil
}

// LoadTokensFromStore loads access and refresh tokens from the credential store
func (c *PigeonHoleConfig) LoadTokensFromStore(store credentialstore.Store, userEmail string) error {
	logrus.Debugf("Loading tokens from credential store for %s", userEmail)

	if c == nil || c.API == nil {
		return fmt.Errorf("config or API config is nil")
	}

	accessToken, err := store.GetAccessToken(userEmail)
	if err == nil && accessToken != "" {
		c.API.AccessToken = &accessToken
	} else if err != nil {
		logrus.Debugf("no access token in credential store: %v", err)
	}

	refreshToken, err := store.GetRefreshToken(userEmail)
	if err == nil && refreshToken != "" {
		c.API.RefreshToken = &refreshToken
	} else if err != nil {
		logrus.Debugf("no refresh token in credential store: %v", err)
	}

	return nil
}

// SaveGPGKeysToStore saves GPG keys to the credential store
func (c *PigeonHoleConfig) SaveGPGKeysToStore(store credentialstore.Store, userEmail string, identity *UserIdentity) error {
	logrus.Debugf("Saving GPG keys to credential store for %s", userEmail)

	if identity == nil || identity.GPGKey == nil {
		return fmt.Errorf("user identity or GPG key is nil")
	}

	gpgKey := identity.GPGKey
	if gpgKey.PrivateKey != nil && *gpgKey.PrivateKey != "" {
		if err := store.SaveGPGPrivateKey(userEmail, *gpgKey.PrivateKey); err != nil {
			logrus.Errorf("failed to save GPG private key: %v", err)
			return err
		}
	}

	if gpgKey.PublicKey != nil && *gpgKey.PublicKey != "" {
		if err := store.SaveGPGPublicKey(userEmail, *gpgKey.PublicKey); err != nil {
			logrus.Errorf("failed to save GPG public key: %v", err)
			return err
		}
	}

	if gpgKey.Thumbprint != nil && *gpgKey.Thumbprint != "" {
		if err := store.SaveGPGThumbprint(userEmail, *gpgKey.Thumbprint); err != nil {
			logrus.Errorf("failed to save GPG thumbprint: %v", err)
			return err
		}
	}

	return nil
}

// LoadGPGKeysFromStore loads GPG keys from the credential store
func (c *PigeonHoleConfig) LoadGPGKeysFromStore(store credentialstore.Store, userEmail string) (*UserIdentity, error) {
	logrus.Debugf("Loading GPG keys from credential store for %s", userEmail)

	identity := &UserIdentity{
		GPGKey: &GPGPair{},
	}

	privateKey, err := store.GetGPGPrivateKey(userEmail)
	if err == nil && privateKey != "" {
		identity.GPGKey.PrivateKey = &privateKey
	} else if err != nil {
		logrus.Debugf("no GPG private key in credential store: %v", err)
	}

	publicKey, err := store.GetGPGPublicKey(userEmail)
	if err == nil && publicKey != "" {
		identity.GPGKey.PublicKey = &publicKey
	} else if err != nil {
		logrus.Debugf("no GPG public key in credential store: %v", err)
	}

	thumbprint, err := store.GetGPGThumbprint(userEmail)
	if err == nil && thumbprint != "" {
		identity.GPGKey.Thumbprint = &thumbprint
		identity.GPGKey.Fingerprint = &thumbprint
	} else if err != nil {
		logrus.Debugf("no GPG thumbprint in credential store: %v", err)
	}

	return identity, nil
}
