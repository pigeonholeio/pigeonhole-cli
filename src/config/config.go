package config

import (
	"fmt"
	"os"

	"github.com/pigeonholeio/common/utils"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

type PigeonHoleConfig struct {
	API      *ApiConfig               `mapstructure:"api"`
	Identity map[string]*UserIdentity `mapstructure:"identity"`
}

type ApiConfig struct {
	Url         *string `mapstructure:"url"`
	AccessToken *string `mapstructure:"accessToken"`
}
type UserIdentity struct {
	// AccessToken *string  `ma	pstructure:"accessToken"`
	GPGKey *GPGPair `mapstructure:"gpgKey"`
}

type GPGPair struct {
	PublicKey  *string `mapstructure:"publicKey"`
	PrivateKey *string `mapstructure:"privateKey"`
	Thumbprint *string `mapstructure:"thumbprint"`
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

	pub, priv, thumbprint := utils.CreateGPGKeyPair(name, email)
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

	*c.PrivateKey = utils.EncodeToBase64(priv)
	*c.PublicKey = utils.EncodeToBase64(pub)
	*c.Thumbprint = thumbprint

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
	if *c.API.AccessToken != "" {
		claims, err := utils.DecodePigeonHoleJWT(*c.API.AccessToken)
		if err != nil {
			return "", fmt.Errorf("not logged in")
		}

		return claims[claimName].(string), nil
	}
	return "", fmt.Errorf("not logged in")
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
