package config

import (
	"github.com/pigeonholeio/pigeonhole-cli/utils"
	"golang.org/x/oauth2"
)

type PigeonHoleConfig struct {
	API           ApiConfig     `mapstructure:"api"`
	OpenIdConnect oauth2.Config `mapstructure:"oidc"`
	GpgKey        GPGPair       `mapstructure:"gpg"`
}

type GPGPair struct {
	PublicKeyBase64  string `mapstructure:"publicKey"`
	PrivateKeyBase64 string `mapstructure:"privateKey"`
}

func (c *GPGPair) DecodedPrivateKey() (string, error) {
	s, _ := utils.DecodeFromBase64(c.PrivateKeyBase64)
	return s, nil
}
func (c *GPGPair) DecodedPublicKey() (string, error) {
	s, _ := utils.DecodeFromBase64(c.PublicKeyBase64)
	return s, nil
}
func (c *GPGPair) EncodePrivateKey(armoredKey string) error {
	return nil
}
func (c *GPGPair) EncodePublicKey(armoredKey string) error {
	return nil
}
func (c *GPGPair) CreateKeyPair(name, email string) error {
	// utils.CreateGPGKey(name, email)
	// utils.crete
	return nil
}

func NewConfig(pigeonholeServerUrl, access_token string, oauthCfg *oauth2.Config) *PigeonHoleConfig {
	apiCfg := ApiConfig{
		Url:         pigeonholeServerUrl,
		AccessToken: access_token,
	}
	cfg := PigeonHoleConfig{
		API:           apiCfg,
		OpenIdConnect: *oauthCfg,
	}
	return &cfg
}

type ApiConfig struct {
	Url         string `mapstructure:"url"`
	AccessToken string `mapstructure:"access_token"`
}

// func loadDefaults() {
// 	viper.SetDefault("api.url", "https://api.pigeono.io")
// 	viper.SetDefault("output.format", "yaml")
// 	viper.SetDefault("log.pretty", true)
// 	viper.SetDefault("log.level", "info")
// 	viper.SetDefault("oidc.client_id", "a45fa66e-3c5c-4b12-a5ff-8e4b0484cd77")
// 	viper.SetDefault("oidc.devicecode_endpoint", "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode")
// 	viper.SetDefault("oidc.token_endpoint", "https://login.microsoftonline.com/common/oauth2/v2.0/token")
// 	viper.SetDefault("oidc.scopes", "openid email profile https://pigeono.io/default")
// }

// func InitConfigWrite(writeConfig bool) {
// 	// loadDefaults()
// 	setLogger()

// 	if CfgFile != "" {
// 		viper.SetConfigFile(CfgFile)
// 	} else {
// 		home, err := os.UserHomeDir()
// 		ConfigPath = fmt.Sprintf("%s/.pigeonhole", home)
// 		if _, err := os.Stat(ConfigPath); os.IsNotExist(err) {
// 			os.MkdirAll(ConfigPath, 0700) // Creates the directory with the necessary permissions
// 		}
// 		cobra.CheckErr(err)
// 		viper.AddConfigPath(ConfigPath)
// 		viper.SetConfigName("config")
// 		viper.SetConfigType("yaml")

// 		if err := viper.Unmarshal(&Config); err != nil {
// 			logrus.Errorf("Unable to decode config file, %v", err)
// 		}
// 	}
// 	if err := viper.ReadInConfig(); err == nil {
// 		logrus.Debugf("Using config file: %s", viper.ConfigFileUsed())
// 	}
// 	viper.AutomaticEnv()

// }
