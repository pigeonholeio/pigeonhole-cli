package config

import (
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type config struct {
	API           apiConfig           `mapstructure:"api"`
	OpenIdConnect openIdConnectConfig `mapstructure:"oidc"`
	Auth          authConfig          `mapstructure:"auth"`
}

type authConfig struct {
	AccessToken string `mapstructure:"token"`
}

type apiConfig struct {
	Url string `mapstructure:"url"`
}

type openIdConnectConfig struct {
	ClientId           string `mapstructure:"client_id"`
	TokenEndpoint      string `mapstructure:"token_endpoint"`
	DeviceCodeEndpoint string `mapstructure:"devicecode_endpoint"`
	Scopes             string `mapstructure:"scopes"`
}

func loadDefaults() {
	viper.SetDefault("api.url", "https://api.pigeono.io")
	viper.SetDefault("oidc.client_id", "a45fa66e-3c5c-4b12-a5ff-8e4b0484cd77")
	viper.SetDefault("oidc.devicecode_endpoint", "https://login.microsoftonline.com/organizations/oauth2/v2.0/devicecode")
	viper.SetDefault("oidc.token_endpoint", "https://login.microsoftonline.com/organizations/oauth2/v2.0/token")
	viper.SetDefault("oidc.scopes", "openid email profile https://pigeono.io/default")
}

var CfgFile string
var Config config
var ConfigPath string

func InitConfig() {
	InitConfigWrite(false)
}

func InitConfigWrite(writeConfig bool) {
	loadDefaults()

	if CfgFile != "" {
		viper.SetConfigFile(CfgFile)
	} else {
		home, err := os.UserHomeDir()
		ConfigPath = fmt.Sprintf("%s/.pigeonhole", home)
		if _, err := os.Stat(ConfigPath); os.IsNotExist(err) {
			os.MkdirAll(ConfigPath, 0700) // Creates the directory with the necessary permissions
		}
		cobra.CheckErr(err)
		viper.AddConfigPath(ConfigPath)
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")

		if err := viper.Unmarshal(&Config); err != nil {
			logrus.Errorf("Unable to decode config file, %v", err)
		}
	}
	if err := viper.ReadInConfig(); err == nil {
		logrus.Debug("Using config file: %s", viper.ConfigFileUsed())
	}
	viper.AutomaticEnv()

}
