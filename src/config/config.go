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
	Log           logConfig           `mapstructure:"log"`
	OpenIdConnect openIdConnectConfig `mapstructure:"oidc"`
	Auth          authConfig          `mapstructure:"auth"`
}

type authConfig struct {
	AccessToken string `mapstructure:"token"`
}

type apiConfig struct {
	Url string `mapstructure:"url"`
}

type logConfig struct {
	Level  string `mapstructure:"level"`
	Pretty bool   `mapstructure:"pretty"`
}

type openIdConnectConfig struct {
	ClientId           string `mapstructure:"client_id"`
	TokenEndpoint      string `mapstructure:"token_endpoint"`
	DeviceCodeEndpoint string `mapstructure:"devicecode_endpoint"`
	Scopes             string `mapstructure:"scopes"`
}

func loadDefaults() {
	viper.SetDefault("api.url", "https://api.pigeono.io")
	viper.SetDefault("output.format", "yaml")
	viper.SetDefault("log.pretty", true)
	viper.SetDefault("log.level", "info")
	viper.SetDefault("oidc.client_id", "a45fa66e-3c5c-4b12-a5ff-8e4b0484cd77")
	viper.SetDefault("oidc.devicecode_endpoint", "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode")
	viper.SetDefault("oidc.token_endpoint", "https://login.microsoftonline.com/common/oauth2/v2.0/token")
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
	setLogger()

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
		logrus.Debugf("Using config file: %s", viper.ConfigFileUsed())
	}
	viper.AutomaticEnv()

}

func setLogger() {
	logrus.SetFormatter(&logrus.TextFormatter{
		TimestampFormat: "2006-01-02T15:04:05Z07:00", // ISO8601 Format
	})
	logrus.SetReportCaller(false)

	switch viper.GetString("log.level") {
	case "debug":
		logrus.SetLevel(logrus.DebugLevel)
	case "info":
		logrus.SetLevel(logrus.InfoLevel)
	case "warn":
		logrus.SetLevel(logrus.WarnLevel)
	case "error":
		logrus.SetLevel(logrus.ErrorLevel)
	default:
		logrus.SetLevel(logrus.InfoLevel)
	}
	// strconv.FormatBool(v)
	// fmt.Println(strconv.FormatBool(viper.GetViper().GetBool("verbose")))
	if viper.GetBool("verbose") {
		// fmt.Println("Setting debug on")
		logrus.SetLevel(logrus.DebugLevel)
	}
}
