package config

import (
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
	viper.SetDefault("api.url", "http://localhost:3000")
	viper.SetDefault("output.format", "yaml")
	viper.SetDefault("log.pretty", true)
	viper.SetDefault("log.level", "info")
	viper.SetDefault("oidc.client_id", "a45fa66e-3c5c-4b12-a5ff-8e4b0484cd77")
	viper.SetDefault("oidc.devicecode_endpoint", "https://login.microsoftonline.com/organizations/oauth2/v2.0/devicecode")
	viper.SetDefault("oidc.token_endpoint", "https://login.microsoftonline.com/organizations/oauth2/v2.0/token")
	viper.SetDefault("oidc.scopes", "openid email profile https://pigeono.io/default")
}

var CfgFile string
var Config config

func InitConfig() {
	loadDefaults()
	setLogger()

	if CfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(CfgFile)
	} else {
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		// Search config in home directory with name ".cli" (without extension).
		viper.AddConfigPath(home)
		// viper.AddConfigPath(".")
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")

		if err := viper.Unmarshal(&Config); err != nil {
			logrus.Errorf("Unable to decode config file, %v", err)
			// log.Fatalf()
		}
	}
	if err := viper.ReadInConfig(); err == nil {
		// fmt.Println(viper.ConfigFileUsed())
		logrus.Debug("Using config file: %s", viper.ConfigFileUsed())
	}

	viper.AutomaticEnv() // read in environment variables that match
	// viper.WriteConfig()
	// If a config file is found, read it in.
	//
	// viper.WriteConfig()

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
