package cmd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/pigeonholeio/common/utils"
	"github.com/pigeonholeio/pigeonhole-cli/config"
	"github.com/pigeonholeio/pigeonhole-cli/sdk"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/Masterminds/semver/v3"
)

var (
	timeoutSec       int
	PigeonHoleClient sdk.ClientWithResponses
	GlobalCtx        context.Context
	PigeonHoleConfig config.PigeonHoleConfig
	ContextCancel    context.CancelFunc
)

var rootCmd = &cobra.Command{
	Use:           "pigeonhole",
	Short:         "Sending secrets securely.",
	SilenceErrors: true,
	Long:          `This command will display the size of a directory with several different options.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// InitConfig()

		SetLogger()
		GlobalCtx, ContextCancel = context.WithTimeout(context.Background(), 60*time.Second)
		PigeonHoleClient = *sdk.PigeonholeClient(&PigeonHoleConfig, Version)
		if cmd.Annotations["skip-pre-run"] == "true" {
			logrus.Debugln("skipping-pre-run for: ", cmd.CommandPath())
			return
		}

		// resp, errx := PigeonHoleClient.GetUserMeWithResponse(GlobalCtx)
		resp, errx := PigeonHoleClient.GetPingWithResponse(GlobalCtx)

		if errx != nil {
			logrus.Debug(errx)
			if errors.Is(errx, context.DeadlineExceeded) {
				fmt.Printf("❌ HTTP request timed out after %d seconds\n", timeoutSec)
				os.Exit(0)

			} else {
				fmt.Println("☠️ Can't reach the PigeonHole servers")
				os.Exit(0)

			}
		}

		if resp.StatusCode() == http.StatusOK {
			if !sameMajorMinor(*resp.JSON200.Version, Version) {
				fmt.Printf("❌ Client version does not match server version, please update to the same major + minor version.\nClient Version: v%s\nServer Version: v%s\n", Version, *resp.JSON200.Version)
				os.Exit(0)

			}
		} else if resp.StatusCode() == http.StatusForbidden {
			logrus.Debugf("Message received from server: %s", *resp.JSON403.Message)
			fmt.Println("🛡️ Invalid Token (Forbidden) - Try signing back in using `pigeonhole auth --help`")
			os.Exit(0)
		} else if resp.StatusCode() == http.StatusBadRequest {
			logrus.Debugf("Message received from server: %s", *resp.JSON400.Message)
			fmt.Println("🛡️ Invalid Token (Bad Request) - Try signing back in using `pigeonhole auth --help`")
			os.Exit(0)
		} else if resp.StatusCode() == http.StatusUnauthorized {
			logrus.Debugf("Message received from server: %s", *resp.JSON401.Message)
			fmt.Println("🛡️ Invalid Token (Unauthorized) - Try signing back in using `pigeonhole auth --help`")
			os.Exit(0)
		} else if resp.StatusCode() == http.StatusInternalServerError {
			logrus.Debugf("Message received from server: %s", *resp.JSON500.Message)
			fmt.Println("🌭 The PigeonHole API is misbehaving. Grab a tea, it'll be fixed soon!")
			os.Exit(0)
		}

		if utils.KeysExist() != true && viper.GetString("auth.token") != "" {
			fmt.Println("WARNING: No keys exist yet! Set one with pigeonhole-cli keys init")
		}
	},
}

func Execute() {
	cobra.CheckErr(rootCmd.Execute())

}

var verbose bool
var cfgFile string
var v *viper.Viper

func sameMajorMinor(server, client string) bool {
	logrus.Debugf("server version: %s, client version: %s", server, client)
	sv1, err := semver.NewVersion(server)
	if err != nil {
		return false
	}

	sv2, err := semver.NewVersion(client)
	if err != nil {
		return false
	}

	return sv1.Major() == sv2.Major() && sv1.Minor() == sv2.Minor()
}

func init() {

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.pigeonhole/config.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Display more verbose output in console output. (default: false)")
	viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose"))
	logrus.Debugf("Called InitConfig")
	InitConfig()
}

var configPath, fullConfigPath, configName, configType string

func InitConfig() {
	v = viper.NewWithOptions(viper.KeyDelimiter("::"))
	logrus.Debugf("Called InitConfig")
	if cfgFile != "" {
		v.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			logrus.Fatalf("could not determine home directory: %v", err)
		}
		configPath = fmt.Sprintf("%s/.pigeonhole", home)
		os.MkdirAll(configPath, 0o700)
		configType = "yaml"
		configName = "config"
		fullConfigPath = fmt.Sprintf("%s/%s.%s", configPath, configName, configType)
		v.AddConfigPath(configPath)
		v.SetConfigName(configName)
		v.SetConfigType(configType)
		viper.Set("fullConfigPath", fullConfigPath)
	}

	// sensible defaults
	v.SetDefault("api::url", "https://api.pigeono.io/v1")
	v.SetDefault("log::level", "info")

	v.AutomaticEnv()

	if err := v.ReadInConfig(); err != nil {
		logrus.Debugf("Could not read config file: %v", err)
	}
	if err := v.Unmarshal(&PigeonHoleConfig); err != nil {
		logrus.Fatalf("Unable to decode into struct: %v", err)
	}
}

func SetLogger() {
	logrus.SetFormatter(&logrus.TextFormatter{
		TimestampFormat: "2006-01-02T15:04:05Z07:00", // ISO8601 Format
	})
	logrus.SetReportCaller(false)
	if verbose {
		logrus.SetLevel(logrus.DebugLevel)
	}
}
