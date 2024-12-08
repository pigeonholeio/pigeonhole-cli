package cmd

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/pigeonholeio/pigeonhole-cli/common"
	"github.com/pigeonholeio/pigeonhole-cli/config"
	"github.com/pigeonholeio/pigeonhole-cli/logger"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var rootCmd = &cobra.Command{
	Use:   "pigeonhole",
	Short: "Sending secrets securely.",
	Long: `Welcome to Pigeonhole! 🐦 📨 🔐

Start sending your secrets in just a few steps.
1. Log in (if you haven't already):
	pigeonhole login
2. Send your secret:
	pigeonhole secrets send -f ./files -r someone@domain.com

It's that easy! 🎉`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {

		ConfigureLogger()

		common.GlobalPigeonHoleClient, common.GlobalCtx = common.NewPigeonHoleClient()
		if cmd.Use == "support" || cmd.Use == "docs" || cmd.Use == "login" || cmd.Use == "version" || (cmd.Parent().Name() != "key" && cmd.Use == "init") {
			return
		}
		resp, errx := common.GlobalPigeonHoleClient.UserMeGetWithResponse(common.GlobalCtx)
		if viper.GetString("auth.token") == "" {
			logger.Log.Fatal("No auth token found. Log in by running \n\tpigeonhole login")
		}
		if errx != nil {
			fmt.Println("Something went wrong - Failed to connect to the Pigeonhole API")
			logger.Log.Debug(errx)
			os.Exit(1)
		}
		if resp.StatusCode() == http.StatusForbidden {
			fmt.Println("Invalid Token")
			os.Exit(1)
		} else if resp.StatusCode() == http.StatusUnauthorized {
			fmt.Println("Invalid Token (Unauthorized).\nTry logging back in using `pigeonhole login`")
			os.Exit(1)
		} else if resp.StatusCode() == http.StatusInternalServerError {
			fmt.Println("The Pigeonhole server is misbehaving, Sorry, it'll be fixed soon!")
			os.Exit(1)
		}
		if common.KeysExist() != true && viper.GetString("auth.token") != "" {
			fmt.Println("WARNING: No keys exist yet! Set one with pigeonhole keys init")
		}
	},
}

func Execute() {
	rootCmd.Execute()
}

var verbose bool
var debug bool
var outputFormat string

func ConfigureLogger() {
	if viper.GetBool("debug") {
		logger.InitLogger(logrus.DebugLevel)
		logger.Log.Debugf("Debug enabled!")
	} else if viper.GetBool("verbose") {
		logger.InitLogger(logrus.InfoLevel)
		logger.Log.Debugf("Verbose enabled!")
	} else {
		logger.InitLogger(logrus.FatalLevel)
	}

}

func init() {

	cobra.OnInitialize(config.InitConfig)
	rootCmd.PersistentFlags().StringVar(&config.CfgFile, "config", "", "config file (default is $HOME/.pigeonhole/config.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Display more verbose output in console output. (default: false)")
	rootCmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "Displays debug output in console output. (default: false)")
	rootCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "yaml", fmt.Sprintf("Output Format -  can be %s", strings.Join(common.GetOutputFormats(), ", ")))
	viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose"))
	viper.BindPFlag("debug", rootCmd.PersistentFlags().Lookup("debug"))
	viper.BindPFlag("outputFormat", rootCmd.PersistentFlags().Lookup("output"))

}
