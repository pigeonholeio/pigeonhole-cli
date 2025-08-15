package cmd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/pigeonholeio/pigeonhole-cli/common"
	"github.com/pigeonholeio/pigeonhole-cli/config"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var timeoutSec int

var rootCmd = &cobra.Command{
	Use:   "pigeonhole",
	Short: "Sending secrets securely.",
	Long:  `This command will display the size of a directory with several different options.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if cmd.Use == "login" || cmd.Use == "version" || (cmd.Parent().Name() != "key" && cmd.Use == "init") {
			return
		}

		common.GlobalPigeonHoleClient, common.GlobalCtx = common.NewPigeonHoleClient(timeoutSec)

		resp, errx := common.GlobalPigeonHoleClient.UserMeGetWithResponse(common.GlobalCtx)

		if errx != nil {
			logrus.Debug(errx)
			if errors.Is(errx, context.DeadlineExceeded) {
				fmt.Printf("❌ HTTP request timed out after %d seconds\n", timeoutSec)
			} else {
				fmt.Println("☠️ Something went wrong - Failed to connect to the Pigeonhole API")
			}
			os.Exit(1)
		}
		if resp.StatusCode() == http.StatusForbidden {
			fmt.Println("🛡️ Invalid Token (Forbidden) - Try signing back in using `pigeonhole login`")
			os.Exit(1)
		} else if resp.StatusCode() == http.StatusUnauthorized {
			fmt.Println("🛡️ Invalid Token (Unauthorized) - Try signing back in using `pigeonhole login`")
			os.Exit(1)
		} else if resp.StatusCode() == http.StatusInternalServerError {
			fmt.Println("The Pigeonhole server is misbehaving, Sorry, it'll be fixed soon!")
			os.Exit(1)
		}
		if common.KeysExist() != true && viper.GetString("auth.token") != "" {
			fmt.Println("WARNING: No keys exist yet! Set one with pigeonhole-cli keys init")
		}
	},
}

func Execute() {
	cobra.CheckErr(rootCmd.Execute())

}

var verbose bool

func init() {

	cobra.OnInitialize(config.InitConfig)
	timeoutSec = 5
	rootCmd.PersistentFlags().StringVar(&config.CfgFile, "config", "", "config file (default is $HOME/.pigeonhole/config.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Display more verbose output in console output. (default: false)")
	viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose"))

}
