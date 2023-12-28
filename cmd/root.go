package cmd

import (
	"fmt"
	"net/http"
	"os"

	"github.com/pigeonholeio/pigeonhole-cli/common"
	"github.com/pigeonholeio/pigeonhole-cli/config"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var rootCmd = &cobra.Command{
	Use:   "pigeonhole-cli",
	Short: "Sending secrets securely.",
	Long:  `This command will display the size of a directory with several different options.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if cmd.Use == "login" {
			return
		}
		common.GlobalPigeonHoleClient, common.GlobalCtx = common.NewPigeonHoleClient()

		resp, errx := common.GlobalPigeonHoleClient.UserMeGetWithResponse(common.GlobalCtx)

		if errx != nil {
			fmt.Println("Something went wrong - Failed to connect to the Pigeonhole API")
			logrus.Debug(errx)
			os.Exit(0)
		}
		if resp.StatusCode() == http.StatusForbidden {
			fmt.Println("Invalid Token")
		} else if resp.StatusCode() == http.StatusUnauthorized {
			fmt.Println("Invalid Token (Unauthorized).\nTry logging back in using `pigeonhole login`")
			os.Exit(0)
		} else if resp.StatusCode() == http.StatusInternalServerError {
			fmt.Println("The Pigeonhole server is misbehaving, Sorry, it'll be fixed soon!")
			os.Exit(0)
		}
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	// cobra.OnInitialize(config.InitConfig)
	cobra.CheckErr(rootCmd.Execute())

}

var verbose bool

func init() {

	// cobra.OnInitialize(initConfig)
	cobra.OnInitialize(config.InitConfig)

	// fmt.Println(config.Config.OpenIdConnect.ClientId)
	rootCmd.PersistentFlags().StringVar(&config.CfgFile, "config", "", "config file (default is $HOME/.cli.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Display more verbose output in console output. (default: false)")
	viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose"))

	// if &GlobalPigeonHoleClient == nil {
	// 	fmt.Println("ERRORX")
	// }
	// if GlobalCtx == nil {
	// 	fmt.Println("ERRORX")
	// }
	// if call == nil {
	// 	// fmt.Println("FAILED CALL")
	// 	spew.Dump(call)
	// }
	// if errx != nil {
	// 	// fmt.Println("FAILED CALL")
	// 	spew.Dump(errx)
	// }

	// fmt.Println(me.JSON200)
	// common.OutputData(me.JSON200)
	// fmt.Println(viper.GetString("auth.accessToken"))
	// rootCmd.PersistentFlags().StringVarP(&Path, "path", "p", os.Getenv("HOME"), "Define the path to scan.")
	// rootCmd.MarkFlagRequired("path")
	// viper.BindPFlag("path", rootCmd.PersistentFlags().Lookup("path"))

}

// initConfig reads in config file and ENV variables if set.
