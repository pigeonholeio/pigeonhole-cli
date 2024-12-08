package cmd

import (
	"fmt"
	"os"

	"github.com/pigeonholeio/pigeonhole-cli/common"
	"github.com/pigeonholeio/pigeonhole-cli/sdk"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// keysInitCmd represents the init command
var KeysCreateCmd = &cobra.Command{
	Use:     "create",
	Aliases: []string{"new"},
	Short:   "Create a new GPG key",
	Long: `Sometimes you may find it neccessary to create another GPG key e.g. another device or a bot.
	
Example:
pigeonhole key create
`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Print("Creating and pushing your new GPG key...")
		claims, _ := common.DecodePigeonHoleJWT()
		pub, priv, thumbprint, _ := common.CreateGPGKey(claims["name"].(string), claims["preferred_username"].(string))
		b64_priv := common.EncodeToBase64(priv)
		b64_pub := common.EncodeToBase64(pub)

		reference, _ := cmd.Flags().GetString("reference")
		clear, _ := cmd.Flags().GetBool("clear")
		force, _ := cmd.Flags().GetBool("force")

		x := sdk.NewKey{
			KeyData:    &b64_pub,
			Thumbprint: &thumbprint,
		}
		if reference != "" {
			x.Reference = &reference
		} else {
			n, _ := os.Hostname()
			x.Reference = &n
		}
		x.Only = &clear
		x.Force = &force

		viper.Set("key.latest.public", b64_pub)
		viper.Set("key.latest.private", b64_priv)
		viper.Set("key.latest.thumbprint", thumbprint)

		f, err := common.GlobalPigeonHoleClient.UserMeKeyPostWithResponse(common.GlobalCtx, x)
		if err != nil {
			fmt.Println(err)
		}
		if f.StatusCode() == 201 {
			viper.WriteConfig()
			fmt.Println("done!")
		} else if f.StatusCode() == 400 {
			fmt.Printf("failed: %s\n", f.JSON400.Message)
		} else if f.StatusCode() == 401 {
			fmt.Printf("failed: %s\n", f.JSON401.Message)
		} else if f.StatusCode() == 403 {
			fmt.Printf("failed: %s\n", f.JSON403.Message)
		} else if f.StatusCode() == 500 {
			fmt.Printf("failed: %s\n", f.JSON500.Message)
		}
	},
}

func init() {
	KeysCreateCmd.PersistentFlags().BoolP("force", "f", false, "Force overwrite key with same reference")
	KeysCreateCmd.PersistentFlags().Bool("clear", false, "Clear out all other keys")
	KeysCreateCmd.PersistentFlags().StringP("reference", "r", "", "Override the reference for the key i.e. where it'll be used or created")
}
