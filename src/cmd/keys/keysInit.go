package cmd

import (
	"fmt"

	"github.com/pigeonholeio/pigeonhole-cli/common"
	"github.com/spf13/cobra"
)

var KeysInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Force generate and push a new set of GPG keys - this will delete all your existing keys",
	Long:  `Use for the first time or if you want to wipe out all your keys.`,
	Run: func(cmd *cobra.Command, args []string) {
		claims, _ := common.DecodePigeonHoleJWT()
		fmt.Printf("Generating new GPG key as %s...", claims["preferred_username"].(string))
		complete, err := common.GenerateKeys(claims["name"].(string), claims["preferred_username"].(string))
		if complete {
			fmt.Println("done!")
		} else {
			fmt.Printf("failed: %s\n", err)
		}
	},
}

func init() {
}
