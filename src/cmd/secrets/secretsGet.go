package cmd

import (
	"fmt"

	"github.com/pigeonholeio/pigeonhole-cli/common"
	"github.com/pigeonholeio/pigeonhole-cli/logger"
	"github.com/pigeonholeio/pigeonhole-cli/sdk"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// collectCmd represents the collect command
var SecretsCollectCmd = &cobra.Command{
	Use:     "get",
	Aliases: []string{"download", "g"},
	Short:   "Retrieve and decrypt secrets",
	Long:    `Retrieve and decrypt secrets`,
	Run: func(cmd *cobra.Command, args []string) {
		ref, _ := cmd.Flags().GetString("reference")
		path, _ := cmd.Flags().GetString("filepath")
		keep, _ := cmd.Flags().GetBool("keep")
		fmt.Print("Finding secret...")
		blob, _ := common.GlobalPigeonHoleClient.DownloadSecretBlobWithResponse(common.GlobalCtx, ref)
		var decryptedTmpFilePath string
		if blob.StatusCode() != 200 {
			fmt.Println("failed!")
			switch blob.StatusCode() {
			case 400:
				fmt.Println(blob.JSON400.Message)
			case 401:
				fmt.Println(blob.JSON401.Message)
			case 403:
				fmt.Println(blob.JSON403.Message)
			case 500:
				fmt.Println(blob.JSON500.Message)
			}
			return
		}
		fmt.Println("found")
		fmt.Printf("Downloading & decrypting secret to %s...", path)
		decryptedTmpFilePath, errx := common.DecryptBytes(blob.Body, path)

		if errx != nil {
			logrus.Fatalf("Unable to decrypt: %s", errx.Error())
		}
		logger.Log.Debugf("decrypting file to: %s", decryptedTmpFilePath)
		common.DecompressFile(decryptedTmpFilePath, path)
		common.ShredFile(decryptedTmpFilePath)
		fmt.Println("done")

		if keep != true {
			s := sdk.SecretDeleteParams{}
			s.Reference = &ref
			fmt.Print("Deleting remote secret...")
			t, _ := common.GlobalPigeonHoleClient.SecretDeleteWithResponse(common.GlobalCtx, &s)
			if t.HTTPResponse.StatusCode == 200 {
				fmt.Println("done!")
			}
		} else {
			fmt.Println("Skipping remote delete as --keep flag set")
		}
	},
}

func init() {
	SecretsCollectCmd.PersistentFlags().StringP("reference", "r", "", "The id or reference of the secret")
	SecretsCollectCmd.MarkPersistentFlagRequired("reference")
	SecretsCollectCmd.PersistentFlags().StringP("filepath", "f", "./decrypted", "The path where to download, decrypt and extract your secret")
	SecretsCollectCmd.MarkFlagRequired("filepath")
	SecretsCollectCmd.PersistentFlags().BoolP("keep", "k", false, "Keep the file in pigeonhole so you can download it multiple times")
}
