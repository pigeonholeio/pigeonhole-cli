package cmd

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"github.com/pigeonholeio/common/utils"
	"github.com/pigeonholeio/pigeonhole-cli/nx"
	"github.com/spf13/cobra"
)

var (
	nxSendTo      []string
	nxSendOnetime bool
)

var nxSendCmd = &cobra.Command{
	Use:         "send [file]",
	Short:       "Encrypt and send a secret (file or stdin) to recipients",
	Annotations: map[string]string{"skip-pre-run": "true"},
	RunE: func(cmd *cobra.Command, args []string) error {
		id, err := nx.LoadIdentity()
		if err != nil {
			return err
		}
		if len(nxSendTo) == 0 {
			return fmt.Errorf("at least one --to recipient is required")
		}

		// Gather recipient device public keys (multi-device => encrypt to all).
		var pubKeys []string
		for _, r := range nxSendTo {
			keys, err := nx.LookupKeys(id.Token, r)
			if err != nil {
				return err
			}
			pubKeys = append(pubKeys, keys...)
		}

		// Read the payload (file arg or stdin).
		var src io.Reader
		if len(args) > 0 && args[0] != "-" {
			f, err := os.Open(args[0])
			if err != nil {
				return err
			}
			defer f.Close()
			src = f
		} else {
			src = os.Stdin
		}

		// OpenPGP-encrypt once, PKESK per recipient key (client-side; zero-knowledge).
		var ct bytes.Buffer
		if err := utils.EncryptStream(src, &ct, pubKeys); err != nil {
			return fmt.Errorf("encryption failed: %w", err)
		}

		secretID, ref, bodyURL, err := nx.CreateSecret(id.Token, nxSendTo, int64(ct.Len()), nxSendOnetime)
		if err != nil {
			return err
		}
		if err := nx.PutBody(bodyURL, ct.Bytes()); err != nil {
			return err
		}
		fmt.Printf("🕊️  Sent! reference: %s\n   id: %s  size: %d bytes  recipients: %v\n", ref, secretID, ct.Len(), nxSendTo)
		return nil
	},
}

func init() {
	nxSendCmd.Flags().StringSliceVar(&nxSendTo, "to", nil, "recipient email(s)")
	nxSendCmd.Flags().BoolVar(&nxSendOnetime, "onetime", false, "burn after first download")
	rootCmd.AddCommand(nxSendCmd)
}
