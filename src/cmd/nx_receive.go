package cmd

import (
	"bytes"
	"fmt"
	"os"

	"github.com/pigeonholeio/common/utils"
	"github.com/pigeonholeio/pigeonhole-cli/nx"
	"github.com/spf13/cobra"
)

var (
	nxRecvRef    string
	nxRecvOutput string
)

var nxReceiveCmd = &cobra.Command{
	Use:         "receive",
	Aliases:     []string{"recv", "get"},
	Short:       "Download and decrypt a secret (to stdout or a file)",
	Annotations: map[string]string{"skip-pre-run": "true"},
	RunE: func(cmd *cobra.Command, args []string) error {
		id, err := nx.LoadIdentity()
		if err != nil {
			return err
		}

		metas, err := nx.List(id.Token, nxRecvRef)
		if err != nil {
			return err
		}
		// consider only uploaded secrets
		var avail []nx.SecretMeta
		for _, m := range metas {
			if m.Uploaded {
				avail = append(avail, m)
			}
		}
		if len(avail) == 0 {
			return fmt.Errorf("no secrets available%s", refSuffix(nxRecvRef))
		}
		if len(avail) > 1 && nxRecvRef == "" {
			refs := make([]string, len(avail))
			for i, m := range avail {
				refs[i] = m.Reference
			}
			return fmt.Errorf("multiple secrets available %v — choose one with --ref", refs)
		}
		chosen := &avail[0]

		ct, err := nx.Download(id.Token, chosen.ID)
		if err != nil {
			return err
		}

		// Decrypt client-side with this device's private key.
		if nxRecvOutput == "" || nxRecvOutput == "-" {
			if err := utils.DecryptStream(bytes.NewReader(ct), os.Stdout, id.PrivateKey); err != nil {
				return fmt.Errorf("decryption failed: %w", err)
			}
			return nil
		}
		f, err := os.Create(nxRecvOutput)
		if err != nil {
			return err
		}
		defer f.Close()
		if err := utils.DecryptStream(bytes.NewReader(ct), f, id.PrivateKey); err != nil {
			return fmt.Errorf("decryption failed: %w", err)
		}
		fmt.Fprintf(os.Stderr, "🕊️  Saved to %s (ref %s)\n", nxRecvOutput, chosen.Reference)
		return nil
	},
}

func refSuffix(ref string) string {
	if ref == "" {
		return ""
	}
	return " for reference " + ref
}

func init() {
	nxReceiveCmd.Flags().StringVar(&nxRecvRef, "ref", "", "secret reference to retrieve")
	nxReceiveCmd.Flags().StringVarP(&nxRecvOutput, "output", "o", "", "write to file (default: stdout)")
	rootCmd.AddCommand(nxReceiveCmd)
}
