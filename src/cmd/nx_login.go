package cmd

import (
	"fmt"

	"github.com/pigeonholeio/common/utils"
	"github.com/pigeonholeio/pigeonhole-cli/nx"
	"github.com/spf13/cobra"
)

var nxLoginEmail string

var nxLoginCmd = &cobra.Command{
	Use:         "login",
	Short:       "Authenticate with PigeonHole (keypair identity)",
	Annotations: map[string]string{"skip-pre-run": "true"},
	RunE: func(cmd *cobra.Command, args []string) error {
		if nxLoginEmail == "" {
			return fmt.Errorf("--email is required")
		}

		// Reuse the existing device keypair if already enrolled with this email.
		id, err := nx.LoadIdentity()
		if err != nil || id.Email != nxLoginEmail || id.PrivateKey == "" {
			pub, priv, fp := utils.CreateGPGKeyPair(nxLoginEmail, nxLoginEmail)
			if pub == "" || priv == "" {
				return fmt.Errorf("failed to generate key pair")
			}
			id = &nx.Identity{Email: nxLoginEmail, PublicKey: pub, PrivateKey: priv, Thumbprint: fp}
		}

		// master_key = this device's public key for now (single-device bootstrap).
		token, err := nx.Enroll(id.Email, id.PublicKey, id.Thumbprint, id.PublicKey)
		if err != nil {
			return err
		}
		id.Token = token
		if err := nx.SaveIdentity(id); err != nil {
			return err
		}
		fmt.Printf("🕊️  Logged in as %s\n   device fingerprint: %s\n", id.Email, id.Thumbprint)
		return nil
	},
}

func init() {
	nxLoginCmd.Flags().StringVar(&nxLoginEmail, "email", "", "your email address")
	rootCmd.AddCommand(nxLoginCmd)
}
