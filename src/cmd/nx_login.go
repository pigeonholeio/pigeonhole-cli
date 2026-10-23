package cmd

import (
	"fmt"

	"github.com/pigeonholeio/common/utils"
	"github.com/pigeonholeio/pigeonhole-cli/nx"
	"github.com/spf13/cobra"
)

var (
	nxLoginEmail string
	nxLoginSSO   bool
)

var nxLoginCmd = &cobra.Command{
	Use:   "login",
	Short: "Sign in to PigeonHole",
	Long: `Sign in to PigeonHole.

By default this uses single sign-on (SSO) via your identity provider.
A device keypair is generated locally and never leaves this machine.`,
	Example: "  pigeonhole login            # SSO (recommended)\n  pigeonhole login --email you@example.com   # dev keypair identity",
	Annotations: map[string]string{"skip-pre-run": "true"},
	RunE: func(cmd *cobra.Command, args []string) error {
		// Default (no flags) = SSO — the intuitive path for new users.
		if nxLoginEmail != "" {
			return keypairLogin(nxLoginEmail)
		}
		return ssoLogin()
	},
}

// keypairLogin: dev identity with an unverified email (local testing).
func keypairLogin(email string) error {
	id, err := nx.LoadIdentity()
	if err != nil || id.Email != email || id.PrivateKey == "" {
		pub, priv, fp := utils.CreateGPGKeyPair(email, email)
		if pub == "" || priv == "" {
			return fmt.Errorf("failed to generate key pair")
		}
		id = &nx.Identity{Email: email, PublicKey: pub, PrivateKey: priv, Thumbprint: fp}
	}
	token, err := nx.Enroll(id.Email, id.PublicKey, id.Thumbprint, id.PublicKey)
	if err != nil {
		return err
	}
	id.Token = token
	if err := nx.SaveIdentity(id); err != nil {
		return err
	}
	fmt.Printf("🕊️  Logged in as %s (dev keypair)\n   device fingerprint: %s\n", id.Email, id.Thumbprint)
	return nil
}

// ssoLogin: OAuth2 device-code flow against Authentik; email is verified by the IdP.
func ssoLogin() error {
	p, err := nx.Providers()
	if err != nil {
		return err
	}
	deviceCode, userCode, verifyURI, verifyComplete, interval, err := nx.DeviceStart(p)
	if err != nil {
		return err
	}
	if verifyComplete != "" {
		fmt.Printf("🔐 Open this URL to sign in:\n   %s\n\n", verifyComplete)
	} else {
		fmt.Printf("🔐 Visit %s and enter code: %s\n\n", verifyURI, userCode)
	}
	fmt.Println("   Waiting for approval…")
	idToken, err := nx.DevicePoll(p, deviceCode, interval)
	if err != nil {
		return err
	}

	// generate this device's keypair locally (private key never leaves the device)
	id, err := nx.LoadIdentity()
	if err != nil || id.PrivateKey == "" {
		pub, priv, fp := utils.CreateGPGKeyPair("pigeonhole-device", "device@pigeono.io")
		id = &nx.Identity{PublicKey: pub, PrivateKey: priv, Thumbprint: fp}
	}
	token, err := nx.OidcEnroll(idToken, id.PublicKey, id.Thumbprint, id.PublicKey)
	if err != nil {
		return err
	}
	id.Token = token
	if err := nx.SaveIdentity(id); err != nil {
		return err
	}
	fmt.Printf("🕊️  Signed in via SSO.\n   device fingerprint: %s\n", id.Thumbprint)
	return nil
}

func init() {
	nxLoginCmd.Flags().StringVar(&nxLoginEmail, "email", "", "dev keypair identity (unverified email)")
	nxLoginCmd.Flags().BoolVar(&nxLoginSSO, "sso", false, "sign in via identity provider (Authentik)")
	rootCmd.AddCommand(nxLoginCmd)
}
