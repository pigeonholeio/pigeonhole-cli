package auth

import (
	"context"
	"os"

	"github.com/pigeonholeio/pigeonhole-cli/config"
	"github.com/pigeonholeio/pigeonhole-cli/sdk"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

// DeviceCodePrompt is called once the device code is available, before polling begins.
type DeviceCodePrompt func(verificationURI, userCode string)

func AuthenticateWithDeviceCode(ctx context.Context, clientId string, provider *sdk.OIDCProvider, prompt DeviceCodePrompt) (*oauth2.Token, error) {

	logrus.Debugf("Using following provider auth url: %s\n", *provider.AuthUrl)
	logrus.Debugf("Using following provider token url: %s\n", *provider.TokenUrl)
	logrus.Debugf("Using following provider device url: %s\n", *provider.DeviceAuthURL)
	logrus.Debugf("Using following provider client id: %s\n", *provider.ClientID)
	logrus.Debugf("Using following provider scopes: %s\n", *provider.Scopes)

	conf := &oauth2.Config{
		ClientID: clientId,
		Endpoint: oauth2.Endpoint{
			AuthURL:       *provider.AuthUrl,
			TokenURL:      *provider.TokenUrl,
			DeviceAuthURL: *provider.DeviceAuthURL,
		},
		Scopes: *provider.Scopes,
	}

	logrus.Debugf("Calling Device Auth auth url: %s\n", *provider.DeviceAuthURL)
	logrus.Debugf("Using audience: %s\n", *provider.Audience)
	da, err := conf.DeviceAuth(ctx, oauth2.SetAuthURLParam("audience", *provider.Audience))
	if err != nil {
		logrus.Debugln(err.Error())
		return nil, err
	}

	if prompt != nil {
		prompt(da.VerificationURI, da.UserCode)
	}

	tok, err := conf.DeviceAccessToken(ctx, da, oauth2.SetAuthURLParam("audience", *provider.Audience))
	if err != nil {
		return nil, err
	}

	return tok, nil
}

// SyncKeysWithRemote validates local keys match remote API and uploads if needed
func SyncKeysWithRemote(ctx context.Context, cfg *config.PigeonHoleConfig, client *sdk.ClientWithResponses) error {
	logrus.Debugln("Syncing local keys with remote API")

	// Get user email
	email, err := cfg.GetUserEmail()
	if err != nil {
		logrus.Debugf("Failed to get user email: %v", err)
		return nil // Non-blocking
	}

	identity, ok := cfg.Identity[email]
	if !ok || identity.GPGKey == nil {
		logrus.Debugf("No local key found for %s", email)
		return nil
	}

	// If no local key exists, nothing to sync
	if !identity.GPGKey.KeyExists() {
		logrus.Debugln("No local key material found")
		return nil
	}

	localFingerprint := identity.GPGKey.Fingerprint
	if localFingerprint == nil || *localFingerprint == "" {
		logrus.Debugln("Local key fingerprint is empty")
		return nil
	}

	// Get remote keys
	remoteKeysResp, err := client.GetUserMeKeyWithResponse(ctx)
	if err != nil {
		logrus.Debugf("Failed to fetch remote keys: %v", err)
		return nil // Non-blocking
	}

	if remoteKeysResp.StatusCode() != 200 || remoteKeysResp.JSON200 == nil {
		logrus.Debugf("Unexpected response from remote keys: %d", remoteKeysResp.StatusCode())
		return nil // Non-blocking
	}

	// Check if local key matches any remote key
	found := false
	if remoteKeysResp.JSON200.Keys != nil {
		for _, remoteKey := range *remoteKeysResp.JSON200.Keys {
			if remoteKey.Fingerprint != nil && *remoteKey.Fingerprint == *localFingerprint {
				found = true
				logrus.Debugln("Local key matches remote key")
				break
			}
		}
	}

	// If not found, upload local key
	if !found {
		logrus.Debugln("Local key not found on remote, uploading...")
		decodedKey, err := identity.GPGKey.DecodedPublicKey()
		if err != nil {
			logrus.Debugf("Failed to decode public key: %v", err)
			return nil // Non-blocking
		}

		hostname, _ := os.Hostname()
		newKey := sdk.NewKey{
			KeyData:     &decodedKey,
			Fingerprint: localFingerprint,
		}
		if hostname != "" {
			newKey.Reference = &hostname
		}

		uploadResp, err := client.PostUserMeKeyWithResponse(ctx, newKey)
		if err != nil {
			logrus.Debugf("Failed to upload key: %v", err)
			return nil // Non-blocking
		}

		if uploadResp.StatusCode() != 201 {
			logrus.Debugf("Failed to upload key: status %d", uploadResp.StatusCode())
			return nil // Non-blocking
		}

		logrus.Debugln("Successfully uploaded local key to remote")
	}

	return nil
}
