package auth

import (
	"context"
	"fmt"

	"github.com/pigeonholeio/pigeonhole-cli/sdk"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

func AuthenticateWithDeviceCode(ctx context.Context, clientId string, provider *sdk.OIDCProvider) (*oauth2.Token, error) {

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
	da, err := conf.DeviceAuth(ctx)
	if err != nil {
		logrus.Debugln(err.Error())
		return nil, err
	}
	fmt.Printf("Go to %s and enter code: %s\n", da.VerificationURI, da.UserCode)

	tok, err := conf.DeviceAccessToken(ctx, da)
	if err != nil {
		return nil, err
	}

	return tok, nil
}
