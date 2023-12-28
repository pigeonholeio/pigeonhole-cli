package auth

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/pigeonholeio/pigeonhole-cli/common"
	"github.com/pigeonholeio/pigeonhole-cli/config"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// const (
// 	deviceCodeEndpoint = "https://login.microsoftonline.com/organizations/oauth2/v2.0/devicecode" // Replace with the actual endpoint
// 	// tokenEndpoint      = "https://login.microsoftonline.com/organizations/oauth2/v2.0/token"      // Replace with the actual endpoint
// 	tokenEndpoint = "https://login.microsoftonline.com/organizations/oauth2/v2.0/token" // Replace with the actual endpoint
// 	clientID      = config.Config.OpenIDConnect.ClientId
// 	scopes        = "openid email profile https://pigeono.io/default"
// )

type DeviceCodeResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURL string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

type TokenResponse struct {
	IdToken   string `json:"id_token"`
	ExpiresIn int    `json:"expires_in"`
}

func AuthenticateWithDeviceCode() (string, error) {

	// Request device and user codes

	// resp, err := http.PostForm(config.Config.OpenIdConnect.DeviceCodeEndpoint, url.Values{"response_type": {"id_token"}, "client_id": {config.Config.OpenIdConnect.ClientId}, "scope": {config.Config.OpenIdConnect.Scopes}})
	// fmt.Println(config.Config.OpenIdConnect.DeviceCodeEndpoint)
	resp, err := http.PostForm(config.Config.OpenIdConnect.DeviceCodeEndpoint, url.Values{"response_type": {"id_token"}, "client_id": {config.Config.OpenIdConnect.ClientId}, "scope": {config.Config.OpenIdConnect.Scopes}})

	if err != nil {
		logrus.Error(err)
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := ioutil.ReadAll(resp.Body)
		logrus.Debug("Getting DeviceCode response:", string(bodyBytes))
	}

	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var deviceCodeResp DeviceCodeResponse

	if err := json.NewDecoder(resp.Body).Decode(&deviceCodeResp); err != nil {
		return "", err
	}

	// Display user code and verification URL to the user
	fmt.Printf("Please visit %s and enter the code: %s\n", deviceCodeResp.VerificationURL, deviceCodeResp.UserCode)

	// Poll the token endpoint to check if the user has authenticated
	// expiresAt := time.Now().Add(time.Duration(deviceCodeResp.ExpiresIn) * time.Second)

	for {
		// time.Sleep(time.Duration(deviceCodeResp.Interval) * time.Second)

		time.Sleep(1 * time.Second)
		resp, err := http.PostForm(config.Config.OpenIdConnect.TokenEndpoint, url.Values{
			"client_id":   {config.Config.OpenIdConnect.ClientId},
			"device_code": {deviceCodeResp.DeviceCode},
			"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
			"scope":       {config.Config.OpenIdConnect.Scopes},
		})
		// spew.Dump(resp)

		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		// bodyBytes, _ := ioutil.ReadAll(resp.Body)
		// logrus.Debugf("Polling response:", string(bodyBytes))
		// fmt.Println(strings(resp.Body.Read())

		if resp.StatusCode == http.StatusOK {
			var tokenResp TokenResponse
			if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
				logrus.Error(err)
			}
			logrus.Debug(tokenResp.IdToken)
			pigeonholeClient, ctx := common.NewIdPClient(tokenResp.IdToken)
			r, errx := pigeonholeClient.AuthSsoTokenPostWithResponse(ctx)
			if errx != nil {
				logrus.Error(errx)
			}

			// spew.Dump(r.JSON200)
			// fmt.Println(r.Body())

			// spew.dump(r)

			// pigeonholeClient.AuthSsoTokenPostWithResponse()
			config.Config.Auth.AccessToken = r.JSON200.AccessToken
			viper.Set("auth.token", r.JSON200.AccessToken)

			err = viper.WriteConfig()
			if err != nil {
				err = viper.SafeWriteConfig()
				if err != nil {
					logrus.Error(err)
					return "", err
				}
				return "", err
			}
			fmt.Println()
			return tokenResp.IdToken, nil
		} else {
			logrus.Debugf("http status code for token: %v", resp.StatusCode)
		}
	}

	return "", fmt.Errorf("authentication timed out")
}
