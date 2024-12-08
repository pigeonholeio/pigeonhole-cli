package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/pigeonholeio/pigeonhole-cli/common"
	"github.com/pigeonholeio/pigeonhole-cli/config"
	"github.com/pigeonholeio/pigeonhole-cli/logger"
	"github.com/spf13/viper"
)

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

func AuthenticateWithAzureDeviceCode() (string, error) {

	// Request device and user codes

	resp, err := http.PostForm(config.Config.OpenIdConnect.DeviceCodeEndpoint, url.Values{"response_type": {"id_token"}, "client_id": {config.Config.OpenIdConnect.ClientId}, "scope": {config.Config.OpenIdConnect.Scopes}})

	if err != nil {
		logger.Log.Error(err)
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		logger.Log.Debugf("Getting DeviceCode response: %s", string(bodyBytes))
	}

	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var deviceCodeResp DeviceCodeResponse

	if err := json.NewDecoder(resp.Body).Decode(&deviceCodeResp); err != nil {
		return "", err
	}

	fmt.Printf("Please visit %s and enter the code: %s\n", deviceCodeResp.VerificationURL, deviceCodeResp.UserCode)

	i := 0
	for {

		time.Sleep(1 * time.Second)
		logger.Log.Debugf("Posting attempt #%d for device code auth", i)
		resp, err := http.PostForm(config.Config.OpenIdConnect.TokenEndpoint, url.Values{
			"client_id":   {config.Config.OpenIdConnect.ClientId},
			"device_code": {deviceCodeResp.DeviceCode},
			"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
			"scope":       {config.Config.OpenIdConnect.Scopes},
		})

		if err != nil {
			return "", err
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			var tokenResp TokenResponse
			if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
				logger.Log.Error(err)
			}
			logger.Log.Debug(tokenResp.IdToken)
			pigeonholeClient, ctx := common.NewIdPClient(tokenResp.IdToken)
			r, errx := pigeonholeClient.AuthSsoTokenPostWithResponse(ctx)
			if errx != nil {
				logger.Log.Error(errx)
			}

			if r.JSON200 != nil {
				logger.Log.Debug("Got access token from IdP: ", r.JSON200.AccessToken)
				config.Config.Auth.AccessToken = r.JSON200.AccessToken
				viper.Set("auth.token", r.JSON200.AccessToken)
				viper.ReadInConfig()
				err = viper.WriteConfig()
				if err != nil {
					err = viper.SafeWriteConfig()
					if err != nil {
						logger.Log.Error(err)
						return "", err
					}
					return "", err
				}
				fmt.Println()
				return tokenResp.IdToken, nil
			} else if r.JSON500 != nil {
				logger.Log.Info("uh oh!")
				return "", fmt.Errorf("Unexpected error from server!")
			}

		} else {
			logger.Log.Debugf("http status code for token: %v", resp.StatusCode)
		}
		i += 1
	}

	return "", fmt.Errorf("authentication timed out")
}
