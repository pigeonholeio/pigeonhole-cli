package cmd

import (
	"encoding/json"
	"fmt"
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

	resp, err := http.PostForm(config.Config.OpenIdConnect.DeviceCodeEndpoint, url.Values{"response_type": {"id_token"}, "client_id": {config.Config.OpenIdConnect.ClientId}, "scope": {config.Config.OpenIdConnect.Scopes}})
	if err != nil {
		// logger.Log.Error(err)
		return "", err
	}

	defer resp.Body.Close()

	var deviceCodeResp DeviceCodeResponse

	if err := json.NewDecoder(resp.Body).Decode(&deviceCodeResp); err != nil {
		return "", err
	}

	// Display user code and verification URL to the user
	fmt.Printf("Please visit %s and enter the code: %s\n", deviceCodeResp.VerificationURL, deviceCodeResp.UserCode)
	timeout := 0
	for {
		// time.Sleep(time.Duration(deviceCodeResp.Interval) * time.Second)

		time.Sleep(3 * time.Second)

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

		if resp.StatusCode == http.StatusOK { // IdP Response i.e. Azure
			var tokenResp TokenResponse
			if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
				// logger.Log.Error(err)
			}
			logger.Log.Debugf("IdP Issued ID Token: %s", tokenResp.IdToken)
			pigeonholeClient, ctx := common.NewIdPClient(tokenResp.IdToken)
			fmt.Print("Exchanging Identity Provider token for a Pigeonhole token...")
			r, errx := pigeonholeClient.AuthSsoTokenPostWithResponse(ctx)
			if errx != nil {
				fmt.Println(errx)
				return "", errx
			}
			switch r.StatusCode() {
			case 400:
				logger.Log.Debugf("Failed to exchange Pigeonhole keys:\n%s", r.JSON400.Message)
				return "", fmt.Errorf("Failed to exchange Pigeonhole keys:\n%s", r.JSON400.Message)
			case 401:
				logger.Log.Debugf("Failed to exchange Pigeonhole keys:\n%s", r.JSON401.Message)
				return "", fmt.Errorf("Failed to exchange Pigeonhole keys:\n%s", r.JSON401.Message)
			case 403:
				logger.Log.Debugf("Failed to exchange Pigeonhole keys:\n%s", r.JSON403.Message)
				return "", fmt.Errorf("Failed to exchange Pigeonhole keys:\n%s", r.JSON403.Message)
			case 500:
				logger.Log.Debugf("Failed to exchange Pigeonhole keys:\n%s", r.JSON500.Message)
				return "", fmt.Errorf("Failed to exchange Pigeonhole keys:\n%s", r.JSON500.Message)
			case 503:
				return "", fmt.Errorf("Pigeonhole is having a little wobbly, try again soon")
			case 201:
				if r.JSON201.AccessToken != "" {
					logger.Log.Debug("Got access token from Pigeonhole: ", r.JSON201.AccessToken)
					config.Config.Auth.AccessToken = r.JSON201.AccessToken
					viper.ReadInConfig()
					err := viper.ReadInConfig()
					if err != nil {

					}
					viper.Set("auth.token", r.JSON201.AccessToken)
					viper.Set("debug", false)
					err = viper.WriteConfig()
					if err != nil {
						return "", err
					}
				}
				fmt.Println("done!")
				return r.JSON201.AccessToken, nil
			}

		} else if resp.StatusCode == http.StatusBadRequest { // Response from IdP
			// User is probably still logging in.
			if timeout > 10 { // Assumes c. 30 seconds
				break
			} else {
				// fmt.Println(timeout)
				timeout += 1
			}
		} else { // response from IdP
			fmt.Errorf("Something went wrong!")
			return "", fmt.Errorf("Failed to exchange Pigeonhole keys:\n%s", resp.Body)
		}
	}
	return "", fmt.Errorf("authentication timed out")

}
