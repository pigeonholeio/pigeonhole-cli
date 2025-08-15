package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pigeonholeio/pigeonhole-cli/common"
	"github.com/pigeonholeio/pigeonhole-cli/config"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

type DeviceCodeResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
	Message                 string `json:"message"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token,omitempty"`
	IdToken      string `json:"id_token,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
}

type OauthError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

var (
	ErrAuthTimedOut      = errors.New("device code authentication timed out")
	ErrUnexpectedStatus  = errors.New("unexpected http status from token endpoint")
	ErrNoIDTokenReceived = errors.New("no id_token received from token endpoint")
)

// AuthenticateWithAzureDeviceCode performs OIDC Device Code flow against endpoints configured in config.Config.OpenIdConnect.
// - honors the interval and expiry returned by the device code response
// - handles common error responses (authorization_pending, slow_down, expired_token, access_denied)
// - returns the id_token on success or an error
func AuthenticateWithAzureDeviceCode(ctx context.Context, timeoutSec int) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	oidcCfg := config.Config.OpenIdConnect
	if oidcCfg.DeviceCodeEndpoint == "" || oidcCfg.TokenEndpoint == "" || oidcCfg.ClientId == "" {
		return "", fmt.Errorf("openidconnect config incomplete")
	}

	httpClient := &http.Client{
		Timeout: time.Duration(timeoutSec) * time.Second,
	}

	// Request device code
	form := url.Values{
		"client_id":     {oidcCfg.ClientId},
		"scope":         {oidcCfg.Scopes},
		"response_type": {"id_token"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, oidcCfg.DeviceCodeEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("creating device code request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("device code request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading device code response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		// try to parse any oauth-style error
		var oe OauthError
		_ = json.Unmarshal(body, &oe)
		return "", fmt.Errorf("device code endpoint returned status %d: %s %s", resp.StatusCode, oe.Error, oe.ErrorDescription)
	}

	var deviceResp DeviceCodeResponse
	if err := json.Unmarshal(body, &deviceResp); err != nil {
		return "", fmt.Errorf("parsing device code response: %w", err)
	}

	// Present to user
	verification := deviceResp.VerificationURIComplete
	if verification == "" {
		verification = deviceResp.VerificationURI
	}
	if deviceResp.Message != "" {
		fmt.Println(deviceResp.Message)

	} else {
		logrus.Infof("Please visit %s and enter the code: %s", verification, deviceResp.UserCode)
	}

	// Determine polling interval and expiry
	interval := time.Duration(deviceResp.Interval) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second // sensible default per RFC
	}
	expiry := time.Now().Add(time.Duration(deviceResp.ExpiresIn) * time.Second)
	if deviceResp.ExpiresIn <= 0 {
		// default to a conservative expiry if none provided
		expiry = time.Now().Add(10 * time.Minute)
	}

	// Polling loop
	for {
		// Respect context cancellation
		if ctx.Err() != nil {
			return "", ctx.Err()
		}

		if time.Now().After(expiry) {
			return "", ErrAuthTimedOut
		}

		// Build token request
		pollForm := url.Values{
			"client_id":   {oidcCfg.ClientId},
			"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
			"device_code": {deviceResp.DeviceCode},
			"scope":       {oidcCfg.Scopes},
		}

		pollReq, err := http.NewRequestWithContext(ctx, http.MethodPost, oidcCfg.TokenEndpoint, strings.NewReader(pollForm.Encode()))
		if err != nil {
			return "", fmt.Errorf("creating token poll request: %w", err)
		}
		pollReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		pollResp, err := httpClient.Do(pollReq)
		if err != nil {
			// network hiccup — log and retry after interval
			logrus.WithError(err).Warn("token endpoint request failed; retrying")
			select {
			case <-time.After(interval):
				continue
			case <-ctx.Done():
				return "", ctx.Err()
			}
		}

		pollBody, readErr := io.ReadAll(pollResp.Body)
		pollResp.Body.Close()
		if readErr != nil {
			logrus.WithError(readErr).Warn("failed to read token endpoint response; retrying")
			select {
			case <-time.After(interval):
				continue
			case <-ctx.Done():
				return "", ctx.Err()
			}
		}

		if pollResp.StatusCode == http.StatusOK { // this means Azure IdP has returned goodness

			var tok TokenResponse
			if err := json.Unmarshal(pollBody, &tok); err != nil {
				return "", fmt.Errorf("parsing token response: %w", err)
			}
			b, err := json.Marshal(tok)
			if err != nil {
				logrus.WithError(err).Error("failed to marshal token")
			} else {
				logrus.Debugf("Returned token: %s", b)
			}
			if tok.IdToken == "" {
				// Some IdPs might return access_token instead; adapt if needed.
				return "", ErrNoIDTokenReceived
			}

			// Exchange IdToken with internal IdP to get AccessToken (existing code's behaviour)
			pigeonholeClient, childCtx := common.NewIdPClient(tok.IdToken, timeoutSec)
			r, err := pigeonholeClient.AuthSsoTokenPostWithResponse(childCtx)
			logrus.Debug(fmt.Sprintf("Status Code from PigeonHole API: %s", r.Status()))

			if err != nil {
				return "", fmt.Errorf("calling internal IdP: %w", err)
			}
			if r == nil || r.JSON201 == nil {
				return "", fmt.Errorf("Unexpected response from PigeonHole, please try again.")
			}

			// Persist access token to in-memory config and viper
			config.Config.Auth.AccessToken = r.JSON201.AccessToken
			viper.Set("auth.token", r.JSON201.AccessToken)
			// prefer WriteConfig; if file doesn't exist, use SafeWriteConfig to create it
			if err := viper.WriteConfig(); err != nil {
				if err := viper.SafeWriteConfig(); err != nil {
					// log and continue — we still return IdToken to the caller
					logrus.WithError(err).Warn("failed to write viper config; configuration not persisted to disk")
				}
			}

			return tok.IdToken, nil
		}

		// Non-200: try to decode OAuth-style error
		var oe OauthError
		_ = json.Unmarshal(pollBody, &oe)

		switch oe.Error {
		case "authorization_pending":
			// user hasn't completed auth yet — wait interval and poll again
			logrus.Debug("authorization_pending, waiting before retry")
			select {
			case <-time.After(interval):
				continue
			case <-ctx.Done():
				return "", ctx.Err()
			}
		case "slow_down":
			// server asks to slow down polling — increase interval by 5s
			interval += 5 * time.Second
			logrus.Debug("received slow_down, increasing interval")
			select {
			case <-time.After(interval):
				continue
			case <-ctx.Done():
				return "", ctx.Err()
			}
		case "expired_token":
			return "", fmt.Errorf("device code expired: %s", oe.ErrorDescription)
		case "access_denied":
			return "", fmt.Errorf("access denied by user: %s", oe.ErrorDescription)
		default:
			// Unexpected error; include status and body for diagnosability
			logrus.WithFields(logrus.Fields{
				"status": pollResp.StatusCode,
				"body":   string(pollBody),
				"error":  oe.Error,
			}).Warn("token endpoint returned non-OK response")
			// Decide whether to continue or break; here we retry until expiry, backing off by interval
			select {
			case <-time.After(interval):
				continue
			case <-ctx.Done():
				return "", ctx.Err()
			}
		}
	}
}
