package auth

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/pigeonholeio/common/utils"
	"github.com/pigeonholeio/pigeonhole-cli/config"
	"github.com/pigeonholeio/pigeonhole-cli/sdk"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

// RefreshToken attempts to refresh the access token using the IdP refresh token
func RefreshToken(ctx context.Context, cfg *config.PigeonHoleConfig, clientID string, provider *sdk.OIDCProvider) error {
	if cfg == nil || cfg.API == nil || cfg.API.RefreshToken == nil || *cfg.API.RefreshToken == "" {
		return fmt.Errorf("no refresh token available")
	}

	logrus.Debugf("Attempting to refresh token using IdP refresh token")

	conf := &oauth2.Config{
		ClientID: clientID,
		Endpoint: oauth2.Endpoint{
			AuthURL:  *provider.AuthUrl,
			TokenURL: *provider.TokenUrl,
		},
		Scopes: *provider.Scopes,
	}

	// Use the refresh token to get a new access token
	tokenSource := conf.TokenSource(ctx, &oauth2.Token{
		RefreshToken: *cfg.API.RefreshToken,
	})

	newToken, err := tokenSource.Token()
	if err != nil {
		logrus.Debugf("Failed to refresh IdP token: %v", err)
		return fmt.Errorf("failed to refresh IdP token: %w", err)
	}

	logrus.Debugf("IdP token refreshed successfully")

	// Update the stored refresh token if a new one was provided
	if newToken.RefreshToken != "" && newToken.RefreshToken != *cfg.API.RefreshToken {
		cfg.API.RefreshToken = &newToken.RefreshToken
		logrus.Debugf("Updated refresh token")
	}

	return nil
}

// RefreshPigeonHoleToken exchanges a fresh IdP token for a new PigeonHole JWT token
func RefreshPigeonHoleToken(ctx context.Context, cfg *config.PigeonHoleConfig, client *sdk.ClientWithResponses, idpToken *oauth2.Token) error {
	logrus.Debugf("Exchanging refreshed IdP token for PigeonHole JWT")

	// Extract audience from PigeonHole API URL
	var audience string
	if cfg != nil && cfg.API != nil && cfg.API.Url != nil && *cfg.API.Url != "" {
		if parsedURL, err := url.Parse(*cfg.API.Url); err == nil {
			audience = parsedURL.Scheme + "://" + parsedURL.Host
			logrus.Debugf("Using audience: %s", audience)
		} else {
			logrus.Warnf("Failed to parse API URL for audience: %v", err)
		}
	}

	phTok := sdk.OIDCProviderToken{
		AccessToken: &idpToken.AccessToken,
		Audience:    &audience,
	}

	resp, err := client.PostAuthOidcHandlerProviderWithResponse(ctx, "oidc", phTok)
	if err != nil {
		return fmt.Errorf("failed to exchange IdP token with PigeonHole: %w", err)
	}

	if resp.StatusCode() != 201 {
		return fmt.Errorf("unexpected status code when refreshing token: %d", resp.StatusCode())
	}

	// Update the access token
	cfg.API.AccessToken = &resp.JSON201.AccessToken

	// Extract and update the token expiry
	if claims, err := utils.DecodePigeonHoleJWT(resp.JSON201.AccessToken); err == nil {
		if exp, ok := claims["exp"]; ok {
			if expFloat, ok := exp.(float64); ok {
				expInt64 := int64(expFloat)
				cfg.API.TokenExpiry = &expInt64
				logrus.Debugf("Token refreshed, new expiry: %d (expires at %s)", expInt64, time.Unix(expInt64, 0))
			}
		}
	}

	return nil
}

// EnsureTokenValid checks if the token is still valid and refreshes if needed
// This should be called before making API requests that require authentication
func EnsureTokenValid(ctx context.Context, cfg *config.PigeonHoleConfig, client *sdk.ClientWithResponses, clientID string, provider *sdk.OIDCProvider) error {
	if cfg == nil || cfg.API == nil || cfg.API.AccessToken == nil {
		return fmt.Errorf("not authenticated - no access token found")
	}

	// Check if token is near expiry
	if !cfg.IsTokenNearExpiry() {
		logrus.Debugf("Token is still valid, no refresh needed")
		return nil
	}

	logrus.Debugf("Token is near expiry, attempting to refresh")

	// Try to refresh the token using the IdP refresh token
	if cfg.CanRefresh() {
		err := RefreshToken(ctx, cfg, clientID, provider)
		if err != nil {
			logrus.Debugf("Failed to refresh IdP token: %v", err)
			return fmt.Errorf("token refresh failed: %w", err)
		}

		// Now exchange the new IdP token for a new PigeonHole JWT
		// We need to get the new token from the IdP again
		newIdpToken, err := authenticateWithRefreshToken(ctx, cfg, clientID, provider)
		if err != nil {
			return fmt.Errorf("failed to get new IdP token: %w", err)
		}

		err = RefreshPigeonHoleToken(ctx, cfg, client, newIdpToken)
		if err != nil {
			return fmt.Errorf("failed to refresh PigeonHole token: %w", err)
		}

		logrus.Debugf("Token refreshed successfully")
		return nil
	}

	return fmt.Errorf("token expired and no refresh token available")
}

// authenticateWithRefreshToken uses the stored refresh token to get a new IdP token
func authenticateWithRefreshToken(ctx context.Context, cfg *config.PigeonHoleConfig, clientID string, provider *sdk.OIDCProvider) (*oauth2.Token, error) {
	if cfg == nil || cfg.API == nil || cfg.API.RefreshToken == nil || *cfg.API.RefreshToken == "" {
		return nil, fmt.Errorf("no refresh token available")
	}

	// Extract audience from PigeonHole API URL
	var audience string
	if cfg != nil && cfg.API != nil && cfg.API.Url != nil && *cfg.API.Url != "" {
		if parsedURL, err := url.Parse(*cfg.API.Url); err == nil {
			audience = parsedURL.Scheme + "://" + parsedURL.Host
			logrus.Debugf("Using audience for token refresh: %s", audience)
		} else {
			logrus.Warnf("Failed to parse API URL for audience: %v", err)
		}
	}

	conf := &oauth2.Config{
		ClientID: clientID,
		Endpoint: oauth2.Endpoint{
			TokenURL: *provider.TokenUrl,
		},
		Scopes: *provider.Scopes,
	}

	// For audience parameter on token endpoint, we need to pass it through context
	// or modify the TokenURL. We'll append it as a query parameter to TokenURL
	tokenURL := *provider.TokenUrl
	if audience != "" {
		separator := "?"
		if parsedURL, err := url.Parse(tokenURL); err == nil {
			if parsedURL.RawQuery != "" {
				separator = "&"
			}
		}
		tokenURL = tokenURL + separator + "audience=" + url.QueryEscape(audience)
	}

	conf.Endpoint.TokenURL = tokenURL

	tokenSource := conf.TokenSource(ctx, &oauth2.Token{
		RefreshToken: *cfg.API.RefreshToken,
	})

	return tokenSource.Token()
}
