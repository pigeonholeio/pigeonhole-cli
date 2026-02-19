package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pigeonholeio/common/utils"
	"github.com/pigeonholeio/pigeonhole-cli/config"
	"github.com/pigeonholeio/pigeonhole-cli/sdk"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
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

	// Update access token with the new one
	cfg.API.AccessToken = &newToken.AccessToken

	// Extract and update token expiry
	if claims, err := utils.DecodePigeonHoleJWT(newToken.AccessToken); err == nil {
		if exp, ok := claims["exp"]; ok {
			if expFloat, ok := exp.(float64); ok {
				expInt64 := int64(expFloat)
				cfg.API.TokenExpiry = &expInt64
				logrus.Debugf("Token expiry updated: %d (expires at %s)", expInt64, time.Unix(expInt64, 0))
			}
		}
	} else {
		logrus.Debugf("Failed to decode new token claims: %v", err)
	}

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

// OIDCDiscoveryDocument represents the OIDC well-known configuration
type OIDCDiscoveryDocument struct {
	Issuer                      string   `json:"issuer"`
	AuthorizationEndpoint       string   `json:"authorization_endpoint"`
	TokenEndpoint               string   `json:"token_endpoint"`
	DeviceAuthorizationEndpoint string   `json:"device_authorization_endpoint"`
	UserinfoEndpoint            string   `json:"userinfo_endpoint"`
	JwksUri                     string   `json:"jwks_uri"`
	ScopesSupported             []string `json:"scopes_supported"`
}

// DiscoverProviderFromIssuer fetches OIDC configuration from issuer's well-known endpoint
func DiscoverProviderFromIssuer(ctx context.Context, issuer string) (*sdk.OIDCProvider, error) {
	// Normalize issuer (remove trailing slash)
	issuer = strings.TrimSuffix(issuer, "/")

	// Build well-known URL
	wellKnownURL := fmt.Sprintf("%s/.well-known/openid-configuration", issuer)
	logrus.Debugf("Fetching OIDC configuration from: %s", wellKnownURL)

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "GET", wellKnownURL, nil)
	if err != nil {
		return nil, err
	}

	// Execute request with timeout
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch OIDC configuration: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OIDC discovery returned status %d", resp.StatusCode)
	}

	// Parse response
	var discovery OIDCDiscoveryDocument
	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		return nil, fmt.Errorf("failed to decode OIDC configuration: %w", err)
	}

	// Build OIDCProvider
	scopes := discovery.ScopesSupported
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}

	provider := &sdk.OIDCProvider{
		Name:          &issuer,
		AuthUrl:       &discovery.AuthorizationEndpoint,
		TokenUrl:      &discovery.TokenEndpoint,
		DeviceAuthURL: &discovery.DeviceAuthorizationEndpoint,
		Scopes:        &scopes,
	}

	return provider, nil
}

// ValidateAndRefreshToken checks if the access token is valid and refreshes it if needed
func ValidateAndRefreshToken(ctx context.Context, cfg *config.PigeonHoleConfig, fullConfigPath string) error {
	// Check if access token exists
	if cfg == nil || cfg.API == nil || cfg.API.AccessToken == nil || *cfg.API.AccessToken == "" {
		return fmt.Errorf("not authenticated - please run 'pigeonhole login'")
	}

	// Decode JWT to check claims
	claims, err := utils.DecodePigeonHoleJWT(*cfg.API.AccessToken)
	if err != nil {
		return fmt.Errorf("invalid token format: %w", err)
	}

	// Extract expiry and check if token is valid
	exp, ok := claims["exp"].(float64)
	if !ok {
		return fmt.Errorf("no expiry claim in token")
	}

	expiryTime := time.Unix(int64(exp), 0)

	// If token is not expired and not near expiry (5 minutes), return success
	if time.Now().Before(expiryTime.Add(-5 * time.Minute)) {
		logrus.Debugf("Token is valid until %s", expiryTime)
		return nil
	}

	logrus.Debugf("Token is expired or near expiry, attempting refresh")

	// Token is expired or near expiry - attempt refresh
	if cfg.API.RefreshToken == nil || *cfg.API.RefreshToken == "" {
		return fmt.Errorf("token expired and no refresh token available - please run 'pigeonhole login'")
	}

	// Extract issuer from JWT to discover provider configuration
	issuer, ok := claims["iss"].(string)
	if !ok || issuer == "" {
		return fmt.Errorf("no issuer claim in token")
	}

	// Discover provider configuration from issuer's well-known endpoint
	provider, err := DiscoverProviderFromIssuer(ctx, issuer)
	if err != nil {
		return fmt.Errorf("failed to discover IdP configuration: %w", err)
	}

	// Extract client ID from JWT claims
	clientID := "pigeonhole-cli"
	if aud, ok := claims["azp"].(string); ok && aud != "" {
		clientID = aud
		logrus.Debugf("Using authorized party (azp) as client ID: %s", clientID)
	} else if aud, ok := claims["aud"].(string); ok && aud != "" {
		clientID = aud
		logrus.Debugf("Using audience (aud) as client ID: %s", clientID)
	}

	// Perform token refresh
	err = RefreshToken(ctx, cfg, clientID, provider)
	if err != nil {
		return fmt.Errorf("token refresh failed: %w\nPlease run 'pigeonhole login' to re-authenticate", err)
	}

	// Update config file with new tokens
	v := viper.New()
	err = cfg.Save(v, &fullConfigPath)
	if err != nil {
		logrus.Warnf("Failed to save refreshed token to config: %v", err)
		// Don't fail if we can't save - the token is still valid in memory
	}

	logrus.Debugf("Token refreshed successfully and saved to config")
	return nil
}
