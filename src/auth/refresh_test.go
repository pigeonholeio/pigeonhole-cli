package auth

import (
	"context"
	"testing"
	"time"

	"github.com/pigeonholeio/pigeonhole-cli/config"
	"golang.org/x/oauth2"
)

func TestRefreshToken(t *testing.T) {
	tests := []struct {
		name      string
		cfg       *config.PigeonHoleConfig
		clientID  string
		expectErr bool
	}{
		{
			name: "no refresh token available",
			cfg: &config.PigeonHoleConfig{
				API: &config.ApiConfig{},
			},
			clientID:  "test-client",
			expectErr: true,
		},
		{
			name: "empty refresh token",
			cfg: &config.PigeonHoleConfig{
				API: &config.ApiConfig{
					RefreshToken: stringPtr(""),
				},
			},
			clientID:  "test-client",
			expectErr: true,
		},
		{
			name: "nil config",
			cfg:  nil,
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test with invalid/mock provider (just testing error handling)
			err := RefreshToken(context.Background(), tt.cfg, tt.clientID, nil)
			if (err != nil) != tt.expectErr {
				t.Errorf("RefreshToken() error = %v, expectErr %v", err, tt.expectErr)
			}
		})
	}
}

func TestIsTokenExpiredFromConfig(t *testing.T) {
	tests := []struct {
		name           string
		tokenExpiry    *int64
		expectedResult bool
	}{
		{
			name:           "token expired (past time)",
			tokenExpiry:    int64Ptr(time.Now().Unix() - 100),
			expectedResult: true,
		},
		{
			name:           "token not expired (future time)",
			tokenExpiry:    int64Ptr(time.Now().Unix() + 3600),
			expectedResult: false,
		},
		{
			name:           "token nil",
			tokenExpiry:    nil,
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.PigeonHoleConfig{
				API: &config.ApiConfig{
					TokenExpiry: tt.tokenExpiry,
				},
			}
			result := cfg.IsTokenExpired()
			if result != tt.expectedResult {
				t.Errorf("IsTokenExpired() = %v, want %v", result, tt.expectedResult)
			}
		})
	}
}

func TestIsTokenNearExpiryFromConfig(t *testing.T) {
	tests := []struct {
		name           string
		tokenExpiry    *int64
		expectedResult bool
		description    string
	}{
		{
			name:           "token expiring in 1 minute",
			tokenExpiry:    int64Ptr(time.Now().Add(1 * time.Minute).Unix()),
			expectedResult: true,
			description:    "should return true for token expiring within 5 minutes",
		},
		{
			name:           "token expiring in 3 minutes",
			tokenExpiry:    int64Ptr(time.Now().Add(3 * time.Minute).Unix()),
			expectedResult: true,
			description:    "should return true for token expiring within 5 minutes",
		},
		{
			name:           "token expiring in 10 minutes",
			tokenExpiry:    int64Ptr(time.Now().Add(10 * time.Minute).Unix()),
			expectedResult: false,
			description:    "should return false for token expiring after 5 minutes",
		},
		{
			name:           "token already expired",
			tokenExpiry:    int64Ptr(time.Now().Unix() - 100),
			expectedResult: true,
			description:    "should return true for expired token",
		},
		{
			name:           "token nil",
			tokenExpiry:    nil,
			expectedResult: false,
			description:    "should return false for nil token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.PigeonHoleConfig{
				API: &config.ApiConfig{
					TokenExpiry: tt.tokenExpiry,
				},
			}
			result := cfg.IsTokenNearExpiry()
			if result != tt.expectedResult {
				t.Errorf("IsTokenNearExpiry() = %v, want %v. %s", result, tt.expectedResult, tt.description)
			}
		})
	}
}

func TestCanRefreshFromConfig(t *testing.T) {
	tests := []struct {
		name           string
		refreshToken   *string
		expectedResult bool
	}{
		{
			name:           "valid refresh token",
			refreshToken:   stringPtr("valid_token_abc123"),
			expectedResult: true,
		},
		{
			name:           "empty refresh token",
			refreshToken:   stringPtr(""),
			expectedResult: false,
		},
		{
			name:           "nil refresh token",
			refreshToken:   nil,
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.PigeonHoleConfig{
				API: &config.ApiConfig{
					RefreshToken: tt.refreshToken,
				},
			}
			result := cfg.CanRefresh()
			if result != tt.expectedResult {
				t.Errorf("CanRefresh() = %v, want %v", result, tt.expectedResult)
			}
		})
	}
}

// Mock OAuth2 Token for testing
func createMockToken(accessToken string, refreshToken string, expiresIn time.Duration) *oauth2.Token {
	return &oauth2.Token{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(expiresIn),
	}
}

// Helper functions
func int64Ptr(i int64) *int64 {
	return &i
}

func stringPtr(s string) *string {
	return &s
}
