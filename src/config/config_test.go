package config

import (
	"testing"
	"time"
)

func TestIsTokenExpired(t *testing.T) {
	tests := []struct {
		name     string
		cfg      *PigeonHoleConfig
		expected bool
	}{
		{
			name: "nil config",
			cfg:  nil,
			expected: false,
		},
		{
			name: "nil API",
			cfg:  &PigeonHoleConfig{},
			expected: false,
		},
		{
			name: "nil TokenExpiry",
			cfg: &PigeonHoleConfig{
				API: &ApiConfig{},
			},
			expected: false,
		},
		{
			name: "token expired",
			cfg: &PigeonHoleConfig{
				API: &ApiConfig{
					TokenExpiry: intPtr(time.Now().Unix() - 100),
				},
			},
			expected: true,
		},
		{
			name: "token not expired",
			cfg: &PigeonHoleConfig{
				API: &ApiConfig{
					TokenExpiry: intPtr(time.Now().Unix() + 3600),
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.cfg.IsTokenExpired()
			if result != tt.expected {
				t.Errorf("IsTokenExpired() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestIsTokenNearExpiry(t *testing.T) {
	tests := []struct {
		name     string
		cfg      *PigeonHoleConfig
		expected bool
	}{
		{
			name:     "nil config",
			cfg:      nil,
			expected: false,
		},
		{
			name: "nil API",
			cfg:  &PigeonHoleConfig{},
			expected: false,
		},
		{
			name: "nil TokenExpiry",
			cfg: &PigeonHoleConfig{
				API: &ApiConfig{},
			},
			expected: false,
		},
		{
			name: "token expiring in 1 minute",
			cfg: &PigeonHoleConfig{
				API: &ApiConfig{
					TokenExpiry: intPtr(time.Now().Add(1 * time.Minute).Unix()),
				},
			},
			expected: true,
		},
		{
			name: "token expiring in 10 minutes",
			cfg: &PigeonHoleConfig{
				API: &ApiConfig{
					TokenExpiry: intPtr(time.Now().Add(10 * time.Minute).Unix()),
				},
			},
			expected: false,
		},
		{
			name: "token already expired",
			cfg: &PigeonHoleConfig{
				API: &ApiConfig{
					TokenExpiry: intPtr(time.Now().Unix() - 100),
				},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.cfg.IsTokenNearExpiry()
			if result != tt.expected {
				t.Errorf("IsTokenNearExpiry() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestCanRefresh(t *testing.T) {
	tests := []struct {
		name     string
		cfg      *PigeonHoleConfig
		expected bool
	}{
		{
			name:     "nil config",
			cfg:      nil,
			expected: false,
		},
		{
			name: "nil API",
			cfg:  &PigeonHoleConfig{},
			expected: false,
		},
		{
			name: "nil RefreshToken",
			cfg: &PigeonHoleConfig{
				API: &ApiConfig{},
			},
			expected: false,
		},
		{
			name: "empty RefreshToken",
			cfg: &PigeonHoleConfig{
				API: &ApiConfig{
					RefreshToken: stringPtr(""),
				},
			},
			expected: false,
		},
		{
			name: "valid RefreshToken",
			cfg: &PigeonHoleConfig{
				API: &ApiConfig{
					RefreshToken: stringPtr("valid_refresh_token"),
				},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.cfg.CanRefresh()
			if result != tt.expected {
				t.Errorf("CanRefresh() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// Helper functions
func intPtr(i int64) *int64 {
	return &i
}

func stringPtr(s string) *string {
	return &s
}
