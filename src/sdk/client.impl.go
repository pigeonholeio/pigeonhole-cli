package sdk

import (
	"context"
	"net"
	"net/http"
	"time"

	"github.com/deepmap/oapi-codegen/pkg/securityprovider"
)

func PigeonholeClient(server, token string) (ClientWithResponses, context.Context) {
	// Create a security provider for the bearer token
	bearerTokenProvider, err := securityprovider.NewSecurityProviderBearerToken(token)
	if err != nil {
		panic(err)
	}

	httpClient := &http.Client{
		Timeout: 0,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}

	// Initialize the API client with the HTTP client and security provider
	client, err := NewClientWithResponses(server,
		WithRequestEditorFn(bearerTokenProvider.Intercept),
		WithHTTPClient(httpClient), // Use the custom HTTP client
	)
	if err != nil {
		panic(err)
	}

	// Create a context with a default timeout
	ctx, _ := context.WithTimeout(context.Background(), 30*time.Second)

	return *client, ctx
}
