package sdk

import (
	"context"
	"time"

	"github.com/deepmap/oapi-codegen/pkg/securityprovider"
)

// func WithBearerToken(token string) RequestEditorFn {
// 	return func(req *http.Request) error {
// 		req.Header.Set("Authorization", "Bearer "+token)
// 		return nil
// 	}
// }

// func NewPigeonholeClient(server string, token string) *Client {
// 	client := &Client{
// 		Server:         server,
// 		RequestEditors: []RequestEditorFn{WithBearerToken(token)},
// 	}

// 	return client
// }

func PigeonholeClient(server string, token string) (ClientWithResponses, context.Context) {
	bearerTokenProvider, bearerTokenProviderErr := securityprovider.NewSecurityProviderBearerToken(token)
	if bearerTokenProviderErr != nil {
		panic(bearerTokenProviderErr)
	}
	x, _ := NewClientWithResponses(server, WithRequestEditorFn(bearerTokenProvider.Intercept))

	ctx, _ := context.WithTimeout(context.Background(), time.Duration(time.Second*5))
	return *x, ctx
}
