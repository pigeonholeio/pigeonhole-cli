package sdk

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/deepmap/oapi-codegen/pkg/securityprovider"
	"github.com/pigeonholeio/pigeonhole-cli/config"
	"github.com/sirupsen/logrus"
)

// func PigeonholeClient(cfg *config.PigeonHoleConfig) ClientWithResponses {
// 	bearerTokenProvider, bearerTokenProviderErr := securityprovider.NewSecurityProviderBearerToken(cfg.API.AccessToken)
// 	if bearerTokenProviderErr != nil {
// 		panic(bearerTokenProviderErr)
// 	}

// 	x, _ := NewClientWithResponses(cfg.API.Url, WithRequestEditorFn(bearerTokenProvider.Intercept))

//		return *x
//	}
func PigeonholeClient(cfg *config.PigeonHoleConfig) *ClientWithResponses {
	// Create a bearer token provider
	bearerTokenProvider, err := securityprovider.NewSecurityProviderBearerToken(cfg.API.AccessToken)
	if err != nil {
		logrus.Panicf("failed to create bearer token provider: %v", err)
	}

	// Set up transport with TLS 1.3 if HTTPS
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if strings.HasPrefix(cfg.API.Url, "https://") {
		transport.TLSClientConfig = &tls.Config{
			MinVersion: tls.VersionTLS13,
		}
	}

	// Create a base HTTP client
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second, // default per-request timeout
	}

	// Initialize the SDK client
	client, err := NewClientWithResponses(
		cfg.API.Url,
		WithHTTPClient(httpClient),
		WithRequestEditorFn(func(ctxReq context.Context, req *http.Request) error {
			logrus.Debugf("Making %s request to %s", req.Method, req.URL)
			if err := bearerTokenProvider.Intercept(ctxReq, req); err != nil {
				return err
			}
			req.Header.Set("X-Client", "pigeonhole-cli")
			return nil
		}),
	)
	if err != nil {
		logrus.Panicf("failed to create pigeonhole client: %v", err)
	}
	return client
}

func GetUserGPGArmoredPubKeysFromIdSlice(ctx context.Context, pigeonholeClient *ClientWithResponses, recipients []string) ([]string, error) {
	params := GetUserParams{}
	params.Id = &recipients
	users, _ := pigeonholeClient.GetUserWithResponse(ctx, &params)
	var keys []string
	for _, x := range *users.JSON200 {
		if len(*x.Keys) > 0 {
			for _, k := range *x.Keys {
				decoded, _ := base64.StdEncoding.DecodeString(*k.KeyData)
				keys = append(keys, string(decoded))
			}

		}
	}
	if len(keys) > 0 {
		return keys, nil
	} else {
		return nil, fmt.Errorf("No keys for recipients")
	}
}

// func NewPostAuthOidcHandlerWithBodyRequest(contentType, provider *OIDCProvider, body io.Reader) (*http.Request, error) {
// 	var err error

// 	endpoint, err := url.Parse(*provider.HandlerUrl)
// 	if err != nil {
// 		return nil, err
// 	}

// 	return NewPostAuthOidcHandlerGenericRequestWithBody(endpoint.String(), "application/json", bodyReader)

// 	req, err := http.NewRequest("POST", endpoint.String(), body)
// 	if err != nil {
// 		return nil, err
// 	}

// 	req.Header.Add("Content-Type", contentType)

//		return req, nil
//	}

// AuthTokenPostWithResponse request returning *AuthTokenPostResponse

//	func (c *Client) UserIdKeyIdDeleteWithBody(ctx context.Context, userId string, keyId string, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error) {
//		req, err := NewUserIdKeyIdDeleteRequestWithBody(c.Server, userId, keyId, contentType, body)
//		if err != nil {
//			return nil, err
//		}
//		req = req.WithContext(ctx)
//		if err := c.applyEditors(ctx, req, reqEditors); err != nil {
//			return nil, err
//		}
//		return c.Client.Do(req)
//	}
// func (c *ClientWithResponses) PostAuthOidcHandlerGeneric(ctx context.Context, provider *OIDCProvider, idPToken *OIDCProviderToken) (*PostAuthOidcHandlerGenericResponse, error) {
// 	return nil, nil
// }

// 	var bodyReader io.Reader

// 	buf, err := json.Marshal(body)
// 	if err != nil {
// 		return nil, err
// 	}
// 	bodyReader = bytes.NewReader(buf)
// 	rsp, err := NewPostAuthOidcHandlerWithBodyRequest(contentType, provider, bodyReader)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return ParsePostAuthOidcHandlerGenericResponse(rsp)
// }

func GenerateKeys(ctx *context.Context, pigeonHoleClient *ClientWithResponses) error {
	fmt.Print("Creating and pushing your new GPG key...")
	return nil
	// if viper.GetString("auth.token") == "" {
	// 	return fmt.Errorf("not logged in")
	// }

	// claims, _ := utils.DecodePigeonHoleJWT()
	// for k, v := range claims {
	// 	logrus.Debugf("JWT claim: %s = %v", k, v)
	// }

	// pub, priv, _, thumbprint := CreateGPGKey(
	// 	claims["name"].(string),
	// 	claims["preferred_username"].(string),
	// )

	// b64Priv := EncodeToBase64(priv)
	// b64Pub := EncodeToBase64(pub)

	// viper.Set("key.latest.public", b64Pub)
	// viper.Set("key.latest.private", b64Priv)

	// only := true
	// ref, _ := os.Hostname()

	// req := sdk.NewKey{
	// 	KeyData:    &b64Pub,
	// 	Reference:  &ref,
	// 	Only:       &only,
	// 	Force:      &only,
	// 	Thumbprint: &thumbprint,
	// }

	// // GlobalPigeonHoleClient, GlobalCtx = NewPigeonHoleClient()
	// resp, err := pigeonHoleClient.PostUserMeKeyWithResponse(*ctx, req)
	// if err != nil {
	// 	return err
	// }

	// logrus.Debugf("Pigeonhole API returned status: %d", resp.StatusCode())

	// if resp.StatusCode() == 201 {
	// 	if err := viper.WriteConfig(); err != nil {
	// 		return fmt.Errorf("failed to write config: %w", err)
	// 	}
	// 	fmt.Println("done!")
	// 	return nil
	// }

	// // Map status codes to messages using a single switch
	// var msg string
	// switch resp.StatusCode() {
	// // case 400:
	// // 	msg = resp.JSON400.Message
	// // case 401:
	// // 	msg = resp.JSON201
	// // case 403:
	// // 	msg = resp.JSON403.Message
	// // case 500:
	// // 	msg = resp.JSON500.Message
	// default:
	// 	msg = "unexpected status code"
	// }

	// return fmt.Errorf("failed: %s (%d)", msg, resp.StatusCode())
}
