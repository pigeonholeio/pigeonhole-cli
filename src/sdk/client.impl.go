package sdk

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/oapi-codegen/oapi-codegen/v2/pkg/securityprovider"
	"github.com/pigeonholeio/pigeonhole-cli/config"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

// func PigeonholeClient(cfg *config.PigeonHoleConfig) ClientWithResponses {
// 	bearerTokenProvider, bearerTokenProviderErr := securityprovider.NewSecurityProviderBearerToken(cfg.API.AccessToken)
// 	if bearerTokenProviderErr != nil {
// 		panic(bearerTokenProviderErr)
// 	}

// 	x, _ := NewClientWithResponses(cfg.API.Url, WithRequestEditorFn(bearerTokenProvider.Intercept))

//		return *x
//	}

type HumanTime time.Time

func (ht HumanTime) MarshalYAML() (interface{}, error) {
	t := time.Time(ht)
	// Emit a YAML timestamp node instead of a string
	node := yaml.Node{
		Kind: yaml.ScalarNode,

		Tag:   "!!timestamp",
		Value: t.Format("2006-01-02 15:04:05"),
	}
	return &node, nil
}

func ToSecretView(s Secret) SecretView {
	size := humanize.Bytes(uint64(*s.Size))
	return SecretView{
		Reference:  s.Reference,
		Size:       &size,
		Sent:       (*HumanTime)(s.SentAt),
		Recipient:  s.Recipient,
		Sender:     s.Sender,
		OneTime:    s.Onetime,
		Expiration: (*HumanTime)(s.Expiration),

		// SentAt:     HumanTime(*s.SentAt),
		// UploadedAt: HumanTime(s.UploadedAt),
	}
}

func ToSecretViewSlice(secrets []Secret) []SecretView {
	views := make([]SecretView, len(secrets))
	for i, s := range secrets {
		views[i] = ToSecretView(s)
	}
	return views
}

// SecretView defines model for SecretView.
type SecretView struct {
	Reference  *string    `json:"reference,omitempty"`
	Sent       *HumanTime `json:"sent_at,omitempty"`
	Expiration *HumanTime `json:"expiration,omitempty"`
	Recipient  *string    `json:"recipient,omitempty"`
	Sender     *string    `json:"sender,omitempty"`
	Size       *string    `json:"size,omitempty"`
	OneTime    *bool      `json:"onetime,omitempty"`
}

func PigeonholeClient(cfg *config.PigeonHoleConfig, version string) *ClientWithResponses {
	// Set up transport with TLS 1.3 if HTTPS
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if strings.HasPrefix(*cfg.API.Url, "https://") {
		transport.TLSClientConfig = &tls.Config{
			MinVersion: tls.VersionTLS13,
		}
	}

	// Configure connection pooling and timeouts
	transport.MaxIdleConns = 100
	transport.MaxIdleConnsPerHost = 10
	transport.IdleConnTimeout = 60 * time.Second
	transport.DisableKeepAlives = true // Disable connection reuse to avoid idle timeout issues during user input

	// Create a base HTTP client
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   90 * time.Second, // Extended timeout to allow for user input delays
	}
	reqEditor := func(ctxReq context.Context, req *http.Request) error {
		logrus.Debugf("Making %s request to %s", req.Method, req.URL)
		req.Header.Set("User-Agent", fmt.Sprintf("pigeonhole-cli/%s-%s/%s", runtime.GOOS, runtime.GOARCH, version))
		return nil
	}

	if cfg != nil && cfg.API != nil && cfg.API.AccessToken != nil {
		_, err := securityprovider.NewSecurityProviderBearerToken(*cfg.API.AccessToken)
		if err != nil {
			logrus.Fatalf("failed to create bearer token provider: %v", err)
			return nil
		}
		reqEditor = func(ctxReq context.Context, req *http.Request) error {
			logrus.Debugf("Making %s request to %s", req.Method, req.URL)

			// Check if token needs refresh (proactive approach)
			if cfg.IsTokenNearExpiry() {
				logrus.Debugf("Token is near expiry, attempting refresh before request")
				// Note: Token refresh will be handled at a higher level in the command execution
				// This is just a warning/logging point
			}

			// Update bearer token provider with current token in case it was refreshed
			bearerTokenProvider, err := securityprovider.NewSecurityProviderBearerToken(*cfg.API.AccessToken)
			if err != nil {
				return fmt.Errorf("failed to create bearer token provider: %w", err)
			}

			if err := bearerTokenProvider.Intercept(ctxReq, req); err != nil {
				return err
			}
			req.Header.Set("User-Agent", fmt.Sprintf("pigeonhole-cli/%s-%s/%s", runtime.GOOS, runtime.GOARCH, version))
			return nil
		}
	}

	client, err := NewClientWithResponses(
		*cfg.API.Url,
		WithHTTPClient(httpClient),
		WithRequestEditorFn(reqEditor),
	)
	if err != nil {
		logrus.Fatalf("failed to create pigeonhole client: %v", err)
		return nil
	}
	return client

	// if err != nil {
	// 	logrus.Panicf("failed to create pigeonhole client: %v", err)
	// }
	// return client
}

func GetUserGPGArmoredPubKeysFromIdSlice(ctx *context.Context, secretEnvelopeResponse *SecretEnvelopeResponse) ([]string, error) {
	if *secretEnvelopeResponse.Users == nil {
		return nil, fmt.Errorf("no users found on Secret Envelope")
	}
	var keys []string
	for _, x := range *secretEnvelopeResponse.Users {

		if x.Keys != nil && len(*x.Keys) > 0 {
			for _, k := range *x.Keys {

				decoded, _ := base64.StdEncoding.DecodeString(*k.KeyData)
				keys = append(keys, string(decoded))
			}
		} else {
			return nil, fmt.Errorf("aborting - no public key found for %s", *x.Email)
		}
	}

	return keys, nil
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
