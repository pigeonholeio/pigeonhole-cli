package sdk

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
)

// func (c *ClientWithResponses) PostAuthOidcCleverHandlerWithResponse(ctx context.Context, provider *OIDCProvider, idPToken *OIDCProviderToken, reqEditors ...RequestEditorFn) (*PostAuthOidcHandlerGenericResponse, error) {
// 	rsp, err := c.PostAuthOidcCleverHandler(ctx, provider, idPToken, reqEditors...)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return ParsePostAuthOidcCleverHandlerResponse(rsp)
// }

// PostAuthOidcHandlerGenericJSONRequestBody
func (c *Client) PostAuthOidcCleverHandler(ctx context.Context, provider *OIDCProvider, idPToken *OIDCProviderToken, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewPostAuthOidcCleverHandlerRequest(provider, idPToken)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

type PostAuthOidcCleverHandlerJSONRequestBody = OIDCProviderToken

// type PostAuthOidcHandlerGenericJSONRequestBody = OIDCProviderToken
func NewPostAuthOidcCleverHandlerRequest(provider *OIDCProvider, idPToken *OIDCProviderToken) (*http.Request, error) {
	var bodyReader io.Reader

	buf, err := json.Marshal(idPToken)
	if err != nil {
		return nil, err
	}
	bodyReader = bytes.NewReader(buf)
	return NewPostAuthOidcCleverHandlerRequestWithBody(provider, "application/json", bodyReader)
}

// NewPostAuthOidcHandlerGenericRequestWithBody generates requests for PostAuthOidcHandlerGeneric with any type of body
func NewPostAuthOidcCleverHandlerRequestWithBody(provider *OIDCProvider, contentType string, body io.Reader) (*http.Request, error) {
	var err error

	handlerUrl, err := url.Parse(*provider.HandlerUrl)

	req, err := http.NewRequest("POST", handlerUrl.String(), body)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", contentType)

	return req, nil
}

// PostAuthOidcHandlerGenericResponse
// ParsePostAuthOidcHandlerGenericResponse parses an HTTP response from a PostAuthOidcHandlerGenericWithResponse call
// func ParsePostAuthOidcCleverHandlerResponse(rsp *http.Response) (*PostAuthOidcHandlerGenericResponse, error) {
// 	bodyBytes, err := io.ReadAll(rsp.Body)
// 	defer func() { _ = rsp.Body.Close() }()
// 	if err != nil {
// 		return nil, err
// 	}

// 	response := &PostAuthOidcHandlerGenericResponse{
// 		Body:         bodyBytes,
// 		HTTPResponse: rsp,
// 	}

// 	switch {
// 	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 201:
// 		var dest GeneralMessageWithTokenResponse
// 		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
// 			return nil, err
// 		}
// 		response.JSON201 = &dest

// 	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 400:
// 		var dest GeneralMessage
// 		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
// 			return nil, err
// 		}
// 		response.JSON400 = &dest

// 	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 401:
// 		var dest GeneralMessage
// 		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
// 			return nil, err
// 		}
// 		response.JSON401 = &dest

// 	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 403:
// 		var dest GeneralMessage
// 		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
// 			return nil, err
// 		}
// 		response.JSON403 = &dest

// 	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 500:
// 		var dest GeneralMessage
// 		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
// 			return nil, err
// 		}
// 		response.JSON500 = &dest

// 	}

// 	return response, nil
// }
