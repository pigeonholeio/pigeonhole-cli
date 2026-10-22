package nx

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// Base returns the API base URL (override with PIGEONHOLE_API).
func Base() string {
	if v := os.Getenv("PIGEONHOLE_API"); v != "" {
		return v
	}
	return "https://api.pigeono.io"
}

var httpc = &http.Client{Timeout: 120 * time.Second}

func do(method, url, token string, body io.Reader, ctype string) (*http.Response, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	return httpc.Do(req)
}

func jsonReq(method, path, token string, payload any) (map[string]any, int, error) {
	var buf io.Reader
	if payload != nil {
		b, _ := json.Marshal(payload)
		buf = bytes.NewReader(b)
	}
	resp, err := do(method, Base()+path, token, buf, "application/json")
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &out)
	}
	return out, resp.StatusCode, nil
}

// Enroll registers email+device public key and returns an access token.
func Enroll(email, pubKey, thumbprint, masterKey string) (string, error) {
	out, code, err := jsonReq("POST", "/auth/enroll", "", map[string]any{
		"email": email, "public_key": pubKey, "thumbprint": thumbprint, "master_key": masterKey,
	})
	if err != nil {
		return "", err
	}
	if code != 201 && code != 200 {
		return "", fmt.Errorf("enroll failed (%d): %v", code, out["message"])
	}
	tok, _ := out["accessToken"].(string)
	if tok == "" {
		return "", fmt.Errorf("no token returned")
	}
	return tok, nil
}

// LookupKeys returns a recipient's active device public keys (armored).
func LookupKeys(token, email string) ([]string, error) {
	out, code, err := jsonReq("GET", "/user/lookup?email="+email, token, nil)
	if err != nil {
		return nil, err
	}
	if code == 404 {
		return nil, fmt.Errorf("recipient %s has no PigeonHole account yet", email)
	}
	if code != 200 {
		return nil, fmt.Errorf("lookup failed (%d): %v", code, out["message"])
	}
	keys := []string{}
	if arr, ok := out["keys"].([]any); ok {
		for _, k := range arr {
			if m, ok := k.(map[string]any); ok {
				if kd, ok := m["key_data"].(string); ok && kd != "" {
					keys = append(keys, kd)
				}
			}
		}
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("recipient %s has no usable keys", email)
	}
	return keys, nil
}

// CreateSecret opens an upload envelope; returns secret id, reference, body PUT url.
func CreateSecret(token string, recipients []string, size int64, onetime bool) (id, ref, bodyPutURL string, err error) {
	out, code, err := jsonReq("POST", "/secret", token, map[string]any{
		"recipient_ids": recipients, "reference": "", "total_payload_size": size, "onetime": onetime,
	})
	if err != nil {
		return "", "", "", err
	}
	if code != 201 {
		return "", "", "", fmt.Errorf("create secret failed (%d): %v", code, out["message"])
	}
	id, _ = out["secret_id"].(string)
	ref, _ = out["reference"].(string)
	if up, ok := out["upload"].(map[string]any); ok {
		if b, ok := up["body"].(map[string]any); ok {
			bodyPutURL, _ = b["url"].(string)
		}
	}
	if bodyPutURL == "" {
		return "", "", "", fmt.Errorf("no upload url returned")
	}
	return id, ref, bodyPutURL, nil
}

// PutBody streams the ciphertext to the capability URL.
func PutBody(bodyPutURL string, data []byte) error {
	resp, err := do("PUT", bodyPutURL, "", bytes.NewReader(data), "application/octet-stream")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 201 && resp.StatusCode != 200 {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("upload failed (%d): %s", resp.StatusCode, string(raw))
	}
	return nil
}

// SecretMeta is a listed secret.
type SecretMeta struct {
	ID        string `json:"id"`
	Reference string `json:"reference"`
	Onetime   bool   `json:"onetime"`
	Uploaded  bool   `json:"uploaded"`
}

// List returns the caller's secrets (optionally filtered by reference).
func List(token, reference string) ([]SecretMeta, error) {
	path := "/secret"
	if reference != "" {
		path += "?reference=" + reference
	}
	out, code, err := jsonReq("GET", path, token, nil)
	if err != nil {
		return nil, err
	}
	if code != 200 {
		return nil, fmt.Errorf("list failed (%d): %v", code, out["message"])
	}
	var metas []SecretMeta
	if arr, ok := out["secrets"].([]any); ok {
		for _, s := range arr {
			b, _ := json.Marshal(s)
			var m SecretMeta
			_ = json.Unmarshal(b, &m)
			metas = append(metas, m)
		}
	}
	return metas, nil
}

// Download resolves a secret's body and returns the ciphertext bytes.
func Download(token, id string) ([]byte, error) {
	out, code, err := jsonReq("GET", "/secret/"+id+"/download", token, nil)
	if err != nil {
		return nil, err
	}
	if code == 410 {
		return nil, fmt.Errorf("secret already consumed (onetime)")
	}
	if code != 200 {
		return nil, fmt.Errorf("download failed (%d): %v", code, out["message"])
	}
	bodyURL := ""
	if b, ok := out["body"].(map[string]any); ok {
		bodyURL, _ = b["url"].(string)
	}
	if bodyURL == "" {
		return nil, fmt.Errorf("no body url")
	}
	resp, err := do("GET", bodyURL, "", nil, "")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("body fetch failed (%d)", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}
