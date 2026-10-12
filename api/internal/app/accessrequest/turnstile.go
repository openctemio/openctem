package accessrequest

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/httpsec"
)

// turnstileVerifyURL is Cloudflare Turnstile's server-side check.
const turnstileVerifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

// Turnstile verifies Cloudflare Turnstile tokens (CAPTCHA_TURNSTILE_SECRET).
type Turnstile struct {
	secret string
	url    string
	client *http.Client
}

// NewTurnstile returns a verifier, or nil when no secret is configured (no
// CAPTCHA: the rate limits still apply).
func NewTurnstile(secret string) *Turnstile {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return nil
	}
	return &Turnstile{secret: secret, url: turnstileVerifyURL, client: httpsec.SafeHTTPClient(10 * time.Second)}
}

// Verify checks one token. A missing token, a network error or a refusal is
// "not verified" (fail-closed).
func (t *Turnstile) Verify(ctx context.Context, token, remoteIP string) (bool, error) {
	token = strings.TrimSpace(token)
	if token == "" || len(token) > 2048 {
		return false, nil
	}
	form := url.Values{"secret": {t.secret}, "response": {token}}
	if remoteIP != "" {
		form.Set("remoteip", remoteIP)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.url, strings.NewReader(form.Encode()))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := t.client.Do(req)
	if err != nil {
		return false, fmt.Errorf("turnstile: %w", err)
	}
	defer resp.Body.Close()
	var body struct {
		Success bool `json:"success"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 64<<10)).Decode(&body); err != nil {
		return false, fmt.Errorf("turnstile: decode: %w", err)
	}
	return resp.StatusCode == http.StatusOK && body.Success, nil
}
