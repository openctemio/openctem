package platformcaptcha

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

// turnstileVerifyURL is Cloudflare Turnstile's server-side check. It is a
// constant: no request or setting names the address the secret is sent to.
const turnstileVerifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

// siteverify is one call to the Turnstile check.
type siteverify struct {
	url    string
	client *http.Client
}

func newSiteverify() *siteverify {
	return &siteverify{url: turnstileVerifyURL, client: httpsec.SafeHTTPClient(10 * time.Second)}
}

type siteverifyAnswer struct {
	Success    bool     `json:"success"`
	ErrorCodes []string `json:"error-codes"`
}

func (v *siteverify) call(ctx context.Context, secret, token, remoteIP string) (siteverifyAnswer, int, error) {
	form := url.Values{"secret": {secret}, "response": {token}}
	if remoteIP != "" {
		form.Set("remoteip", remoteIP)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.url, strings.NewReader(form.Encode()))
	if err != nil {
		return siteverifyAnswer{}, 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := v.client.Do(req)
	if err != nil {
		return siteverifyAnswer{}, 0, fmt.Errorf("turnstile: %w", err)
	}
	defer resp.Body.Close()
	var body siteverifyAnswer
	if err := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 64<<10)).Decode(&body); err != nil {
		return siteverifyAnswer{}, resp.StatusCode, fmt.Errorf("turnstile: decode: %w", err)
	}
	return body, resp.StatusCode, nil
}

// verify checks one browser token. A missing token, a network error or a
// refusal is "not verified" (fail closed).
func (v *siteverify) verify(ctx context.Context, secret, token, remoteIP string) (bool, error) {
	token = strings.TrimSpace(token)
	if token == "" || len(token) > 2048 {
		return false, nil
	}
	body, status, err := v.call(ctx, secret, token, remoteIP)
	if err != nil {
		return false, err
	}
	return status == http.StatusOK && body.Success, nil
}

// SecretCheck is the outcome of checking a secret key.
type SecretCheck string

// Outcomes of CheckSecret.
const (
	// SecretValid: Turnstile accepted the secret (it refused only the
	// placeholder token).
	SecretValid SecretCheck = "valid"
	// SecretInvalid: Turnstile does not know the secret.
	SecretInvalid SecretCheck = "invalid"
	// SecretUnreachable: Turnstile could not be asked or answered something
	// unexpected; nothing is known about the secret.
	SecretUnreachable SecretCheck = "unreachable"
)

// checkToken is a placeholder browser token: Turnstile refuses it as
// invalid-input-response when the secret is good, and reports
// invalid-input-secret when the secret is wrong.
const checkToken = "openctem-console-secret-check"

// checkSecret asks Turnstile whether it knows the secret.
func (v *siteverify) checkSecret(ctx context.Context, secret string) SecretCheck {
	body, _, err := v.call(ctx, secret, checkToken, "")
	if err != nil {
		return SecretUnreachable
	}
	for _, c := range body.ErrorCodes {
		switch c {
		case "invalid-input-secret", "missing-input-secret":
			return SecretInvalid
		case "invalid-input-response", "timeout-or-duplicate":
			return SecretValid
		}
	}
	if body.Success {
		// Turnstile's test secrets accept every token.
		return SecretValid
	}
	return SecretUnreachable
}
