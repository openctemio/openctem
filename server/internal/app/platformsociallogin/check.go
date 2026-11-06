package platformsociallogin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/pkg/httpsec"
)

// Result is the outcome of a configuration check.
type Result string

// Outcomes of a check.
const (
	// ResultValid: the provider knows the client and accepts the secret.
	ResultValid Result = "valid"
	// ResultInvalid: the provider does not know the client or refuses the secret.
	ResultInvalid Result = "invalid"
	// ResultRedirectMismatch: the client is accepted, but the redirect URI is
	// not registered for it.
	ResultRedirectMismatch Result = "redirect_mismatch"
	// ResultUnreachable: the provider could not be reached.
	ResultUnreachable Result = "unreachable"
	// ResultUnknown: the provider answered something this check cannot read.
	ResultUnknown Result = "unknown"
)

// tester asks a provider's token endpoint about a client. The check sends an
// authorization-code exchange with a code that cannot be valid: a provider
// that knows the client and the secret answers that the code is bad
// (invalid_grant), one that does not answers invalid_client. The secret goes
// only to the provider's fixed token endpoint (through the SSRF-safe
// client), and nothing the provider says is passed on except the verdict.
type tester struct {
	client *http.Client
	// tokenURL overrides the provider's endpoint (tests).
	tokenURL func(provider string) string
}

func newTester() *tester {
	return &tester{client: httpsec.SafeHTTPClient(10 * time.Second)}
}

type tokenAnswer struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func (t *tester) endpoint(provider string) string {
	if t.tokenURL != nil {
		return t.tokenURL(provider)
	}
	return auth.TokenEndpoint(auth.OAuthProvider(provider))
}

func (t *tester) check(ctx context.Context, provider, clientID, secret, redirectURI string) Result {
	form := url.Values{
		"client_id": {clientID}, "client_secret": {secret}, "grant_type": {"authorization_code"},
		"code": {"openctem-configuration-check"}, "redirect_uri": {redirectURI},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.endpoint(provider), strings.NewReader(form.Encode()))
	if err != nil {
		return ResultUnknown
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := t.client.Do(req)
	if err != nil {
		return ResultUnreachable
	}
	defer resp.Body.Close()
	body, err := httpsec.ReadLimited(resp.Body, 64<<10)
	if err != nil {
		return ResultUnreachable
	}
	if resp.StatusCode >= 500 {
		return ResultUnreachable
	}
	var ans tokenAnswer
	if json.Unmarshal(body, &ans) != nil {
		return ResultUnknown
	}
	return classify(ans)
}

// classify maps a token endpoint error to a verdict. Only fixed error codes
// and Microsoft's AADSTS numbers are read; no text is echoed.
func classify(a tokenAnswer) Result {
	switch a.Error {
	case "invalid_client", "unauthorized_client", "incorrect_client_credentials", "invalid_request_uri":
		return ResultInvalid
	case "redirect_uri_mismatch":
		return ResultRedirectMismatch
	case "invalid_grant", "bad_verification_code":
		// The client was accepted; the code is the part that cannot be valid.
		// Microsoft reports a wrong secret, an unknown application and a
		// redirect mismatch under invalid_grant/invalid_client descriptions.
		switch {
		case strings.Contains(a.ErrorDescription, "AADSTS50011"):
			return ResultRedirectMismatch
		case strings.Contains(a.ErrorDescription, "AADSTS7000215"), strings.Contains(a.ErrorDescription, "AADSTS700016"):
			return ResultInvalid
		}
		return ResultValid
	}
	if strings.Contains(a.ErrorDescription, "AADSTS7000215") || strings.Contains(a.ErrorDescription, "AADSTS700016") {
		return ResultInvalid
	}
	if strings.Contains(a.ErrorDescription, "AADSTS50011") {
		return ResultRedirectMismatch
	}
	return ResultUnknown
}
