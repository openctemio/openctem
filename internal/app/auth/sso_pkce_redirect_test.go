package auth

// Tests for SSO P1 (part 2): PKCE (S256) on the per-tenant OIDC flow and the
// exact-match redirect_uri allow-list. White-box (package auth) because the PKCE
// verifier lives in the unexported generateState/validateState/exchangeCode.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/api/internal/config"
	"github.com/openctemio/api/pkg/crypto"
	identityproviderdom "github.com/openctemio/api/pkg/domain/identityprovider"
	tenantdom "github.com/openctemio/api/pkg/domain/tenant"
	"github.com/openctemio/api/pkg/logger"
)

func newPKCESSOService(t *testing.T, enc crypto.Encryptor, allow []string) *SSOService {
	t.Helper()
	tn, _ := tenantdom.NewTenant("Acme", "acme", "00000000-0000-0000-0000-000000000001")
	return &SSOService{
		ipRepo:     &fakeIPRepo{byProvider: map[identityproviderdom.Provider]*identityproviderdom.IdentityProvider{}},
		tenantRepo: &fakeTenantRepo{t: tn},
		encryptor:  enc,
		authConfig: config.AuthConfig{
			JWTSecret:           "test-secret-key-for-sso-testing-32ch",
			EntraSSO:            enabledEntra(),
			AllowedRedirectURIs: allow,
		},
		logger: logger.NewNop(),
	}
}

// --- FIX A: PKCE (S256) ---

func TestGenerateAuthorizeURL_PKCE_S256(t *testing.T) {
	cipher, err := crypto.NewCipher([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	svc := newPKCESSOService(t, cipher, []string{"https://app.example.com"})

	res, err := svc.GenerateAuthorizeURL(context.Background(), SSOAuthorizeInput{
		OrgSlug:     "acme",
		Provider:    "entra_id",
		RedirectURI: "https://app.example.com/auth/sso/callback/entra_id",
	})
	if err != nil {
		t.Fatalf("GenerateAuthorizeURL: %v", err)
	}

	u, err := url.Parse(res.AuthorizationURL)
	if err != nil {
		t.Fatalf("parse authorize URL: %v", err)
	}
	q := u.Query()
	if q.Get("code_challenge_method") != "S256" {
		t.Fatalf("code_challenge_method = %q, want S256", q.Get("code_challenge_method"))
	}
	challenge := q.Get("code_challenge")
	if challenge == "" {
		t.Fatal("authorize URL missing code_challenge")
	}

	// Recover the verifier from state and prove S256(verifier) == challenge.
	_, _, _, verifier, verr := svc.validateState(res.State)
	if verr != nil {
		t.Fatalf("validateState: %v", verr)
	}
	if verifier == "" {
		t.Fatal("no PKCE verifier recovered from state")
	}
	sum := sha256.Sum256([]byte(verifier))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if want != challenge {
		t.Fatalf("challenge mismatch: url=%s recomputed=%s", challenge, want)
	}

	// CRUX: the raw verifier must NOT appear in the (signed, unencrypted) state
	// that round-trips through the browser — it is AES-GCM-encrypted.
	if strings.Contains(res.State, verifier) {
		t.Fatal("raw PKCE verifier leaked in the round-tripping state")
	}
}

func TestExchangeCode_IncludesPKCEVerifier(t *testing.T) {
	var gotVerifier string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		vals, _ := url.ParseQuery(string(body))
		gotVerifier = vals.Get("code_verifier")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at","id_token":""}`))
	}))
	defer ts.Close()

	svc := &SSOService{httpClient: ts.Client(), logger: logger.NewNop()}
	_, err := svc.exchangeCode(context.Background(), "cid", "secret", "the-code",
		"https://app.example.com/cb", ts.URL, "verifier-xyz")
	if err != nil {
		t.Fatalf("exchangeCode: %v", err)
	}
	if gotVerifier != "verifier-xyz" {
		t.Fatalf("code_verifier not sent in token exchange, got %q", gotVerifier)
	}
}

func TestHandleCallback_MissingPKCEVerifier_FailsClosed(t *testing.T) {
	svc := newPKCESSOService(t, crypto.NewNoOpEncryptor(), []string{"https://app.example.com"})

	// A validly-signed state that carries NO pkce field (tampered / pre-PKCE).
	stateData := map[string]interface{}{
		"org": "acme", "provider": "entra_id", "nonce": "n",
		"random": "r", "exp": time.Now().Add(5 * time.Minute).Unix(),
	}
	js, _ := json.Marshal(stateData)
	b64 := base64.URLEncoding.EncodeToString(js)
	state := b64 + "." + svc.signState(b64)

	_, err := svc.HandleCallback(context.Background(), SSOCallbackInput{
		Provider: "entra_id", Code: "c", State: state,
		RedirectURI: "https://app.example.com/cb",
	})
	if !errors.Is(err, ErrSSOInvalidState) {
		t.Fatalf("want ErrSSOInvalidState for missing verifier, got %v", err)
	}
}

func TestValidateState_TamperedPKCE_FailsClosed(t *testing.T) {
	cipher, err := crypto.NewCipher([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	svc := newPKCESSOService(t, cipher, nil)

	stateData := map[string]interface{}{
		"org": "acme", "provider": "entra_id", "nonce": "n",
		"pkce": "!!!not-valid-ciphertext!!!", "random": "r",
		"exp": time.Now().Add(5 * time.Minute).Unix(),
	}
	js, _ := json.Marshal(stateData)
	b64 := base64.URLEncoding.EncodeToString(js)
	state := b64 + "." + svc.signState(b64)

	if _, _, _, _, err := svc.validateState(state); err == nil {
		t.Fatal("expected error for undecryptable pkce ciphertext")
	}
}

// --- FIX B: redirect_uri exact-match allow-list ---

func TestValidateRedirectURI_AllowList(t *testing.T) {
	svc := &SSOService{
		authConfig: config.AuthConfig{AllowedRedirectURIs: []string{
			"https://app.example.com",                       // origin-only: any path
			"https://portal.example.com/auth/sso/callback/", // path-pinned prefix
		}},
		logger: logger.NewNop(),
	}

	cases := []struct {
		name string
		uri  string
		ok   bool
	}{
		{"allowed origin, any path", "https://app.example.com/auth/sso/callback/entra_id", true},
		{"allowed path-pinned prefix", "https://portal.example.com/auth/sso/callback/okta", true},
		{"foreign host", "https://evil.com/auth/sso/callback/entra_id", false},
		{"host suffix trick", "https://app.example.com.evil.com/cb", false},
		{"scheme swap", "http://app.example.com/cb", false},
		{"userinfo spoof", "https://app.example.com@evil.com/cb", false},
		{"path traversal on pinned prefix", "https://portal.example.com/auth/sso/callback/../../evil", false},
		{"extra segment on pinned prefix", "https://portal.example.com/auth/sso/callback/a/b", false},
		{"different path than pinned prefix", "https://portal.example.com/evil", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := svc.validateRedirectURI(c.uri)
			if c.ok && err != nil {
				t.Fatalf("expected %q allowed, got %v", c.uri, err)
			}
			if !c.ok {
				if err == nil {
					t.Fatalf("expected %q rejected, got nil", c.uri)
				}
				if !errors.Is(err, ErrSSOInvalidRedirectURI) {
					t.Fatalf("expected ErrSSOInvalidRedirectURI for %q, got %v", c.uri, err)
				}
			}
		})
	}
}

func TestValidateRedirectURI_EmptyAllowListFailsClosed(t *testing.T) {
	svc := &SSOService{authConfig: config.AuthConfig{}, logger: logger.NewNop()}
	if err := svc.validateRedirectURI("https://app.example.com/cb"); !errors.Is(err, ErrSSOInvalidRedirectURI) {
		t.Fatalf("empty allow-list must reject, got %v", err)
	}
}
