package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/api/internal/config"
	"github.com/openctemio/api/pkg/logger"
)

// mockProvider is an OAuth authorization server that enforces PKCE: the
// token endpoint accepts a code only with the verifier whose S256 hash is the
// challenge sent on the authorize leg.
type mockProvider struct {
	mu         sync.Mutex
	challenge  string
	tokenCalls int
	verifiers  []string
	srv        *httptest.Server
}

func newMockProvider(t *testing.T) *mockProvider {
	t.Helper()
	m := &mockProvider{}
	m.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()
		if !strings.HasSuffix(r.URL.Path, "/access_token") {
			// userinfo etc.: not needed to prove the PKCE leg
			http.Error(w, "unexpected", http.StatusNotFound)
			return
		}
		_ = r.ParseForm()
		m.tokenCalls++
		v := r.PostForm.Get("code_verifier")
		m.verifiers = append(m.verifiers, v)
		sum := sha256.Sum256([]byte(v))
		if v == "" || base64.RawURLEncoding.EncodeToString(sum[:]) != m.challenge {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"bearer"}`))
	}))
	t.Cleanup(m.srv.Close)
	return m
}

// redirectTransport sends every outbound request to the mock provider.
type redirectTransport struct{ target *url.URL }

func (rt redirectTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.URL.Scheme, r.URL.Host = rt.target.Scheme, rt.target.Host
	return http.DefaultTransport.RoundTrip(r)
}

func newPKCETestService(t *testing.T, m *mockProvider) *OAuthService {
	t.Helper()
	cfg := config.OAuthConfig{
		Enabled:       true,
		StateSecret:   "state-secret-for-tests-0123456789",
		StateDuration: 5 * time.Minute,
		GitHub:        config.OAuthProviderConfig{Enabled: true, ClientID: "cid", ClientSecret: "csecret"},
	}
	s := NewOAuthService(nil, nil, nil, cfg, config.AuthConfig{JWTSecret: "jwt-secret-for-tests-0123456789abcdef"}, logger.NewNop())
	target, _ := url.Parse(m.srv.URL)
	s.httpClient = &http.Client{Transport: redirectTransport{target: target}, Timeout: 5 * time.Second}
	return s
}

func authorize(t *testing.T, s *OAuthService, m *mockProvider) (state string) {
	t.Helper()
	res, err := s.GetAuthorizationURL(context.Background(), AuthorizationURLInput{
		Provider: OAuthProviderGitHub, RedirectURI: "https://app.example/auth/callback", FinalRedirect: "/",
	})
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(res.AuthorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	m.challenge = u.Query().Get("code_challenge")
	m.mu.Unlock()
	if m.challenge == "" || u.Query().Get("code_challenge_method") != "S256" {
		t.Fatalf("authorize URL lacks an S256 challenge: %s", res.AuthorizationURL)
	}
	if u.Query().Get("state") != res.State {
		t.Fatal("state in URL differs from returned state")
	}
	return res.State
}

// TestOAuthState_DoesNotCarryPKCEVerifier: the verifier rode in the state in
// plaintext (base64 JSON). The state travels through the browser, the IdP and
// any log or Referer on the way, so whoever intercepts the authorization code
// also had the verifier — PKCE then protects nothing.
func TestOAuthState_DoesNotCarryPKCEVerifier(t *testing.T) {
	m := newMockProvider(t)
	s := newPKCETestService(t, m)
	state := authorize(t, s, m)

	raw, err := base64.URLEncoding.DecodeString(strings.SplitN(state, ".", 2)[0])
	if err != nil {
		t.Fatal(err)
	}
	var data map[string]any
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatal(err)
	}
	for k, v := range data {
		sv, _ := v.(string)
		sum := sha256.Sum256([]byte(sv))
		if sv != "" && base64.RawURLEncoding.EncodeToString(sum[:]) == m.challenge {
			t.Fatalf("state field %q is the PKCE verifier (its S256 is the code_challenge)", k)
		}
	}
	if _, ok := data["code_verifier"]; ok {
		t.Fatal("state carries a code_verifier field")
	}
}

// TestOAuthCallback_PKCEVerifierRoundTrip is the legitimate flow: the
// verifier kept server-side reaches the provider's token endpoint and
// matches the challenge.
func TestOAuthCallback_PKCEVerifierRoundTrip(t *testing.T) {
	m := newMockProvider(t)
	s := newPKCETestService(t, m)
	state := authorize(t, s, m)

	_, err := s.HandleCallback(context.Background(), CallbackInput{
		Provider: OAuthProviderGitHub, Code: "code-1", State: state, RedirectURI: "https://app.example/auth/callback",
	})
	// The mock has no userinfo endpoint, so the flow stops right after a
	// successful code exchange.
	if !errors.Is(err, ErrOAuthUserInfoFailed) {
		t.Fatalf("want the exchange to succeed and userinfo to fail, got %v", err)
	}
	if m.tokenCalls != 1 {
		t.Fatalf("token endpoint called %d times", m.tokenCalls)
	}
}

// TestOAuthCallback_StateIsSingleUse: a state (and its verifier) is consumed
// by the first callback; replaying it is refused before any code exchange.
func TestOAuthCallback_StateIsSingleUse(t *testing.T) {
	m := newMockProvider(t)
	s := newPKCETestService(t, m)
	state := authorize(t, s, m)

	in := CallbackInput{Provider: OAuthProviderGitHub, Code: "code-1", State: state, RedirectURI: "https://app.example/auth/callback"}
	_, _ = s.HandleCallback(context.Background(), in)
	in.Code = "intercepted-code"
	_, err := s.HandleCallback(context.Background(), in)
	if !errors.Is(err, ErrInvalidState) {
		t.Fatalf("replayed state: want ErrInvalidState, got %v", err)
	}
	if m.tokenCalls != 1 {
		t.Fatalf("replayed state reached the token endpoint (%d calls)", m.tokenCalls)
	}
}

func TestMemoryPKCEStore_ExpiresAndIsSingleUse(t *testing.T) {
	st := NewMemoryPKCEStore()
	ctx := context.Background()
	if err := st.Set(ctx, "k", "v", 50*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if v, ok, _ := st.GetDel(ctx, "k"); !ok || v != "v" {
		t.Fatalf("take: %q %v", v, ok)
	}
	if _, ok, _ := st.GetDel(ctx, "k"); ok {
		t.Fatal("second take must miss")
	}
	_ = st.Set(ctx, "k2", "v", 10*time.Millisecond)
	time.Sleep(30 * time.Millisecond)
	if _, ok, _ := st.GetDel(ctx, "k2"); ok {
		t.Fatal("expired entry must miss")
	}
}
