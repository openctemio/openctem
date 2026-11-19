//go:build authtestseam

package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"

	"github.com/openctemio/openctem/server/internal/config"
	"github.com/openctemio/openctem/server/pkg/logger"
	"github.com/openctemio/openctem/server/pkg/oidc"
)

// A test build reaches every social provider endpoint at the stand-in named
// by AUTHTESTSEAM_PROVIDER_URL: the browser's authorization URL, the token
// exchange, the signing keys and the profile APIs. The identity rules stay as
// in production: the id_token carries the provider's real issuer and our
// client id, and is verified against the stand-in's keys.
func TestProviderTestSeam_SignInAgainstAStandIn(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const clientID = "seam-client"
	idToken := func() string {
		tok := jwtv5.NewWithClaims(jwtv5.SigningMethodRS256, jwtv5.MapClaims{
			"iss": "https://accounts.google.com", "aud": clientID, "sub": "g-123",
			"email": "person@example.com", "email_verified": true, "name": "Person",
			"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
		})
		tok.Header["kid"] = "seam-1"
		s, err := tok.SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	mux := http.NewServeMux()
	writeJSON := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("/oauth2.googleapis.com/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("client_id") != clientID || r.Form.Get("code") != "the-code" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]any{"access_token": "g-access", "id_token": idToken(), "token_type": "Bearer"})
	})
	mux.HandleFunc("/www.googleapis.com/oauth2/v3/certs", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "seam-1", "alg": "RS256", "use": "sig",
			"n": b64(key.N.Bytes()), "e": b64(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("/www.googleapis.com/oauth2/v2/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer g-access" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		writeJSON(w, map[string]string{"id": "g-123", "name": "Person"})
	})
	mux.HandleFunc("/github.com/login/oauth/access_token", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"access_token": "gh-access", "token_type": "bearer"})
	})
	mux.HandleFunc("/api.github.com/user", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"id": 4242, "login": "person", "name": "Person"})
	})
	mux.HandleFunc("/api.github.com/user/emails", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, []map[string]any{{"email": "person@example.com", "primary": true, "verified": true}})
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	t.Setenv("APP_ENV", "test")
	t.Setenv(EnvTestSeamProviderURL, srv.URL)
	t.Setenv(EnvTestSeamProviderBrowserURL, "https://idp.example.test:8443")

	s := &OAuthService{
		config: config.OAuthConfig{
			Enabled: true, FrontendCallbackURL: "http://localhost:3000/auth/callback",
			StateSecret: "0123456789abcdef0123456789abcdef", StateDuration: time.Minute,
			Google: config.OAuthProviderConfig{Enabled: true, ClientID: clientID, ClientSecret: "s"},
			GitHub: config.OAuthProviderConfig{Enabled: true, ClientID: clientID, ClientSecret: "s"},
		},
		logger:       logger.NewNop(),
		httpClient:   srv.Client(),
		oidcVerifier: oidc.NewClient(srv.Client(), func(string) error { return nil }),
		pkceStore:    NewMemoryPKCEStore(),
	}
	ctx := context.Background()

	// The browser is sent to the stand-in's browser address.
	az, err := s.GetAuthorizationURL(ctx, AuthorizationURLInput{Provider: OAuthProviderGoogle, RedirectURI: "http://localhost:3000/auth/callback/google"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(az.AuthorizationURL, "https://idp.example.test:8443/accounts.google.com/o/oauth2/v2/auth?") {
		t.Fatalf("authorization URL %s", az.AuthorizationURL)
	}
	if u, _ := url.Parse(az.AuthorizationURL); u.Query().Get("client_id") != clientID {
		t.Fatalf("authorization URL lost its parameters: %s", az.AuthorizationURL)
	}

	// Google: code exchange, id_token verified with the stand-in's keys
	// under Google's issuer, profile from the stand-in.
	tokens, err := s.exchangeCode(ctx, OAuthProviderGoogle, &s.config.Google, "the-code", "http://localhost:3000/auth/callback/google", "")
	if err != nil {
		t.Fatalf("google exchange: %v", err)
	}
	info, err := s.providerUserInfo(ctx, OAuthProviderGoogle, tokens)
	if err != nil {
		t.Fatalf("google identity: %v", err)
	}
	if info.Email != "person@example.com" || info.Subject != "g-123" || info.Issuer != googleIssuer {
		t.Fatalf("google identity %+v", info)
	}

	// GitHub: code exchange and both profile APIs.
	tokens, err = s.exchangeCode(ctx, OAuthProviderGitHub, &s.config.GitHub, "the-code", "http://localhost:3000/auth/callback/github", "")
	if err != nil {
		t.Fatalf("github exchange: %v", err)
	}
	info, err = s.providerUserInfo(ctx, OAuthProviderGitHub, tokens)
	if err != nil {
		t.Fatalf("github identity: %v", err)
	}
	if info.Email != "person@example.com" || info.Subject != "4242" {
		t.Fatalf("github identity %+v", info)
	}

	// Any APP_ENV that is not an explicit test value: a tagged binary still
	// reaches the real providers.
	for _, env := range []string{"production", "staging", "development", "", "prod", "testing"} {
		t.Setenv("APP_ENV", env)
		if got := TokenEndpoint(OAuthProviderGoogle); got != "https://oauth2.googleapis.com/token" {
			t.Fatalf("APP_ENV=%q must never use the stand-in, got %s", env, got)
		}
		if TestSeamActive() {
			t.Fatalf("APP_ENV=%q reports the seam active", env)
		}
	}
}
