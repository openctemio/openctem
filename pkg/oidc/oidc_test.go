package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
)

var errBlocked = errors.New("url blocked")

// testIdP is a minimal OIDC provider over TLS.
type testIdP struct {
	srv      *httptest.Server
	key      *rsa.PrivateKey
	ecKey    *ecdsa.PrivateKey
	issuer   string // what discovery reports (defaults to the server URL)
	lastForm url.Values
	lastAuth string
	idToken  string // returned by the token endpoint
	authMeth []string
}

func newTestIdP(t *testing.T) *testIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := &testIdP{key: key, ecKey: ecKey}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		doc := map[string]any{
			"issuer":                 p.issuer,
			"authorization_endpoint": p.srv.URL + "/authorize",
			"token_endpoint":         p.srv.URL + "/token",
			"jwks_uri":               p.srv.URL + "/jwks",
		}
		if p.authMeth != nil {
			doc["token_endpoint_auth_methods_supported"] = p.authMeth
		}
		_ = json.NewEncoder(w).Encode(doc)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{
			{
				"kty": "RSA", "kid": "rsa1", "use": "sig", "alg": "RS256",
				"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
			},
			{
				"kty": "EC", "kid": "ec1", "crv": "P-256", "use": "sig",
				"x": base64.RawURLEncoding.EncodeToString(ecKey.X.FillBytes(make([]byte, 32))),
				"y": base64.RawURLEncoding.EncodeToString(ecKey.Y.FillBytes(make([]byte, 32))),
			},
		}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		p.lastForm = r.PostForm
		p.lastAuth = r.Header.Get("Authorization")
		if r.PostForm.Get("code") != "good-code" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "at", "id_token": p.idToken, "token_type": "Bearer"})
	})
	p.srv = httptest.NewTLSServer(mux)
	p.issuer = p.srv.URL
	t.Cleanup(p.srv.Close)
	return p
}

func (p *testIdP) client() *Client {
	return NewClient(p.srv.Client(), func(string) error { return nil })
}

func (p *testIdP) sign(t *testing.T, claims jwtv5.MapClaims) string {
	t.Helper()
	tok := jwtv5.NewWithClaims(jwtv5.SigningMethodRS256, claims)
	tok.Header["kid"] = "rsa1"
	s, err := tok.SignedString(p.key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (p *testIdP) baseClaims() jwtv5.MapClaims {
	now := time.Now()
	return jwtv5.MapClaims{
		"iss": p.issuer, "sub": "user-123", "aud": "client-1",
		"exp": now.Add(5 * time.Minute).Unix(), "iat": now.Unix(),
		"nonce": "n-1", "email": "Ops@Acme.io", "email_verified": true,
		"acr": "urn:mfa", "amr": []string{"pwd", "otp"},
	}
}

func (p *testIdP) expect() Expectations {
	return Expectations{Issuer: p.issuer, ClientID: "client-1", Nonce: "n-1", JWKSURI: p.srv.URL + "/jwks"}
}

func TestDiscover(t *testing.T) {
	p := newTestIdP(t)
	d, err := p.client().Discover(context.Background(), p.issuer)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if d.TokenEndpoint != p.srv.URL+"/token" || d.JWKSURI != p.srv.URL+"/jwks" {
		t.Fatalf("unexpected endpoints: %+v", d)
	}
	if d.TokenEndpointAuthMethod != AuthMethodClientSecretBasic {
		t.Fatalf("default auth method should be client_secret_basic, got %q", d.TokenEndpointAuthMethod)
	}
	// Trailing slash on the configured issuer still fetches the document but
	// the issuer must then match exactly.
	if _, err := p.client().Discover(context.Background(), p.issuer+"/"); err == nil {
		t.Fatal("issuer with a different spelling than discovery reports must be refused")
	}
}

func TestDiscoverRefusals(t *testing.T) {
	p := newTestIdP(t)
	c := p.client()
	ctx := context.Background()

	p.issuer = "https://evil.example"
	if _, err := c.Discover(ctx, p.srv.URL); err == nil {
		t.Fatal("discovery issuer mismatch must be refused")
	}
	p.issuer = p.srv.URL

	if _, err := c.Discover(ctx, "http://idp.example"); err == nil {
		t.Fatal("http issuer must be refused")
	}
	if _, err := c.Discover(ctx, p.srv.URL+"?x=1"); err == nil {
		t.Fatal("issuer with a query must be refused")
	}

	blocked := NewClient(p.srv.Client(), func(string) error { return errBlocked })
	if _, err := blocked.Discover(ctx, p.srv.URL); err == nil {
		t.Fatal("URL guard must be applied to discovery")
	}
}

func TestDiscoverPrefersPostWhenBasicUnsupported(t *testing.T) {
	p := newTestIdP(t)
	p.authMeth = []string{"client_secret_post", "private_key_jwt"}
	d, err := p.client().Discover(context.Background(), p.issuer)
	if err != nil {
		t.Fatal(err)
	}
	if d.TokenEndpointAuthMethod != AuthMethodClientSecretPost {
		t.Fatalf("got %q", d.TokenEndpointAuthMethod)
	}
	p.authMeth = []string{"private_key_jwt"}
	if _, err := p.client().Discover(context.Background(), p.issuer); err == nil {
		t.Fatal("an IdP supporting neither secret method must be refused")
	}
}

func TestExchangeSendsPKCEAndSecret(t *testing.T) {
	p := newTestIdP(t)
	p.idToken = "the-id-token"
	c := p.client()
	ctx := context.Background()

	tok, err := c.Exchange(ctx, ExchangeRequest{
		TokenEndpoint: p.srv.URL + "/token", AuthMethod: AuthMethodClientSecretBasic,
		ClientID: "client-1", ClientSecret: "s3cr:et", Code: "good-code",
		RedirectURI: "https://console.example/admin/login/callback", CodeVerifier: "verifier-1",
	})
	if err != nil || tok != "the-id-token" {
		t.Fatalf("exchange: %q %v", tok, err)
	}
	if p.lastForm.Get("code_verifier") != "verifier-1" || p.lastForm.Get("grant_type") != "authorization_code" {
		t.Fatalf("form: %v", p.lastForm)
	}
	if p.lastForm.Get("client_secret") != "" || !strings.HasPrefix(p.lastAuth, "Basic ") {
		t.Fatal("basic auth must carry the secret, not the form")
	}

	if _, err := c.Exchange(ctx, ExchangeRequest{
		TokenEndpoint: p.srv.URL + "/token", AuthMethod: AuthMethodClientSecretPost,
		ClientID: "client-1", ClientSecret: "s", Code: "good-code", RedirectURI: "https://x", CodeVerifier: "v",
	}); err != nil {
		t.Fatal(err)
	}
	if p.lastForm.Get("client_secret") != "s" || p.lastAuth != "" {
		t.Fatal("post auth must carry the secret in the form")
	}

	if _, err := c.Exchange(ctx, ExchangeRequest{
		TokenEndpoint: p.srv.URL + "/token", AuthMethod: AuthMethodClientSecretPost,
		ClientID: "client-1", ClientSecret: "s", Code: "bad", RedirectURI: "https://x", CodeVerifier: "v",
	}); err == nil {
		t.Fatal("a refused code must fail")
	}
}

func TestVerifyIDToken(t *testing.T) {
	p := newTestIdP(t)
	c := p.client()
	ctx := context.Background()

	claims, err := c.VerifyIDToken(ctx, p.sign(t, p.baseClaims()), p.expect())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.Subject != "user-123" || claims.Email != "Ops@Acme.io" || !claims.EmailIsVerified() {
		t.Fatalf("claims: %+v", claims)
	}
	if claims.ACR != "urn:mfa" || len(claims.AMR) != 2 {
		t.Fatalf("acr/amr: %+v", claims)
	}
}

func TestVerifyIDTokenRefusals(t *testing.T) {
	p := newTestIdP(t)
	c := p.client()
	ctx := context.Background()

	cases := map[string]func(m jwtv5.MapClaims){
		"wrong issuer":   func(m jwtv5.MapClaims) { m["iss"] = "https://other" },
		"wrong audience": func(m jwtv5.MapClaims) { m["aud"] = "client-2" },
		"wrong nonce":    func(m jwtv5.MapClaims) { m["nonce"] = "n-2" },
		"missing nonce":  func(m jwtv5.MapClaims) { delete(m, "nonce") },
		"expired":        func(m jwtv5.MapClaims) { m["exp"] = time.Now().Add(-10 * time.Minute).Unix() },
		"missing exp":    func(m jwtv5.MapClaims) { delete(m, "exp") },
		"future iat":     func(m jwtv5.MapClaims) { m["iat"] = time.Now().Add(10 * time.Minute).Unix() },
		"missing sub":    func(m jwtv5.MapClaims) { delete(m, "sub") },
		"multi-aud without azp": func(m jwtv5.MapClaims) {
			m["aud"] = []string{"client-1", "other"}
		},
		"multi-aud wrong azp": func(m jwtv5.MapClaims) {
			m["aud"] = []string{"client-1", "other"}
			m["azp"] = "other"
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			m := p.baseClaims()
			mutate(m)
			if _, err := c.VerifyIDToken(ctx, p.sign(t, m), p.expect()); err == nil {
				t.Fatalf("%s must be refused", name)
			}
		})
	}

	t.Run("multi-aud with azp", func(t *testing.T) {
		m := p.baseClaims()
		m["aud"] = []string{"client-1", "other"}
		m["azp"] = "client-1"
		if _, err := c.VerifyIDToken(ctx, p.sign(t, m), p.expect()); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("alg none", func(t *testing.T) {
		tok := jwtv5.NewWithClaims(jwtv5.SigningMethodNone, p.baseClaims())
		s, _ := tok.SignedString(jwtv5.UnsafeAllowNoneSignatureType)
		if _, err := c.VerifyIDToken(ctx, s, p.expect()); err == nil {
			t.Fatal("alg none must be refused")
		}
	})

	t.Run("HS256 with the public key as secret", func(t *testing.T) {
		tok := jwtv5.NewWithClaims(jwtv5.SigningMethodHS256, p.baseClaims())
		tok.Header["kid"] = "rsa1"
		s, _ := tok.SignedString(p.key.N.Bytes())
		if _, err := c.VerifyIDToken(ctx, s, p.expect()); err == nil {
			t.Fatal("HMAC must be refused")
		}
	})

	t.Run("signed by another key", func(t *testing.T) {
		other, _ := rsa.GenerateKey(rand.Reader, 2048)
		tok := jwtv5.NewWithClaims(jwtv5.SigningMethodRS256, p.baseClaims())
		tok.Header["kid"] = "rsa1"
		s, _ := tok.SignedString(other)
		if _, err := c.VerifyIDToken(ctx, s, p.expect()); err == nil {
			t.Fatal("foreign signature must be refused")
		}
	})

	t.Run("RSA kid with EC alg", func(t *testing.T) {
		tok := jwtv5.NewWithClaims(jwtv5.SigningMethodES256, p.baseClaims())
		tok.Header["kid"] = "rsa1"
		s, _ := tok.SignedString(p.ecKey)
		if _, err := c.VerifyIDToken(ctx, s, p.expect()); err == nil {
			t.Fatal("key/alg mismatch must be refused")
		}
	})

	t.Run("ES256 accepted", func(t *testing.T) {
		tok := jwtv5.NewWithClaims(jwtv5.SigningMethodES256, p.baseClaims())
		tok.Header["kid"] = "ec1"
		s, _ := tok.SignedString(p.ecKey)
		if _, err := c.VerifyIDToken(ctx, s, p.expect()); err != nil {
			t.Fatal(err)
		}
	})
}

func TestEmailVerifiedVariants(t *testing.T) {
	for raw, want := range map[string]bool{
		`{"email_verified":true}`:    true,
		`{"email_verified":"true"}`:  true,
		`{"email_verified":false}`:   false,
		`{"email_verified":"false"}`: false,
		`{}`:                         false,
		`{"xms_edov":true}`:          true,
		`{"xms_edov":false}`:         false,
	} {
		var c Claims
		if err := json.Unmarshal([]byte(raw), &c); err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		if got := c.EmailIsVerified(); got != want {
			t.Fatalf("%s: got %v want %v", raw, got, want)
		}
	}
}

func TestPKCE(t *testing.T) {
	v, ch, err := NewPKCE()
	if err != nil {
		t.Fatal(err)
	}
	if len(v) < 43 {
		t.Fatalf("verifier too short: %d", len(v))
	}
	sum := sha256.Sum256([]byte(v))
	if ch != base64.RawURLEncoding.EncodeToString(sum[:]) {
		t.Fatal("challenge is not S256(verifier)")
	}
}

func TestAuthorizationURL(t *testing.T) {
	u, err := AuthorizationURL("https://idp.example/authorize?tenant=x", AuthorizationRequest{
		ClientID: "c", RedirectURI: "https://console/cb", Scopes: []string{"openid", "email"},
		State: "s", Nonce: "n", CodeChallenge: "ch", ACRValues: []string{"a", "b"},
	})
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := url.Parse(u)
	q := parsed.Query()
	for k, want := range map[string]string{
		"tenant": "x", "response_type": "code", "client_id": "c", "redirect_uri": "https://console/cb",
		"scope": "openid email", "state": "s", "nonce": "n", "code_challenge": "ch",
		"code_challenge_method": "S256", "acr_values": "a b",
	} {
		if q.Get(k) != want {
			t.Fatalf("%s = %q, want %q", k, q.Get(k), want)
		}
	}
}
