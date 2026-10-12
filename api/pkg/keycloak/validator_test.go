package keycloak

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// testRealm is a Keycloak realm over TLS that serves one RSA key.
type testRealm struct {
	srv     *httptest.Server
	key     *rsa.PrivateKey
	fetches atomic.Int32
	down    atomic.Bool
}

func newTestRealm(t *testing.T) *testRealm {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	r := &testRealm{key: key}
	r.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		r.fetches.Add(1)
		if r.down.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "realm-key", "use": "sig", "alg": "RS256",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *testRealm) issuer() string { return r.srv.URL + "/realms/openctem" }

func (r *testRealm) validator(t *testing.T, audience string) *Validator {
	t.Helper()
	v, err := newValidator(context.Background(), ValidatorConfig{
		JWKSURL:             r.srv.URL + "/realms/openctem/protocol/openid-connect/certs",
		IssuerURL:           r.issuer(),
		Audience:            audience,
		RequireInitialFetch: true,
	}, r.srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = v.Close() })
	return v
}

func (r *testRealm) claims() jwt.MapClaims {
	now := time.Now()
	return jwt.MapClaims{
		"iss": r.issuer(), "sub": "user-1", "aud": "openctem-api", "azp": "openctem-web",
		"exp": now.Add(5 * time.Minute).Unix(), "iat": now.Unix(),
		"preferred_username": "jdoe", "email": "jdoe@example.com",
		"realm_access": map[string]any{"roles": []string{"admin", "viewer"}},
		"tenant_id":    "t-1",
	}
}

func sign(t *testing.T, method jwt.SigningMethod, key any, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(method, claims)
	if kid != "" {
		tok.Header["kid"] = kid
	}
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestValidateToken(t *testing.T) {
	r := newTestRealm(t)
	v := r.validator(t, "openctem-api")
	if !v.HasKeys() {
		t.Fatal("initial fetch did not load keys")
	}
	c, err := v.ValidateToken(context.Background(), sign(t, jwt.SigningMethodRS256, r.key, "realm-key", r.claims()))
	if err != nil {
		t.Fatalf("valid token refused: %v", err)
	}
	if c.GetUserID() != "user-1" || c.PreferredUsername != "jdoe" || c.GetTenantID() != "t-1" ||
		!c.HasRealmRole("admin") || len(c.GetRealmRoles()) != 2 {
		t.Fatalf("claims = %+v", c)
	}
}

// The audience rule: aud or azp must name the configured client; without a
// configured client every audience of the realm is accepted.
func TestValidateTokenAudience(t *testing.T) {
	r := newTestRealm(t)
	raw := func(aud, azp string) string {
		m := r.claims()
		m["aud"], m["azp"] = aud, azp
		return sign(t, jwt.SigningMethodRS256, r.key, "realm-key", m)
	}
	strict := r.validator(t, "openctem-api")
	if _, err := strict.ValidateToken(context.Background(), raw("account", "openctem-api")); err != nil {
		t.Fatalf("azp match refused: %v", err)
	}
	if _, err := strict.ValidateToken(context.Background(), raw("account", "other-client")); !errors.Is(err, ErrInvalidAudience) {
		t.Fatalf("foreign client accepted: %v", err)
	}
	if _, err := r.validator(t, "").ValidateToken(context.Background(), raw("account", "other-client")); err != nil {
		t.Fatalf("no configured audience: %v", err)
	}
}

func TestValidateTokenRefusals(t *testing.T) {
	r := newTestRealm(t)
	v := r.validator(t, "openctem-api")
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&r.key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	mut := func(f func(m jwt.MapClaims)) string {
		m := r.claims()
		f(m)
		return sign(t, jwt.SigningMethodRS256, r.key, "realm-key", m)
	}
	now := time.Now()
	cases := map[string]struct {
		raw  string
		want error
	}{
		"HS256 with the realm public key": {sign(t, jwt.SigningMethodHS256, pubDER, "realm-key", r.claims()), ErrInvalidToken},
		"alg none":                        {sign(t, jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType, "realm-key", r.claims()), ErrInvalidToken},
		"signed by another key":           {sign(t, jwt.SigningMethodRS256, other, "realm-key", r.claims()), ErrInvalidToken},
		"unknown kid":                     {sign(t, jwt.SigningMethodRS256, r.key, "rotated", r.claims()), ErrKeyNotFound},
		"another realm":                   {mut(func(m jwt.MapClaims) { m["iss"] = r.srv.URL + "/realms/evil" }), ErrInvalidIssuer},
		"expired":                         {mut(func(m jwt.MapClaims) { m["exp"] = now.Add(-10 * time.Minute).Unix() }), ErrExpiredToken},
		"no exp":                          {mut(func(m jwt.MapClaims) { delete(m, "exp") }), ErrInvalidToken},
		"not valid yet":                   {mut(func(m jwt.MapClaims) { m["nbf"] = now.Add(10 * time.Minute).Unix() }), ErrInvalidToken},
		"issued in the future":            {mut(func(m jwt.MapClaims) { m["iat"] = now.Add(10 * time.Minute).Unix() }), ErrInvalidToken},
		"oversized":                       {mut(func(m jwt.MapClaims) { m["pad"] = strings.Repeat("a", 40<<10) }), ErrInvalidToken},
		"garbage":                         {"not.a.jwt", ErrInvalidToken},
		"empty":                           {"", ErrInvalidToken},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := v.ValidateToken(context.Background(), tc.raw); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

// A flood of made-up kids does not make every request fetch the realm keys.
func TestUnknownKidFloodIsThrottled(t *testing.T) {
	r := newTestRealm(t)
	v := r.validator(t, "")
	before := r.fetches.Load()
	for i := range 50 {
		raw := sign(t, jwt.SigningMethodRS256, r.key, "kid-"+time.Now().String()+string(rune('a'+i%26)), r.claims())
		if _, err := v.ValidateToken(context.Background(), raw); err == nil {
			t.Fatal("unknown kid accepted")
		}
	}
	if n := r.fetches.Load() - before; n > 1 {
		t.Fatalf("realm keys fetched %d times for 50 unknown kids", n)
	}
}

// While the realm is down, the keys already loaded keep verifying.
func TestRealmOutageKeepsKnownKeys(t *testing.T) {
	r := newTestRealm(t)
	v := r.validator(t, "")
	r.down.Store(true)
	if err := v.refresh(); err == nil {
		t.Fatal("refresh against a down realm succeeded")
	}
	if n, err := v.LastRefreshError(); n != 1 || err == nil {
		t.Fatalf("failure not recorded: %d %v", n, err)
	}
	if _, err := v.ValidateToken(context.Background(), sign(t, jwt.SigningMethodRS256, r.key, "realm-key", r.claims())); err != nil {
		t.Fatalf("known key refused during an outage: %v", err)
	}
}

func TestNewValidatorRequiresIssuerAndJWKS(t *testing.T) {
	if _, err := NewValidator(context.Background(), ValidatorConfig{JWKSURL: "https://kc.example/certs"}); err == nil {
		t.Fatal("validator without an issuer created")
	}
	if _, err := NewValidator(context.Background(), ValidatorConfig{IssuerURL: "https://kc.example/realms/x"}); err == nil {
		t.Fatal("validator without a JWKS URL created")
	}
}
