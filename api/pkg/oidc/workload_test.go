package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
)

func (p *testIdP) workloadClaims() jwtv5.MapClaims {
	now := time.Now()
	return jwtv5.MapClaims{
		"iss": p.issuer, "sub": "repo:acme/api:ref:refs/heads/main", "aud": "openctem:tenant:t1",
		"exp": now.Add(5 * time.Minute).Unix(), "iat": now.Unix(), "nbf": now.Unix(),
		"jti": "jti-1", "repository": "acme/api", "ref": "refs/heads/main", "sha": "abc123",
	}
}

func (p *testIdP) workloadExpect() WorkloadExpectations {
	return WorkloadExpectations{Issuer: p.issuer, Audience: "openctem:tenant:t1"}
}

func TestVerifyWorkloadToken(t *testing.T) {
	p := newTestIdP(t)
	tok, err := p.client().VerifyWorkloadToken(context.Background(), p.sign(t, p.workloadClaims()), p.workloadExpect())
	if err != nil {
		t.Fatalf("valid token refused: %v", err)
	}
	if tok.JTI != "jti-1" || tok.Subject == "" || tok.Claims["repository"] != "acme/api" {
		t.Fatalf("claims = %+v", tok)
	}
}

func TestVerifyWorkloadTokenRefusals(t *testing.T) {
	p := newTestIdP(t)
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signWith := func(method jwtv5.SigningMethod, key any, claims jwtv5.MapClaims) string {
		tok := jwtv5.NewWithClaims(method, claims)
		tok.Header["kid"] = "rsa1"
		s, err := tok.SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	mut := func(f func(c jwtv5.MapClaims)) string {
		c := p.workloadClaims()
		f(c)
		return p.sign(t, c)
	}
	now := time.Now()
	cases := map[string]string{
		"expired":           mut(func(c jwtv5.MapClaims) { c["exp"] = now.Add(-10 * time.Minute).Unix() }),
		"no exp":            mut(func(c jwtv5.MapClaims) { delete(c, "exp") }),
		"not yet valid":     mut(func(c jwtv5.MapClaims) { c["nbf"] = now.Add(10 * time.Minute).Unix() }),
		"issued in future":  mut(func(c jwtv5.MapClaims) { c["iat"] = now.Add(10 * time.Minute).Unix() }),
		"no iat":            mut(func(c jwtv5.MapClaims) { delete(c, "iat") }),
		"wrong audience":    mut(func(c jwtv5.MapClaims) { c["aud"] = "openctem:tenant:t2" }),
		"wrong issuer":      mut(func(c jwtv5.MapClaims) { c["iss"] = "https://evil.example" }),
		"no jti":            mut(func(c jwtv5.MapClaims) { delete(c, "jti") }),
		"no sub":            mut(func(c jwtv5.MapClaims) { delete(c, "sub") }),
		"lifetime too long": mut(func(c jwtv5.MapClaims) { c["exp"] = now.Add(48 * time.Hour).Unix() }),
		"forged signature":  signWith(jwtv5.SigningMethodRS256, otherKey, p.workloadClaims()),
		"hmac alg":          signWith(jwtv5.SigningMethodHS256, []byte("secret"), p.workloadClaims()),
		"alg none":          signWith(jwtv5.SigningMethodNone, jwtv5.UnsafeAllowNoneSignatureType, p.workloadClaims()),
		"garbage":           "not.a.jwt",
		"empty":             "",
		"oversized":         strings.Repeat("a", MaxTokenSize+1),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := p.client().VerifyWorkloadToken(context.Background(), raw, p.workloadExpect()); err == nil {
				t.Fatal("token accepted")
			}
		})
	}
	if _, err := p.client().VerifyWorkloadToken(context.Background(), p.sign(t, p.workloadClaims()), WorkloadExpectations{Issuer: p.issuer}); err == nil {
		t.Fatal("accepted without an expected audience")
	}
}

// The discovery document may not send key retrieval to another host, and its
// issuer must be the configured one.
func TestWorkloadDiscoveryPinning(t *testing.T) {
	p := newTestIdP(t)
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": "https://elsewhere", "jwks_uri": p.srv.URL + "/jwks"})
	}))
	defer other.Close()
	c := NewClient(other.Client(), func(string) error { return nil })
	if _, err := c.VerifyWorkloadToken(context.Background(), p.sign(t, p.workloadClaims()),
		WorkloadExpectations{Issuer: other.URL, Audience: "openctem:tenant:t1"}); err == nil {
		t.Fatal("discovery with a foreign issuer accepted")
	}

	foreignJWKS := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": "https://" + r.Host, "jwks_uri": p.srv.URL + "/jwks"})
	}))
	defer foreignJWKS.Close()
	c = NewClient(foreignJWKS.Client(), func(string) error { return nil })
	if _, err := c.workloadJWKSURI(context.Background(), foreignJWKS.URL); err == nil ||
		!strings.Contains(err.Error(), "issuer's host") {
		t.Fatalf("jwks_uri on another host: %v", err)
	}
	if _, err := c.workloadJWKSURI(context.Background(), "http://plain.example"); err == nil {
		t.Fatal("http issuer accepted")
	}
}

// Every outbound request goes through the URL guard (production:
// httpsec.ValidateURL, the SSRF guard).
func TestWorkloadURLGuard(t *testing.T) {
	p := newTestIdP(t)
	var checked atomic.Int32
	c := NewClient(p.srv.Client(), func(string) error {
		checked.Add(1)
		return errBlocked
	})
	if _, err := c.VerifyWorkloadToken(context.Background(), p.sign(t, p.workloadClaims()), p.workloadExpect()); err == nil {
		t.Fatal("blocked URL fetched")
	}
	if checked.Load() == 0 {
		t.Fatal("URL guard not consulted")
	}
}

// A token naming an unknown kid cannot make every request fetch the JWKS.
func TestJWKSRefetchThrottled(t *testing.T) {
	p := newTestIdP(t)
	var fetches atomic.Int32
	inner := p.srv.Config.Handler
	p.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/jwks" {
			fetches.Add(1)
		}
		inner.ServeHTTP(w, r)
	})
	c := p.client()
	if _, err := c.VerifyWorkloadToken(context.Background(), p.sign(t, p.workloadClaims()), p.workloadExpect()); err != nil {
		t.Fatal(err)
	}
	unknown := jwtv5.NewWithClaims(jwtv5.SigningMethodRS256, p.workloadClaims())
	unknown.Header["kid"] = "rotated"
	raw, err := unknown.SignedString(p.key)
	if err != nil {
		t.Fatal(err)
	}
	for range 5 {
		if _, err := c.VerifyWorkloadToken(context.Background(), raw, p.workloadExpect()); err == nil {
			t.Fatal("unknown kid accepted")
		}
	}
	if n := fetches.Load(); n != 1 {
		t.Fatalf("JWKS fetched %d times, want 1 within the refresh interval", n)
	}
}

func TestUnverifiedIssuer(t *testing.T) {
	p := newTestIdP(t)
	iss, err := UnverifiedIssuer(p.sign(t, p.workloadClaims()))
	if err != nil || iss != p.issuer {
		t.Fatalf("iss = %q %v", iss, err)
	}
	for _, bad := range []string{"", "a.b", "a.!!!.c", strings.Repeat("x", MaxTokenSize+1)} {
		if _, err := UnverifiedIssuer(bad); err == nil {
			t.Fatalf("%q: issuer read from a malformed token", bad)
		}
	}
}

// Clock skew is tolerated for one minute, no more: a token expired 30
// seconds ago verifies, one expired (or issued) two minutes off does not.
func TestWorkloadClockSkewBounds(t *testing.T) {
	p := newTestIdP(t)
	now := time.Now()
	at := func(f func(c jwtv5.MapClaims)) string {
		c := p.workloadClaims()
		c["jti"] = "skew-" + strings.ReplaceAll(time.Now().Format(time.RFC3339Nano), ":", "")
		f(c)
		return p.sign(t, c)
	}
	if _, err := p.client().VerifyWorkloadToken(context.Background(),
		at(func(c jwtv5.MapClaims) { c["exp"] = now.Add(-30 * time.Second).Unix() }), p.workloadExpect()); err != nil {
		t.Fatalf("a token within the leeway was refused: %v", err)
	}
	for name, f := range map[string]func(c jwtv5.MapClaims){
		"expired two minutes ago":      func(c jwtv5.MapClaims) { c["exp"] = now.Add(-2 * time.Minute).Unix() },
		"issued two minutes ahead":     func(c jwtv5.MapClaims) { c["iat"] = now.Add(2 * time.Minute).Unix() },
		"valid from two minutes ahead": func(c jwtv5.MapClaims) { c["nbf"] = now.Add(2 * time.Minute).Unix() },
	} {
		if _, err := p.client().VerifyWorkloadToken(context.Background(), at(f), p.workloadExpect()); err == nil {
			t.Fatalf("%s: accepted beyond the leeway", name)
		}
	}
}

// A provider that sends no jti gets a replay key derived from the token
// itself: the same token always maps to the same key, another token to
// another key. Without JTIOptional the token is still refused.
func TestWorkloadJTIOptional(t *testing.T) {
	p := newTestIdP(t)
	c := p.workloadClaims()
	delete(c, "jti")
	raw := p.sign(t, c)
	if _, err := p.client().VerifyWorkloadToken(context.Background(), raw, p.workloadExpect()); err == nil {
		t.Fatal("token without jti accepted")
	}
	exp := p.workloadExpect()
	exp.JTIOptional = true
	a, err := p.client().VerifyWorkloadToken(context.Background(), raw, exp)
	if err != nil {
		t.Fatalf("token without jti refused with JTIOptional: %v", err)
	}
	b, _ := p.client().VerifyWorkloadToken(context.Background(), raw, exp)
	if !strings.HasPrefix(a.JTI, TokenHashJTIPrefix) || len(a.JTI) != len(TokenHashJTIPrefix)+64 || b == nil || a.JTI != b.JTI {
		t.Fatalf("replay key = %q, again %v", a.JTI, b)
	}
	c["sub"] = "another"
	other, err := p.client().VerifyWorkloadToken(context.Background(), p.sign(t, c), exp)
	if err != nil || other.JTI == a.JTI {
		t.Fatalf("another token shares the replay key: %v", err)
	}
	withJTI, err := p.client().VerifyWorkloadToken(context.Background(), p.sign(t, p.workloadClaims()), exp)
	if err != nil || withJTI.JTI != "jti-1" {
		t.Fatalf("a token's own jti must win: %+v %v", withJTI, err)
	}
}

// A preview judges a sample token at its own issue time: an expired token
// shows as verified, a forged one or one for another audience does not.
func TestWorkloadIgnoreTimes(t *testing.T) {
	p := newTestIdP(t)
	old := p.workloadClaims()
	old["iat"] = time.Now().Add(-3 * time.Hour).Unix()
	old["nbf"] = old["iat"]
	old["exp"] = time.Now().Add(-2 * time.Hour).Unix()
	exp := p.workloadExpect()
	if _, err := p.client().VerifyWorkloadToken(context.Background(), p.sign(t, old), exp); err == nil {
		t.Fatal("expired token accepted without IgnoreTimes")
	}
	exp.IgnoreTimes = true
	if _, err := p.client().VerifyWorkloadToken(context.Background(), p.sign(t, old), exp); err != nil {
		t.Fatalf("preview of an expired token: %v", err)
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	forged := jwtv5.NewWithClaims(jwtv5.SigningMethodRS256, old)
	forged.Header["kid"] = "rsa1"
	raw, err := forged.SignedString(other)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.client().VerifyWorkloadToken(context.Background(), raw, exp); err == nil {
		t.Fatal("preview accepted a forged signature")
	}
	wrongAud := p.workloadClaims()
	wrongAud["aud"] = "openctem:tenant:t2"
	if _, err := p.client().VerifyWorkloadToken(context.Background(), p.sign(t, wrongAud), exp); err == nil {
		t.Fatal("preview accepted another audience")
	}
}
