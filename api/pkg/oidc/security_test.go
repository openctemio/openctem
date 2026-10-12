package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"

	"github.com/openctemio/openctem/api/pkg/httpsec"
)

// tokenFlow is one consumer of the verification core: how it signs a valid
// token and how it verifies one.
type tokenFlow struct {
	name   string
	claims func(p *testIdP) jwtv5.MapClaims
	verify func(c *Client, p *testIdP, raw string) error
}

// accessPolicy is the core as the external provider's access tokens and the
// logout tokens use it: exact issuer and audience, no flow extras.
func accessPolicy(p *testIdP) TokenPolicy {
	return TokenPolicy{JWKSURI: p.srv.URL + "/jwks", Issuer: p.issuer, Audience: "client-1", Leeway: time.Minute}
}

var tokenFlows = []tokenFlow{
	{
		name:   "sign-in",
		claims: func(p *testIdP) jwtv5.MapClaims { return p.baseClaims() },
		verify: func(c *Client, p *testIdP, raw string) error {
			_, err := c.VerifyIDToken(context.Background(), raw, p.expect())
			return err
		},
	},
	{
		name:   "workload",
		claims: func(p *testIdP) jwtv5.MapClaims { return p.workloadClaims() },
		verify: func(c *Client, p *testIdP, raw string) error {
			_, err := c.VerifyWorkloadToken(context.Background(), raw, p.workloadExpect())
			return err
		},
	},
	{
		name: "access token",
		claims: func(p *testIdP) jwtv5.MapClaims {
			m := p.baseClaims()
			delete(m, "nonce")
			return m
		},
		verify: func(c *Client, p *testIdP, raw string) error {
			return c.VerifyJWT(context.Background(), raw, jwtv5.MapClaims{}, accessPolicy(p))
		},
	},
}

func signWithHeader(t *testing.T, method jwtv5.SigningMethod, key any, kid string, claims jwtv5.MapClaims) string {
	t.Helper()
	tok := jwtv5.NewWithClaims(method, claims)
	if kid != "" {
		tok.Header["kid"] = kid
	}
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// Every flow refuses the same attacks, because they share one core.
func TestEveryFlowRefusesForgedTokens(t *testing.T) {
	for _, f := range tokenFlows {
		t.Run(f.name, func(t *testing.T) {
			p := newTestIdP(t)
			c := p.client()
			if err := f.verify(c, p, p.sign(t, f.claims(p))); err != nil {
				t.Fatalf("a valid token was refused: %v", err)
			}
			other, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatal(err)
			}
			pubDER, err := x509.MarshalPKIXPublicKey(&p.key.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
			mut := func(change func(m jwtv5.MapClaims)) string {
				m := f.claims(p)
				change(m)
				return p.sign(t, m)
			}
			now := time.Now()
			cases := map[string]string{
				// Algorithm confusion: an RS256 key used as an HMAC secret.
				"HS256 with the PEM public key":     signWithHeader(t, jwtv5.SigningMethodHS256, pubPEM, "rsa1", f.claims(p)),
				"HS256 with the DER public key":     signWithHeader(t, jwtv5.SigningMethodHS256, pubDER, "rsa1", f.claims(p)),
				"HS256 with the modulus":            signWithHeader(t, jwtv5.SigningMethodHS256, p.key.N.Bytes(), "rsa1", f.claims(p)),
				"alg none":                          signWithHeader(t, jwtv5.SigningMethodNone, jwtv5.UnsafeAllowNoneSignatureType, "rsa1", f.claims(p)),
				"EC alg on an RSA kid":              signWithHeader(t, jwtv5.SigningMethodES256, p.ecKey, "rsa1", f.claims(p)),
				"unknown kid":                       signWithHeader(t, jwtv5.SigningMethodRS256, p.key, "nope", f.claims(p)),
				"wrong issuer":                      mut(func(m jwtv5.MapClaims) { m["iss"] = "https://evil.example" }),
				"wrong audience":                    mut(func(m jwtv5.MapClaims) { m["aud"] = "someone-else" }),
				"expired beyond the leeway":         mut(func(m jwtv5.MapClaims) { m["exp"] = now.Add(-10 * time.Minute).Unix() }),
				"not valid before, beyond leeway":   mut(func(m jwtv5.MapClaims) { m["nbf"] = now.Add(10 * time.Minute).Unix() }),
				"issued in the future":              mut(func(m jwtv5.MapClaims) { m["iat"] = now.Add(10 * time.Minute).Unix() }),
				"no exp":                            mut(func(m jwtv5.MapClaims) { delete(m, "exp") }),
				"oversized":                         mut(func(m jwtv5.MapClaims) { m["pad"] = strings.Repeat("a", MaxTokenSize) }),
				"empty":                             "",
				"not a JWS":                         "a.b",
				"signature of another token":        swapSignature(t, p.sign(t, f.claims(p)), mut(func(m jwtv5.MapClaims) { m["sub"] = "other" })),
				"payload changed after signing":     tamperPayload(p.sign(t, f.claims(p))),
				"RS256 by a key not in the JWKS":    signWithHeader(t, jwtv5.SigningMethodRS256, other, "rsa1", f.claims(p)),
				"kid of the EC key with an RS alg":  signWithHeader(t, jwtv5.SigningMethodRS256, p.key, "ec1", f.claims(p)),
				"PS256 signed by a key not in JWKS": signWithHeader(t, jwtv5.SigningMethodPS256, other, "rsa1", f.claims(p)),
			}
			for name, raw := range cases {
				t.Run(name, func(t *testing.T) {
					if err := f.verify(c, p, raw); err == nil {
						t.Fatal("token accepted")
					}
				})
			}
		})
	}
}

// An attacker sending tokens with ever-new kids cannot make any flow fetch
// the JWKS more than once per refresh interval.
func TestEveryFlowThrottlesUnknownKidRefetch(t *testing.T) {
	for _, f := range tokenFlows {
		t.Run(f.name, func(t *testing.T) {
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
			if err := f.verify(c, p, p.sign(t, f.claims(p))); err != nil {
				t.Fatal(err)
			}
			for i := range 50 {
				raw := signWithHeader(t, jwtv5.SigningMethodRS256, p.key, "flood-"+string(rune('a'+i%26))+time.Now().String(), f.claims(p))
				if err := f.verify(c, p, raw); err == nil {
					t.Fatal("unknown kid accepted")
				}
			}
			if n := fetches.Load(); n != 1 {
				t.Fatalf("JWKS fetched %d times, want 1", n)
			}
		})
	}
}

// The JWKS (and every other URL) goes through the URL guard: with the
// production guard a provider on a loopback or private address is never
// dialed, whatever the flow.
func TestEveryFlowAppliesTheSSRFGuard(t *testing.T) {
	for _, f := range tokenFlows {
		t.Run(f.name, func(t *testing.T) {
			p := newTestIdP(t) // listens on 127.0.0.1
			var dialed atomic.Int32
			inner := p.srv.Config.Handler
			p.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				dialed.Add(1)
				inner.ServeHTTP(w, r)
			})
			c := NewClient(p.srv.Client(), func(raw string) error {
				_, err := httpsec.ValidateURL(raw)
				return err
			})
			if err := f.verify(c, p, p.sign(t, f.claims(p))); err == nil {
				t.Fatal("token verified with keys from a loopback address")
			}
			if dialed.Load() != 0 {
				t.Fatal("a blocked address was dialed")
			}
		})
	}
}

// A discovery document cannot send key retrieval to a plain-HTTP or
// private URL (sign-in and workload flows discover their JWKS).
func TestDiscoveredJWKSMustBeHTTPS(t *testing.T) {
	p := newTestIdP(t)
	srv := p.srv
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"issuer":"` + p.issuer + `","authorization_endpoint":"` + srv.URL +
			`/a","token_endpoint":"` + srv.URL + `/t","jwks_uri":"http://169.254.169.254/latest/meta-data"}`))
	})
	if _, err := p.client().Discover(context.Background(), p.issuer); err == nil {
		t.Fatal("sign-in discovery accepted an http jwks_uri")
	}
	if _, err := p.client().workloadJWKSURI(context.Background(), p.issuer); err == nil {
		t.Fatal("workload discovery accepted an http jwks_uri")
	}
}

func TestSignInNonceAndEntraTenantPinning(t *testing.T) {
	p := newTestIdP(t)
	c := p.client()
	ctx := context.Background()

	m := p.baseClaims()
	m["nonce"] = "replayed-from-another-flow"
	if _, err := c.VerifyIDToken(ctx, p.sign(t, m), p.expect()); err == nil {
		t.Fatal("nonce mismatch accepted")
	}
	noNonce := p.expect()
	noNonce.Nonce = ""
	if _, err := c.VerifyIDToken(ctx, p.sign(t, p.baseClaims()), noNonce); err == nil {
		t.Fatal("verified without an expected nonce")
	}
	both := p.expect()
	both.IssuerRule = GoogleIssuer
	if _, err := c.VerifyIDToken(ctx, p.sign(t, p.baseClaims()), both); err == nil {
		t.Fatal("expectations with both an issuer and an issuer rule accepted")
	}

	const pinned = "11111111-1111-1111-1111-111111111111"
	entra := func(tid, iss string) string {
		m := p.baseClaims()
		m["tid"], m["iss"] = tid, iss
		return p.sign(t, m)
	}
	exp := func(configured string) Expectations {
		e := p.expect()
		e.Issuer, e.IssuerRule = "", EntraIssuer(configured)
		return e
	}
	issOf := func(tid string) string { return "https://login.microsoftonline.com/" + tid + "/v2.0" }
	other := "22222222-2222-2222-2222-222222222222"

	if _, err := c.VerifyIDToken(ctx, entra(pinned, issOf(pinned)), exp(pinned)); err != nil {
		t.Fatalf("pinned directory refused: %v", err)
	}
	if _, err := c.VerifyIDToken(ctx, entra(other, issOf(other)), exp(pinned)); err == nil {
		t.Fatal("another directory accepted by a single-tenant configuration")
	}
	if _, err := c.VerifyIDToken(ctx, entra(pinned, issOf(other)), exp("common")); err == nil {
		t.Fatal("tid and iss that disagree accepted")
	}
	if _, err := c.VerifyIDToken(ctx, entra("", issOf(other)), exp("common")); err == nil {
		t.Fatal("token without tid accepted")
	}
	for _, multi := range []string{"common", "organizations", ""} {
		if _, err := c.VerifyIDToken(ctx, entra(other, issOf(other)), exp(multi)); err != nil {
			t.Fatalf("%q: a consistent token from any directory refused: %v", multi, err)
		}
	}
}

func TestEntraIssuerRule(t *testing.T) {
	const tid = "11111111-1111-1111-1111-111111111111"
	iss := func(d string) string { return "https://login.microsoftonline.com/" + d + "/v2.0" }
	tests := []struct {
		name, configured, issuer, tid string
		wantErr                       bool
	}{
		{"single-tenant match", tid, iss(tid), tid, false},
		{"single-tenant dir mismatch", tid, iss("other"), "other", true},
		{"issuer/tid inconsistent", tid, iss("x"), tid, true},
		{"missing tid", tid, iss(tid), "", true},
		{"common accepts any", "common", iss("anydir"), "anydir", false},
		{"empty accepts any", "", iss("anydir"), "anydir", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := &Claims{TID: tc.tid, RegisteredClaims: jwtv5.RegisteredClaims{Issuer: tc.issuer}}
			if err := EntraIssuer(tc.configured)(c); (err != nil) != tc.wantErr {
				t.Errorf("err = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}

func TestOktaAndGoogleIssuerRules(t *testing.T) {
	is := func(iss string) *Claims { return &Claims{RegisteredClaims: jwtv5.RegisteredClaims{Issuer: iss}} }
	okta := OktaIssuer("https://acme.okta.com/")
	if err := okta(is("https://acme.okta.com/oauth2/default")); err != nil {
		t.Fatalf("own issuer rejected: %v", err)
	}
	if err := okta(is("https://evil.okta.com/oauth2/default")); err == nil {
		t.Fatal("another org's issuer accepted")
	}
	for _, ok := range []string{"https://accounts.google.com", "accounts.google.com"} {
		if err := GoogleIssuer(is(ok)); err != nil {
			t.Fatal(err)
		}
	}
	if err := GoogleIssuer(is("https://evil.example.com")); err == nil {
		t.Fatal("non-Google issuer accepted")
	}
}

func TestMaxAuthAge(t *testing.T) {
	p := newTestIdP(t)
	c := p.client()
	exp := p.expect()
	exp.MaxAuthAge = time.Minute
	at := func(authTime any) string {
		m := p.baseClaims()
		if authTime != nil {
			m["auth_time"] = authTime
		}
		return p.sign(t, m)
	}
	if _, err := c.VerifyIDToken(context.Background(), at(time.Now().Unix()), exp); err != nil {
		t.Fatalf("fresh authentication refused: %v", err)
	}
	for name, raw := range map[string]string{
		"no auth_time":    at(nil),
		"an hour ago":     at(time.Now().Add(-time.Hour).Unix()),
		"in the future":   at(time.Now().Add(time.Hour).Unix()),
		"not a timestamp": at("yesterday"),
	} {
		if _, err := c.VerifyIDToken(context.Background(), raw, exp); err == nil {
			t.Fatalf("%s: accepted as a fresh authentication", name)
		}
	}
	// Without MaxAuthAge an old auth_time is fine (a normal sign-in).
	if _, err := c.VerifyIDToken(context.Background(), at(time.Now().Add(-24*time.Hour).Unix()), p.expect()); err != nil {
		t.Fatal(err)
	}
}

// A provider outage does not end every session: keys fetched within
// jwksMaxStale still verify known kids, and stop after it.
func TestJWKSStaleGraceOnOutage(t *testing.T) {
	p := newTestIdP(t)
	clock := time.Now()
	c := p.client()
	c.now = func() time.Time { return clock }
	policy := accessPolicy(p)
	claims := func() jwtv5.MapClaims {
		m := p.baseClaims()
		m["iat"], m["exp"] = clock.Unix(), clock.Add(5*time.Minute).Unix()
		return m
	}
	if err := c.VerifyJWT(context.Background(), p.sign(t, claims()), jwtv5.MapClaims{}, policy); err != nil {
		t.Fatal(err)
	}
	p.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	clock = clock.Add(2 * time.Hour) // past jwksTTL, within jwksMaxStale
	if err := c.VerifyJWT(context.Background(), p.sign(t, claims()), jwtv5.MapClaims{}, policy); err != nil {
		t.Fatalf("known kid refused during an outage within the grace: %v", err)
	}
	clock = clock.Add(jwksMaxStale)
	err := c.VerifyJWT(context.Background(), p.sign(t, claims()), jwtv5.MapClaims{}, policy)
	if !errors.Is(err, ErrJWKSUnavailable) {
		t.Fatalf("keys older than the grace must not verify, got %v", err)
	}
}

func TestVerifyJWTRefusesIncompletePolicy(t *testing.T) {
	p := newTestIdP(t)
	raw := p.sign(t, p.baseClaims())
	for name, pol := range map[string]TokenPolicy{
		"no JWKS":     {Issuer: p.issuer, Audience: "client-1"},
		"no issuer":   {JWKSURI: p.srv.URL + "/jwks", Audience: "client-1"},
		"no audience": {JWKSURI: p.srv.URL + "/jwks", Issuer: p.issuer},
	} {
		if err := p.client().VerifyJWT(context.Background(), raw, jwtv5.MapClaims{}, pol); err == nil {
			t.Fatalf("%s: verified", name)
		}
	}
}

func TestParseJWKSRefusals(t *testing.T) {
	for name, body := range map[string]string{
		"no keys":          `{"keys":[]}`,
		"not json":         `not json`,
		"small RSA key":    `{"keys":[{"kty":"RSA","kid":"k","n":"AQAB","e":"AQAB"}]}`,
		"encryption key":   `{"keys":[{"kty":"RSA","kid":"k","use":"enc","n":"AQAB","e":"AQAB"}]}`,
		"symmetric key":    `{"keys":[{"kty":"oct","kid":"k","k":"c2VjcmV0"}]}`,
		"unsupported kind": `{"keys":[{"kty":"OKP","kid":"k","crv":"Ed25519","x":"AA"}]}`,
	} {
		if _, err := parseJWKS([]byte(body)); err == nil {
			t.Fatalf("%s: parsed", name)
		}
	}
}

// swapSignature puts b's signature on a's header and payload.
func swapSignature(t *testing.T, a, b string) string {
	t.Helper()
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	return pa[0] + "." + pa[1] + "." + pb[2]
}

// tamperPayload flips one character of the payload, keeping the signature.
func tamperPayload(raw string) string {
	parts := strings.Split(raw, ".")
	b := []byte(parts[1])
	if b[5] == 'A' {
		b[5] = 'B'
	} else {
		b[5] = 'A'
	}
	return parts[0] + "." + string(b) + "." + parts[2]
}
