package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
)

// pastedIssuer is never reachable: a pasted key set must not need it.
const pastedIssuer = "https://gitlab.example.com"

type pastedFixture struct {
	rsa *rsa.PrivateKey
	ec  *ecdsa.PrivateKey
}

func newPastedFixture(t *testing.T) *pastedFixture {
	t.Helper()
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ek, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &pastedFixture{rsa: rk, ec: ek}
}

func rsaJWK(k *rsa.PublicKey, kid string) map[string]any {
	return map[string]any{"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
		"n": base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes())}
}

func ecJWK(t *testing.T, k *ecdsa.PublicKey, kid string) map[string]any {
	t.Helper()
	pt, err := k.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{"kty": "EC", "kid": kid, "crv": "P-256",
		"x": base64.RawURLEncoding.EncodeToString(pt[1:33]), "y": base64.RawURLEncoding.EncodeToString(pt[33:])}
}

func jwksDoc(t *testing.T, keys ...map[string]any) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{"keys": keys})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (f *pastedFixture) doc(t *testing.T) []byte {
	return jwksDoc(t, rsaJWK(&f.rsa.PublicKey, "rsa-pasted"), ecJWK(t, &f.ec.PublicKey, "ec-pasted"))
}

func pastedClaims() jwtv5.MapClaims {
	now := time.Now()
	return jwtv5.MapClaims{"iss": pastedIssuer, "sub": "project_path:acme/api:ref_type:branch:ref:main",
		"aud": "openctem:tenant:t1", "exp": now.Add(5 * time.Minute).Unix(), "iat": now.Unix(),
		"nbf": now.Unix(), "jti": "jti-pasted"}
}

func signPasted(t *testing.T, m jwtv5.SigningMethod, key any, kid string, c jwtv5.MapClaims) string {
	t.Helper()
	tok := jwtv5.NewWithClaims(m, c)
	if kid != "" {
		tok.Header["kid"] = kid
	}
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// noNetworkClient fails the test on any outbound request and counts them.
func noNetworkClient(t *testing.T, calls *atomic.Int32) *Client {
	t.Helper()
	rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		t.Errorf("network call in pasted-key mode: %s", r.URL)
		return nil, errors.New("no network")
	})
	return NewClient(&http.Client{Transport: rt}, func(u string) error {
		calls.Add(1)
		t.Errorf("URL check in pasted-key mode: %s", u)
		return errors.New("no network")
	})
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestParseStaticJWKSAccepts(t *testing.T) {
	f := newPastedFixture(t)
	set, err := ParseStaticJWKS(f.doc(t))
	if err != nil {
		t.Fatalf("valid document refused: %v", err)
	}
	got := set.Keys()
	if len(got) != 2 || got[0] != (PastedKey{KID: "ec-pasted", Alg: "ES256"}) || got[1] != (PastedKey{KID: "rsa-pasted", Alg: "RS256"}) {
		t.Fatalf("keys = %+v", got)
	}
	// alg and use may be absent.
	k := rsaJWK(&f.rsa.PublicKey, "a")
	delete(k, "alg")
	delete(k, "use")
	if _, err := ParseStaticJWKS(jwksDoc(t, k)); err != nil {
		t.Fatalf("key without alg and use refused: %v", err)
	}
}

func TestParseStaticJWKSRefusals(t *testing.T) {
	f := newPastedFixture(t)
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	with := func(k map[string]any, set map[string]any, del ...string) map[string]any {
		out := map[string]any{}
		for n, v := range k {
			out[n] = v
		}
		for n, v := range set {
			out[n] = v
		}
		for _, n := range del {
			delete(out, n)
		}
		return out
	}
	r := rsaJWK(&f.rsa.PublicKey, "r1")
	e := ecJWK(t, &f.ec.PublicKey, "e1")
	many := make([]map[string]any, MaxPastedKeys+1)
	for i := range many {
		many[i] = rsaJWK(&f.rsa.PublicKey, "k"+string(rune('a'+i)))
	}
	cases := map[string]struct {
		doc  []byte
		want string
	}{
		"empty":              {[]byte("  "), "empty"},
		"not json":           {[]byte("-----BEGIN PUBLIC KEY-----"), "valid JSON"},
		"single key object":  {mustJSON(t, r), "no keys"},
		"no keys":            {[]byte(`{"keys":[]}`), "no keys"},
		"too many keys":      {jwksDoc(t, many...), "at most 10"},
		"too large":          {[]byte(`{"keys":[],"pad":"` + strings.Repeat("a", MaxPastedJWKSSize) + `"}`), "larger than 64 KiB"},
		"no kid":             {jwksDoc(t, with(r, nil, "kid")), "no key id"},
		"duplicate kid":      {jwksDoc(t, r, rsaJWK(&f.rsa.PublicKey, "r1")), "appears twice"},
		"use enc":            {jwksDoc(t, with(r, map[string]any{"use": "enc"})), "only signing keys"},
		"rsa alg RS512":      {jwksDoc(t, with(r, map[string]any{"alg": "RS512"})), "must be RS256"},
		"rsa alg PS256":      {jwksDoc(t, with(r, map[string]any{"alg": "PS256"})), "must be RS256"},
		"ec alg ES384":       {jwksDoc(t, with(e, map[string]any{"alg": "ES384"})), "must be ES256"},
		"ec P-384":           {jwksDoc(t, ecP384(t, p384)), "P-256"},
		"rsa 1024":           {jwksDoc(t, rsaJWK(&small.PublicKey, "small")), "2048"},
		"oct key":            {jwksDoc(t, map[string]any{"kty": "oct", "kid": "h"}), "key type"},
		"okp key":            {jwksDoc(t, map[string]any{"kty": "OKP", "kid": "o", "crv": "Ed25519", "x": "AA"}), "key type"},
		"kid not a string":   {jwksDoc(t, with(r, map[string]any{"kid": 7})), "must be a string"},
		"kid control chars":  {jwksDoc(t, with(r, map[string]any{"kid": "a\nb"})), "not valid"},
		"private d":          {jwksDoc(t, with(r, map[string]any{"d": "AQAB"})), `private key material ("d")`},
		"private p":          {jwksDoc(t, with(r, map[string]any{"p": "AQAB"})), `("p")`},
		"private q":          {jwksDoc(t, with(r, map[string]any{"q": "AQAB"})), `("q")`},
		"private dp":         {jwksDoc(t, with(r, map[string]any{"dp": "AQAB"})), `("dp")`},
		"private dq":         {jwksDoc(t, with(r, map[string]any{"dq": "AQAB"})), `("dq")`},
		"private qi":         {jwksDoc(t, with(r, map[string]any{"qi": "AQAB"})), `("qi")`},
		"private ec d":       {jwksDoc(t, with(e, map[string]any{"d": "AQAB"})), `("d")`},
		"symmetric k":        {jwksDoc(t, map[string]any{"kty": "oct", "kid": "s", "k": "c2VjcmV0"}), `("k")`},
		"private second key": {jwksDoc(t, r, with(e, map[string]any{"d": "AQAB"})), "key 2"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseStaticJWKS(tc.doc)
			if err == nil {
				t.Fatal("document accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not say %q", err, tc.want)
			}
		})
	}
}

func ecP384(t *testing.T, k *ecdsa.PrivateKey) map[string]any {
	t.Helper()
	pt, err := k.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	n := (len(pt) - 1) / 2
	return map[string]any{"kty": "EC", "kid": "p384", "crv": "P-384",
		"x": base64.RawURLEncoding.EncodeToString(pt[1 : 1+n]), "y": base64.RawURLEncoding.EncodeToString(pt[1+n:])}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestVerifyWorkloadTokenPastedKeys(t *testing.T) {
	f := newPastedFixture(t)
	set, err := ParseStaticJWKS(f.doc(t))
	if err != nil {
		t.Fatal(err)
	}
	exp := WorkloadExpectations{Issuer: pastedIssuer, Audience: "openctem:tenant:t1", Keys: set}
	var calls atomic.Int32
	c := noNetworkClient(t, &calls)

	t.Run("rsa key matches", func(t *testing.T) {
		tok, err := c.VerifyWorkloadToken(context.Background(), signPasted(t, jwtv5.SigningMethodRS256, f.rsa, "rsa-pasted", pastedClaims()), exp)
		if err != nil {
			t.Fatalf("token refused: %v", err)
		}
		if tok.KeyID != "rsa-pasted" || tok.JTI != "jti-pasted" {
			t.Fatalf("token = %+v", tok)
		}
	})
	t.Run("ec key matches", func(t *testing.T) {
		tok, err := c.VerifyWorkloadToken(context.Background(), signPasted(t, jwtv5.SigningMethodES256, f.ec, "ec-pasted", pastedClaims()), exp)
		if err != nil || tok.KeyID != "ec-pasted" {
			t.Fatalf("token = %+v, err = %v", tok, err)
		}
	})
	t.Run("unknown kid", func(t *testing.T) {
		_, err := c.VerifyWorkloadToken(context.Background(), signPasted(t, jwtv5.SigningMethodRS256, f.rsa, "rotated", pastedClaims()), exp)
		if !errors.Is(err, ErrPastedKeyUnknown) {
			t.Fatalf("err = %v, want ErrPastedKeyUnknown", err)
		}
		if errors.Is(err, ErrJWKSUnavailable) || errors.Is(err, ErrKeyNotFound) {
			t.Fatalf("pasted mode reported a fetch error: %v", err)
		}
	})
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	refused := map[string]string{
		"wrong alg for rsa key":   signPasted(t, jwtv5.SigningMethodRS384, f.rsa, "rsa-pasted", pastedClaims()),
		"pss with rsa key":        signPasted(t, jwtv5.SigningMethodPS256, f.rsa, "rsa-pasted", pastedClaims()),
		"rsa alg on ec kid":       signPasted(t, jwtv5.SigningMethodRS256, f.rsa, "ec-pasted", pastedClaims()),
		"hmac":                    signPasted(t, jwtv5.SigningMethodHS256, []byte("secret"), "rsa-pasted", pastedClaims()),
		"forged with known kid":   signPasted(t, jwtv5.SigningMethodRS256, other, "rsa-pasted", pastedClaims()),
		"no kid, several keys":    signPasted(t, jwtv5.SigningMethodRS256, f.rsa, "", pastedClaims()),
		"expired":                 signPasted(t, jwtv5.SigningMethodRS256, f.rsa, "rsa-pasted", with(pastedClaims(), "exp", time.Now().Add(-10*time.Minute).Unix())),
		"not yet valid":           signPasted(t, jwtv5.SigningMethodRS256, f.rsa, "rsa-pasted", with(pastedClaims(), "nbf", time.Now().Add(10*time.Minute).Unix())),
		"wrong issuer":            signPasted(t, jwtv5.SigningMethodRS256, f.rsa, "rsa-pasted", with(pastedClaims(), "iss", "https://evil.example")),
		"wrong audience":          signPasted(t, jwtv5.SigningMethodRS256, f.rsa, "rsa-pasted", with(pastedClaims(), "aud", "openctem:tenant:t2")),
		"lifetime too long":       signPasted(t, jwtv5.SigningMethodRS256, f.rsa, "rsa-pasted", with(pastedClaims(), "exp", time.Now().Add(48*time.Hour).Unix())),
		"no jti":                  signPasted(t, jwtv5.SigningMethodRS256, f.rsa, "rsa-pasted", without(pastedClaims(), "jti")),
		"alg none with known kid": signPasted(t, jwtv5.SigningMethodNone, jwtv5.UnsafeAllowNoneSignatureType, "rsa-pasted", pastedClaims()),
	}
	for name, raw := range refused {
		t.Run(name, func(t *testing.T) {
			if _, err := c.VerifyWorkloadToken(context.Background(), raw, exp); err == nil {
				t.Fatal("token accepted")
			}
		})
	}
	if n := calls.Load(); n != 0 {
		t.Fatalf("%d network calls in pasted-key mode", n)
	}
}

// A one-key set verifies a token without a kid, as a fetched one-key JWKS does.
func TestVerifyWorkloadTokenPastedSingleKeyNoKID(t *testing.T) {
	f := newPastedFixture(t)
	set, err := ParseStaticJWKS(jwksDoc(t, rsaJWK(&f.rsa.PublicKey, "only")))
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	tok, err := noNetworkClient(t, &calls).VerifyWorkloadToken(context.Background(),
		signPasted(t, jwtv5.SigningMethodRS256, f.rsa, "", pastedClaims()),
		WorkloadExpectations{Issuer: pastedIssuer, Audience: "openctem:tenant:t1", Keys: set})
	if err != nil || tok.KeyID != "" {
		t.Fatalf("token = %+v, err = %v", tok, err)
	}
}

// Narrowing the algorithms for a pasted set must not change the shared
// allowlist other verifications use.
func TestPastedKeysDoNotNarrowSharedAllowlist(t *testing.T) {
	before := append([]string(nil), signingMethods...)
	f := newPastedFixture(t)
	set, err := ParseStaticJWKS(jwksDoc(t, rsaJWK(&f.rsa.PublicKey, "only")))
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	_, _ = noNetworkClient(t, &calls).VerifyWorkloadToken(context.Background(),
		signPasted(t, jwtv5.SigningMethodRS256, f.rsa, "only", pastedClaims()),
		WorkloadExpectations{Issuer: pastedIssuer, Audience: "openctem:tenant:t1", Keys: set})
	if strings.Join(before, ",") != strings.Join(signingMethods, ",") {
		t.Fatalf("shared allowlist changed: %v -> %v", before, signingMethods)
	}
}

func with(c jwtv5.MapClaims, k string, v any) jwtv5.MapClaims {
	c[k] = v
	return c
}

func without(c jwtv5.MapClaims, k string) jwtv5.MapClaims {
	delete(c, k)
	return c
}
