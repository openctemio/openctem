package internalapi

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type tokenOpts struct {
	key      ed25519.PrivateKey
	method   jwt.SigningMethod
	iss, aud string
	sub, jti string
	scope    string
	iat, exp time.Time
	noExp    bool
}

func sign(t *testing.T, o tokenOpts) string {
	t.Helper()
	claims := jwt.MapClaims{"iss": o.iss, "aud": o.aud, "sub": o.sub, "jti": o.jti, "scope": o.scope, "iat": o.iat.Unix()}
	if !o.noExp {
		claims["exp"] = o.exp.Unix()
	}
	m := o.method
	if m == nil {
		m = jwt.SigningMethodEdDSA
	}
	var key any = o.key
	if m == jwt.SigningMethodHS256 {
		key = []byte("shared-secret-shared-secret-32by")
	}
	if m == jwt.SigningMethodNone {
		key = jwt.UnsafeAllowNoneSignatureType
	}
	s, err := jwt.NewWithClaims(m, claims).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestVerifier(t *testing.T) {
	pub, priv := newKey(t)
	_, other := newKey(t)
	now := time.Now()
	v, err := NewVerifier([]ed25519.PublicKey{pub}, "openctem-cloud", NewMemoryReplayCache())
	if err != nil {
		t.Fatal(err)
	}
	ok := func(jti string) tokenOpts {
		return tokenOpts{key: priv, iss: "openctem-cloud", aud: Audience, sub: "cloud", jti: jti, scope: "limits:write usage:read",
			iat: now, exp: now.Add(2 * time.Minute)}
	}
	ctx := context.Background()

	c, _, err := v.Verify(ctx, sign(t, ok("a")))
	if err != nil || c.Subject != "cloud" || !c.Has(ScopeLimitsWrite) || !c.Has(ScopeUsageRead) || c.Has(ScopeOrgsProvision) {
		t.Fatalf("valid token: %+v %v", c, err)
	}
	if _, detail, err := v.Verify(ctx, sign(t, ok("a"))); !errors.Is(err, ErrUnauthenticated) || detail != "token: jti replayed" {
		t.Fatalf("replay must be refused: %v %s", err, detail)
	}

	cases := map[string]tokenOpts{}
	o := ok("b")
	o.key = other
	cases["key not configured"] = o
	o = ok("c")
	o.aud = "someone-else"
	cases["wrong audience"] = o
	o = ok("d")
	o.iss = "attacker"
	cases["wrong issuer"] = o
	o = ok("e")
	o.iat, o.exp = now.Add(-10*time.Minute), now.Add(-5*time.Minute)
	cases["expired"] = o
	o = ok("f")
	o.exp = now.Add(10 * time.Minute)
	cases["lifetime over 5 minutes"] = o
	o = ok("g")
	o.iat, o.exp = now.Add(3*time.Minute), now.Add(4*time.Minute)
	cases["issued in the future"] = o
	o = ok("")
	cases["no jti"] = o
	o = ok("h")
	o.sub = ""
	cases["no subject"] = o
	o = ok("i")
	o.noExp = true
	cases["no expiry"] = o
	o = ok("j")
	o.method = jwt.SigningMethodHS256
	cases["HS256 instead of EdDSA"] = o
	o = ok("k")
	o.method = jwt.SigningMethodNone
	cases["alg none"] = o
	for name, opts := range cases {
		if _, _, err := v.Verify(ctx, sign(t, opts)); !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("%s: want refusal, got %v", name, err)
		}
	}
	if _, _, err := v.Verify(ctx, "not-a-token"); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("garbage must be refused")
	}

	// Key rotation: either configured key verifies.
	pub2, priv2 := newKey(t)
	v2, _ := NewVerifier([]ed25519.PublicKey{pub, pub2}, "openctem-cloud", NewMemoryReplayCache())
	o = ok("rot")
	o.key = priv2
	if _, _, err := v2.Verify(ctx, sign(t, o)); err != nil {
		t.Fatalf("second key: %v", err)
	}
}

type failingReplay struct{}

func (failingReplay) FirstUse(context.Context, string, time.Time) (bool, error) {
	return false, errors.New("redis down")
}

func TestVerifierFailsClosedOnReplayCacheError(t *testing.T) {
	pub, priv := newKey(t)
	v, _ := NewVerifier([]ed25519.PublicKey{pub}, "openctem-cloud", failingReplay{})
	now := time.Now()
	tok := sign(t, tokenOpts{key: priv, iss: "openctem-cloud", aud: Audience, sub: "cloud", jti: "x", scope: "usage:read", iat: now, exp: now.Add(time.Minute)})
	if _, _, err := v.Verify(context.Background(), tok); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("an unreadable replay cache must refuse: %v", err)
	}
}

func TestParsePublicKeys(t *testing.T) {
	pub, _ := newKey(t)
	der, _ := x509.MarshalPKIXPublicKey(pub)
	one := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	keys, err := ParsePublicKeys(append(append([]byte{}, one...), one...))
	if err != nil || len(keys) != 2 {
		t.Fatalf("two keys: %d %v", len(keys), err)
	}
	if _, err := ParsePublicKeys([]byte("nothing")); err == nil {
		t.Fatal("no key must be refused")
	}
	if _, err := NewVerifier(nil, "x", NewMemoryReplayCache()); err == nil {
		t.Fatal("no key")
	}
	if _, err := NewVerifier(keys, "", NewMemoryReplayCache()); err == nil {
		t.Fatal("no issuer")
	}
}
