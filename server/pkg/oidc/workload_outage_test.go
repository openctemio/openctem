package oidc

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
)

// An issuer outage: the last discovery document and keys keep verifying for
// jwksMaxStale, concurrent refreshes collapse into one fetch, a failed fetch
// is not repeated within jwksMinRefresh, and past jwksMaxStale the error is
// ErrJWKSUnavailable (the caller may answer "retry later").
func TestWorkloadIssuerOutage(t *testing.T) {
	p := newTestIdP(t)
	var down atomic.Bool
	var discoveries atomic.Int32
	inner := p.srv.Config.Handler
	p.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			discoveries.Add(1)
		}
		if down.Load() {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		inner.ServeHTTP(w, r)
	})
	now := time.Now()
	var clock atomic.Int64
	clock.Store(now.UnixNano())
	c := p.client()
	c.now = func() time.Time { return time.Unix(0, clock.Load()) }
	verify := func() error { return c.verifyAt(t, p, clock.Load()) }
	if err := verify(); err != nil {
		t.Fatal(err)
	}

	// Two hours on, the issuer is down: the stale document and keys verify.
	down.Store(true)
	clock.Store(now.Add(2 * time.Hour).UnixNano())
	before := discoveries.Load()
	var wg sync.WaitGroup
	errs := make([]error, 10)
	for i := range errs {
		wg.Add(1)
		go func(i int) { defer wg.Done(); errs[i] = c.verifyAt(t, p, clock.Load()) }(i)
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatalf("stale discovery and keys refused during an outage: %v", err)
		}
	}
	if n := discoveries.Load() - before; n != 1 {
		t.Fatalf("%d discovery fetches for 10 concurrent exchanges, want 1", n)
	}

	// Past jwksMaxStale: unavailable, as a typed error.
	clock.Store(now.Add(jwksMaxStale + time.Hour).UnixNano())
	if err := verify(); !errors.Is(err, ErrJWKSUnavailable) {
		t.Fatalf("past the stale bound: %v, want ErrJWKSUnavailable", err)
	}
}

// verifyAt verifies a fresh token as of the given clock.
func (c *Client) verifyAt(t *testing.T, p *testIdP, nanos int64) error {
	claims := p.workloadClaims()
	at := time.Unix(0, nanos)
	claims["iat"], claims["nbf"], claims["exp"] = at.Unix(), at.Unix(), at.Add(5*time.Minute).Unix()
	_, err := c.VerifyWorkloadToken(context.Background(), p.sign(t, claims), p.workloadExpect())
	return err
}

// A kid the cached keys do not have is ErrKeyNotFound to the caller (a key
// rotation it may retry shortly), not a bare verification failure.
func TestWorkloadUnknownKidIsTyped(t *testing.T) {
	p := newTestIdP(t)
	c := p.client()
	tok := jwtv5.NewWithClaims(jwtv5.SigningMethodRS256, p.workloadClaims())
	tok.Header["kid"] = "rotated"
	raw, err := tok.SignedString(p.key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.VerifyWorkloadToken(context.Background(), raw, p.workloadExpect()); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("unknown kid: %v, want ErrKeyNotFound", err)
	}
}
