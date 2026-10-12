package mcpoauth_test

// DPoP-bound grants (RFC 9449, RFC-062 §9) over a migrated database.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/openctemio/openctem/api/internal/app/mcpoauth"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// memReplay is an in-memory replay cache.
type memReplay struct {
	mu   sync.Mutex
	seen map[string]bool
}

func (m *memReplay) FirstUse(_ context.Context, key string, _ time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.seen[key] {
		return false, nil
	}
	m.seen[key] = true
	return true, nil
}

type dpopKey struct {
	t   *testing.T
	key *ecdsa.PrivateKey
}

func newDPoPKey(t *testing.T) dpopKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return dpopKey{t: t, key: k}
}

// proof signs a DPoP proof for method+url; token, when set, is hashed into ath.
func (k dpopKey) proof(method, u, token string) string {
	pad := func(b []byte) []byte { out := make([]byte, 32); copy(out[32-len(b):], b); return out }
	enc := base64.RawURLEncoding
	c := jwt.MapClaims{"htm": method, "htu": u, "iat": time.Now().Unix(), "jti": uuid.NewString()}
	if token != "" {
		sum := sha256.Sum256([]byte(token))
		c["ath"] = enc.EncodeToString(sum[:])
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, c)
	tok.Header["typ"] = "dpop+jwt"
	tok.Header["jwk"] = map[string]any{"kty": "EC", "crv": "P-256", "x": enc.EncodeToString(pad(k.key.X.Bytes())), "y": enc.EncodeToString(pad(k.key.Y.Bytes()))}
	s, err := tok.SignedString(k.key)
	if err != nil {
		k.t.Fatal(err)
	}
	return s
}

const tokenEndpoint = issuer + "/oauth/token"

func (h *harness) dpopService() *mcpoauth.Service {
	h.t.Helper()
	cfg := h.cfg
	cfg.Replay = &memReplay{seen: map[string]bool{}}
	svc, err := mcpoauth.NewService(cfg)
	if err != nil {
		h.t.Fatal(err)
	}
	return svc
}

func TestDPoPBoundGrant(t *testing.T) {
	h := newHarness(t)
	svc := h.dpopService()
	ctx := context.Background()
	user := h.member(h.tenant, "owner")
	key := newDPoPKey(t)
	code := h.approve(user, h.tenant, authorizeQuery(nil))
	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier},
		"client_id": {clientID}, "redirect_uri": {redirect}, "resource": {resource},
	}
	tok, oerr := svc.Token(ctx, form, key.proof("POST", tokenEndpoint, ""), mcpoauth.Actor{})
	if oerr != nil || tok.TokenType != "DPoP" {
		t.Fatalf("exchange: %+v %v", tok, oerr)
	}

	auth := func(scheme, proof string) error {
		_, err := svc.AuthenticateAccessToken(ctx, tok.AccessToken, "198.51.100.1", mcpoauth.DPoPRequest{Scheme: scheme, Proof: proof, Method: "POST"})
		return err
	}
	good := key.proof("POST", resource, tok.AccessToken)
	if err := auth("DPoP", good); err != nil {
		t.Fatalf("valid proof refused: %v", err)
	}
	other := newDPoPKey(t)
	for name, err := range map[string]error{
		"bearer scheme":     auth("Bearer", ""),
		"no proof":          auth("DPoP", ""),
		"replayed proof":    auth("DPoP", good),
		"other key":         auth("DPoP", other.proof("POST", resource, tok.AccessToken)),
		"proof without ath": auth("DPoP", key.proof("POST", resource, "")),
		"other url":         auth("DPoP", key.proof("POST", issuer+"/api/v1/other", tok.AccessToken)),
		"other method":      auth("DPoP", key.proof("GET", resource, tok.AccessToken)),
	} {
		if !errors.Is(err, mcpoauth.ErrDPoP) {
			t.Errorf("%s: %v, want ErrDPoP", name, err)
		}
	}

	// Refresh: the same key only.
	refresh := func(proof string) (*mcpoauth.TokenResponse, *mcpoauth.OAuthError) {
		return svc.Token(ctx, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok.RefreshToken}, "client_id": {clientID}}, proof, mcpoauth.Actor{})
	}
	if _, oerr := refresh(""); oerr == nil || oerr.Code != "invalid_dpop_proof" {
		t.Fatalf("refresh without proof: %v", oerr)
	}
	if _, oerr := refresh(other.proof("POST", tokenEndpoint, "")); oerr == nil {
		t.Fatal("refresh with another key")
	}
	next, oerr := refresh(key.proof("POST", tokenEndpoint, ""))
	if oerr != nil || next.TokenType != "DPoP" {
		t.Fatalf("refresh with the key: %+v %v", next, oerr)
	}
}

func TestBearerTokenCannotClaimDPoP(t *testing.T) {
	h := newHarness(t)
	svc := h.dpopService()
	user := h.member(h.tenant, "owner")
	tok, oerr := h.exchange(h.approve(user, h.tenant, authorizeQuery(nil)), verifier, nil)
	if oerr != nil || tok.TokenType != "Bearer" {
		t.Fatalf("%+v %v", tok, oerr)
	}
	key := newDPoPKey(t)
	_, err := svc.AuthenticateAccessToken(context.Background(), tok.AccessToken, "198.51.100.1",
		mcpoauth.DPoPRequest{Scheme: "DPoP", Proof: key.proof("POST", resource, tok.AccessToken), Method: "POST"})
	if !errors.Is(err, mcpoauth.ErrDPoP) {
		t.Fatalf("bearer token under the DPoP scheme: %v", err)
	}
}

func TestPolicyRequiresDPoP(t *testing.T) {
	h := newHarness(t)
	svc := h.dpopService()
	ctx := context.Background()
	user := h.member(h.tenant, "owner")
	bearer, oerr := h.exchange(h.approve(user, h.tenant, authorizeQuery(nil)), verifier, nil)
	if oerr != nil {
		t.Fatal(oerr)
	}
	h.policies[h.tenant] = tenantdom.MCPSettings{RequireDPoP: true}
	// An existing bearer connection stops working.
	if _, err := svc.AuthenticateAccessToken(ctx, bearer.AccessToken, "198.51.100.1", mcpoauth.DPoPRequest{Scheme: "Bearer", Method: "POST"}); err == nil {
		t.Fatal("bearer token works under require_dpop")
	}
	// A new code exchange without a proof is refused; with one it works.
	form := func(code string) url.Values {
		return url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier},
			"client_id": {clientID}, "redirect_uri": {redirect}, "resource": {resource}}
	}
	if _, oerr := svc.Token(ctx, form(h.approve(user, h.tenant, authorizeQuery(nil))), "", mcpoauth.Actor{}); oerr == nil || oerr.Code != "invalid_dpop_proof" {
		t.Fatalf("exchange without proof: %v", oerr)
	}
	key := newDPoPKey(t)
	if _, oerr := svc.Token(ctx, form(h.approve(user, h.tenant, authorizeQuery(nil))), key.proof("POST", tokenEndpoint, ""), mcpoauth.Actor{}); oerr != nil {
		t.Fatalf("exchange with proof: %v", oerr)
	}
}

func TestDPoPWithoutReplayCacheFailsClosed(t *testing.T) {
	h := newHarness(t)
	user := h.member(h.tenant, "owner")
	key := newDPoPKey(t)
	code := h.approve(user, h.tenant, authorizeQuery(nil))
	// h.svc has no replay cache: proofs are refused, and the code survives
	// (the proof is checked before the code is redeemed).
	if _, oerr := h.svc.Token(context.Background(), url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier},
		"client_id": {clientID}, "redirect_uri": {redirect}, "resource": {resource},
	}, key.proof("POST", tokenEndpoint, ""), mcpoauth.Actor{}); oerr == nil {
		t.Fatal("proof accepted without a replay cache")
	}
	if _, oerr := h.exchange(code, verifier, nil); oerr != nil {
		t.Fatalf("code burned by a refused proof: %v", oerr)
	}
}
