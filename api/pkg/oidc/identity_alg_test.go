package oidc

import (
	"context"
	"testing"

	jwtv5 "github.com/golang-jwt/jwt/v5"
)

func (p *testIdP) signWith(t *testing.T, m jwtv5.SigningMethod, claims jwtv5.MapClaims) string {
	t.Helper()
	tok := jwtv5.NewWithClaims(m, claims)
	tok.Header["kid"] = "rsa1"
	s, err := tok.SignedString(p.key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// T6: a sign-in id_token is accepted only with RS256, PS256 or ES256, even
// when it is validly signed by the provider's own key with another RSA hash.
func TestIDTokenAlgorithmAllowList(t *testing.T) {
	p := newTestIdP(t)
	c := p.client()
	ctx := context.Background()

	for name, m := range map[string]jwtv5.SigningMethod{
		"RS384": jwtv5.SigningMethodRS384,
		"RS512": jwtv5.SigningMethodRS512,
		"PS384": jwtv5.SigningMethodPS384,
		"PS512": jwtv5.SigningMethodPS512,
	} {
		t.Run(name+" refused", func(t *testing.T) {
			if _, err := c.VerifyIDToken(ctx, p.signWith(t, m, p.baseClaims()), p.expect()); err == nil {
				t.Fatalf("%s id_token must be refused", name)
			}
		})
	}
	for name, m := range map[string]jwtv5.SigningMethod{
		"RS256": jwtv5.SigningMethodRS256,
		"PS256": jwtv5.SigningMethodPS256,
	} {
		t.Run(name+" accepted", func(t *testing.T) {
			if _, err := c.VerifyIDToken(ctx, p.signWith(t, m, p.baseClaims()), p.expect()); err != nil {
				t.Fatalf("%s id_token must be accepted: %v", name, err)
			}
		})
	}
}

// A policy can only narrow the shared allowlist: an algorithm outside it is
// ignored, and a policy left with none is incomplete. Without a policy list
// the shared allowlist still applies (other flows keep RS512).
func TestTokenPolicyAlgorithmsOnlyNarrow(t *testing.T) {
	p := newTestIdP(t)
	c := p.client()
	ctx := context.Background()
	base := TokenPolicy{JWKSURI: p.srv.URL + "/jwks", Issuer: p.issuer, Audience: "client-1", Leeway: signInLeeway}

	widen := base
	widen.Algorithms = []string{"HS256", "none"}
	if err := c.VerifyJWT(ctx, p.signWith(t, jwtv5.SigningMethodRS256, p.baseClaims()), &Claims{}, widen); err == nil {
		t.Fatal("a policy naming only algorithms outside the allowlist must be refused")
	}
	if err := c.VerifyJWT(ctx, p.signWith(t, jwtv5.SigningMethodRS512, p.baseClaims()), &Claims{}, base); err != nil {
		t.Fatalf("the shared allowlist still accepts RS512 for other flows: %v", err)
	}
	if got := allowedMethods([]string{"RS256", "HS256"}); len(got) != 1 || got[0] != "RS256" {
		t.Fatalf("allowedMethods = %v", got)
	}
}
