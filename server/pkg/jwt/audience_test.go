package jwt

import (
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
)

// TestGeneratedTokensCarryAudience asserts every public token-gen
// path embeds the DefaultAudience — so a downstream service can rely
// on the `aud` claim instead of trusting the signing key alone.
func TestGeneratedTokensCarryAudience(t *testing.T) {
	g := NewGenerator(TokenConfig{
		Secret:               "test-secret-32chars-minimum-len-ok",
		Issuer:               "openctem.api",
		AccessTokenDuration:  time.Minute,
		RefreshTokenDuration: time.Hour,
	})

	tok, _, err := g.GenerateAccessToken("u1", "s1", "admin")
	if err != nil {
		t.Fatalf("GenerateAccessToken: %v", err)
	}

	claims, err := ValidateToken(tok, "test-secret-32chars-minimum-len-ok")
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if len(claims.Audience) == 0 || claims.Audience[0] != DefaultAudience {
		t.Fatalf("want Audience=[%s], got %v", DefaultAudience, claims.Audience)
	}
}

// TestValidateToken_RejectsWrongAudience verifies that a token signed
// with this service's key but addressed to a DIFFERENT audience is
// rejected. That's the cross-service replay threat the claim closes.
func TestValidateToken_RejectsWrongAudience(t *testing.T) {
	secret := "test-secret-32chars-minimum-len-ok"
	now := time.Now()
	bad := gojwt.NewWithClaims(gojwt.SigningMethodHS256, Claims{
		UserID: "u1",
		RegisteredClaims: gojwt.RegisteredClaims{
			Audience:  gojwt.ClaimStrings{"some.other.service"},
			ExpiresAt: gojwt.NewNumericDate(now.Add(time.Minute)),
			IssuedAt:  gojwt.NewNumericDate(now),
			NotBefore: gojwt.NewNumericDate(now),
		},
	})
	signed, err := bad.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if _, err := ValidateToken(signed, secret); err == nil {
		t.Fatal("expected ValidateToken to reject a token with a foreign audience")
	}
}

// TestValidateToken_AcceptsLegacyTokenWithoutAud preserves the
// rollout contract: tokens issued before this change lack `aud` and
// must still parse so users don't all get kicked out. A follow-up
// release flips this to "audience required" once the issuance side
// has been live long enough for every active token to carry one.
func TestValidateToken_AcceptsLegacyTokenWithoutAud(t *testing.T) {
	secret := "test-secret-32chars-minimum-len-ok"
	now := time.Now()
	legacy := gojwt.NewWithClaims(gojwt.SigningMethodHS256, Claims{
		UserID: "u1",
		RegisteredClaims: gojwt.RegisteredClaims{
			// no Audience set
			ExpiresAt: gojwt.NewNumericDate(now.Add(time.Minute)),
			IssuedAt:  gojwt.NewNumericDate(now),
			NotBefore: gojwt.NewNumericDate(now),
		},
	})
	signed, err := legacy.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if _, err := ValidateToken(signed, secret); err != nil {
		t.Fatalf("legacy token without aud should still validate: %v", err)
	}
}
