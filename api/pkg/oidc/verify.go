package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
)

// The one verification core. Every signed token the API accepts from an
// identity provider goes through VerifyJWT: tenant SSO and platform-admin
// id_tokens (VerifyIDToken), OIDC back-channel logout tokens, CI workload
// tokens (VerifyWorkloadToken) and the external OIDC provider's access tokens
// (pkg/keycloak). What a flow additionally expects (nonce, azp, jti, roles)
// is checked by that flow on top of it. Which issuers a flow trusts is
// configured separately per flow and never shared: an IdP trusted for
// sign-in is not trusted for CI, and the other way round.

// MaxTokenSize bounds a raw token before any parsing.
const MaxTokenSize = 32 << 10

// ErrTokenSize means the token is empty or larger than MaxTokenSize.
var ErrTokenSize = errors.New("token is empty or too large")

// signingMethods are the accepted signature algorithms. HMAC and "none" are
// never accepted, and the key type must match the algorithm, so a public key
// can never be used as an HMAC secret.
var signingMethods = []string{"RS256", "RS384", "RS512", "PS256", "ES256"}

// TokenPolicy is what VerifyJWT checks. Leaving the issuer or the audience
// unchecked must be asked for explicitly, so a missing value fails closed.
type TokenPolicy struct {
	// JWKSURI is where the signing keys are fetched (through the URL guard).
	JWKSURI string
	// Issuer is the exact iss. Empty only with IssuerCheckedByCaller.
	Issuer string
	// IssuerCheckedByCaller: the issuer depends on a claim (an Entra issuer
	// embeds the directory id) and the caller checks it after VerifyJWT.
	IssuerCheckedByCaller bool
	// Audience must be one of aud. Empty only with AudienceCheckedByCaller.
	Audience string
	// AudienceCheckedByCaller: the caller accepts several audiences, or aud
	// or azp, and checks them after VerifyJWT.
	AudienceCheckedByCaller bool
	// Leeway is the clock skew tolerated on exp, nbf and iat.
	Leeway time.Duration
	// ExpOptional allows a token without exp (an OIDC logout token).
	ExpOptional bool
}

var errIncompletePolicy = errors.New("incomplete token policy")

// VerifyJWT verifies raw and decodes it into claims: size cap, algorithm
// allowlist, signature against the JWKS key named by kid (with the key type
// matching the algorithm), iss, aud, exp, nbf and iat not in the future.
// Every failure is an error and the caller must refuse the token.
func (c *Client) VerifyJWT(ctx context.Context, raw string, claims jwtv5.Claims, p TokenPolicy) error {
	if raw == "" || len(raw) > MaxTokenSize {
		return ErrTokenSize
	}
	if p.JWKSURI == "" ||
		(p.Issuer == "" && !p.IssuerCheckedByCaller) ||
		(p.Audience == "" && !p.AudienceCheckedByCaller) {
		return errIncompletePolicy
	}
	opts := []jwtv5.ParserOption{
		jwtv5.WithValidMethods(signingMethods),
		jwtv5.WithIssuedAt(),
		jwtv5.WithLeeway(p.Leeway),
		jwtv5.WithTimeFunc(c.now),
	}
	if !p.ExpOptional {
		opts = append(opts, jwtv5.WithExpirationRequired())
	}
	if p.Issuer != "" {
		opts = append(opts, jwtv5.WithIssuer(p.Issuer))
	}
	if p.Audience != "" {
		opts = append(opts, jwtv5.WithAudience(p.Audience))
	}
	keyFunc := func(t *jwtv5.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		key, err := c.key(ctx, p.JWKSURI, kid)
		if err != nil {
			return nil, err
		}
		switch t.Method.(type) {
		case *jwtv5.SigningMethodRSA, *jwtv5.SigningMethodRSAPSS:
			if _, ok := key.(*rsa.PublicKey); !ok {
				return nil, errors.New("key type does not match alg")
			}
		case *jwtv5.SigningMethodECDSA:
			if _, ok := key.(*ecdsa.PublicKey); !ok {
				return nil, errors.New("key type does not match alg")
			}
		default:
			return nil, errors.New("unsupported alg")
		}
		return key, nil
	}
	_, err := jwtv5.NewParser(opts...).ParseWithClaims(raw, claims, keyFunc)
	return err
}
