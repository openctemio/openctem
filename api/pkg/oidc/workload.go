package oidc

// Workload identity tokens: the OIDC tokens CI providers (GitHub Actions,
// GitLab CI) give a job to prove which repository, ref and pipeline it is
// (docs/rfcs/RFC-051-ci-runner-identity-and-gate.md). Unlike an id_token they
// come with no nonce and no client; the audience is what the relying party
// told the job to ask for.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
)

// workloadLeeway is the clock skew tolerated on exp, nbf and iat. Smaller
// than the sign-in leeway: CI tokens live minutes.
const workloadLeeway = time.Minute

// MaxWorkloadTokenLifetime refuses tokens whose exp is further than this
// from their iat: a stolen long-lived token is worth more.
const MaxWorkloadTokenLifetime = 24 * time.Hour

// WorkloadExpectations pin a workload token to one issuer and audience.
type WorkloadExpectations struct {
	Issuer   string
	Audience string
}

// WorkloadToken is a verified workload token.
type WorkloadToken struct {
	Claims    map[string]any
	Issuer    string
	Subject   string
	JTI       string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// UnverifiedIssuer reads the iss claim of a token without verifying it, to
// choose which issuer to verify it against. Never trust anything else from
// an unverified token.
func UnverifiedIssuer(raw string) (string, error) {
	if raw == "" || len(raw) > MaxTokenSize {
		return "", errors.New("token is empty or too large")
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return "", errors.New("token is not a JWS compact serialization")
	}
	var claims struct {
		Iss string `json:"iss"`
	}
	payload, err := jwtv5.NewParser().DecodeSegment(parts[1])
	if err != nil || json.Unmarshal(payload, &claims) != nil || claims.Iss == "" {
		return "", errors.New("token has no readable issuer")
	}
	return claims.Iss, nil
}

// discoveredJWKS is the jwks_uri an issuer's discovery document named.
type discoveredJWKS struct {
	uri       string
	fetchedAt time.Time
}

// workloadJWKSURI returns the issuer's JWKS URI from its discovery document,
// cached for jwksTTL. The document's issuer must equal the issuer exactly and
// the JWKS must be served over https by the issuer's own host: a discovery
// document cannot point key retrieval somewhere else.
func (c *Client) workloadJWKSURI(ctx context.Context, issuer string) (string, error) {
	c.mu.Lock()
	if c.discovery == nil {
		c.discovery = map[string]discoveredJWKS{}
	}
	if d, ok := c.discovery[issuer]; ok && c.now().Sub(d.fetchedAt) < jwksTTL {
		c.mu.Unlock()
		return d.uri, nil
	}
	c.mu.Unlock()

	if err := ValidateIssuer(issuer); err != nil {
		return "", fmt.Errorf("issuer %w", err)
	}
	body, err := c.get(ctx, strings.TrimSuffix(issuer, "/")+"/.well-known/openid-configuration")
	if err != nil {
		return "", fmt.Errorf("discovery: %w", err)
	}
	var doc struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return "", errors.New("discovery: invalid document")
	}
	if doc.Issuer != issuer {
		return "", fmt.Errorf("discovery: issuer %q does not match %q", doc.Issuer, issuer)
	}
	if err := requireHTTPS(doc.JWKSURI, true); err != nil {
		return "", fmt.Errorf("discovery: jwks_uri %w", err)
	}
	iu, _ := url.Parse(issuer)
	ju, _ := url.Parse(doc.JWKSURI)
	if iu == nil || ju == nil || !strings.EqualFold(iu.Host, ju.Host) {
		return "", errors.New("discovery: jwks_uri is not on the issuer's host")
	}
	c.mu.Lock()
	c.discovery[issuer] = discoveredJWKS{uri: doc.JWKSURI, fetchedAt: c.now()}
	c.mu.Unlock()
	return doc.JWKSURI, nil
}

// VerifyWorkloadToken verifies a CI workload token with the shared core
// (VerifyJWT: signature, alg allowlist, iss, aud, exp, nbf, iat) and the
// workload rules: iat required, a bounded lifetime, and
// the presence of sub and jti. Every failure is an error; the caller must
// refuse the exchange. Replay (jti) is the caller's to check.
func (c *Client) VerifyWorkloadToken(ctx context.Context, raw string, exp WorkloadExpectations) (*WorkloadToken, error) {
	if raw == "" || len(raw) > MaxTokenSize {
		return nil, errors.New("token is empty or too large")
	}
	if exp.Issuer == "" || exp.Audience == "" {
		return nil, errors.New("incomplete expectations")
	}
	jwksURI, err := c.workloadJWKSURI(ctx, exp.Issuer)
	if err != nil {
		return nil, err
	}
	claims := jwtv5.MapClaims{}
	if err := c.VerifyJWT(ctx, raw, claims, TokenPolicy{
		JWKSURI:  jwksURI,
		Issuer:   exp.Issuer,
		Audience: exp.Audience,
		Leeway:   workloadLeeway,
	}); err != nil {
		return nil, fmt.Errorf("token: %w", err)
	}
	iat, err := claims.GetIssuedAt()
	if err != nil || iat == nil {
		return nil, errors.New("token: iat is missing")
	}
	expAt, err := claims.GetExpirationTime()
	if err != nil || expAt == nil {
		return nil, errors.New("token: exp is missing")
	}
	if expAt.Sub(iat.Time) > MaxWorkloadTokenLifetime {
		return nil, errors.New("token: lifetime is too long")
	}
	sub, _ := claims.GetSubject()
	jti, _ := claims["jti"].(string)
	if sub == "" || jti == "" {
		return nil, errors.New("token: sub or jti is missing")
	}
	if len(jti) > 255 {
		return nil, errors.New("token: jti is too long")
	}
	return &WorkloadToken{Claims: map[string]any(claims), Issuer: exp.Issuer, Subject: sub, JTI: jti,
		IssuedAt: iat.Time, ExpiresAt: expAt.Time}, nil
}
