package middleware

// Rate limit for the public CI token exchange (POST /api/v1/ci/oidc/exchange,
// docs/rfcs/RFC-051-ci-runner-identity-and-gate.md).
//
// Hosted CI runners share egress addresses across their customers, so one
// strict budget per address lets one busy pipeline fleet (or one attacker on
// the same runners) throttle every other organization's jobs. Two buckets
// instead, both shared by every API replica through the auth rate-limit
// store:
//
//   - per address: a wide backstop sized for a shared runner egress address.
//     It runs first and reads nothing but the address, so a flood is turned
//     away before the body is read.
//   - per pipeline identity: the organization (tenant_id) and the token's
//     issuer, from the request, at that address. The claims are NOT verified
//     here (the handler does that), so they only choose a bucket, never grant
//     anything: a client inventing new tenant ids or issuers gets fresh
//     identity buckets but stays inside the address backstop. The address is
//     part of the key so that a party who knows an organization's id (it is
//     in public pipeline files) cannot use up that organization's budget from
//     somewhere else by sending junk tokens naming it.
//
// A request whose body or token cannot be read is limited by address alone,
// in the identity bucket's budget.

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/logger"
)

// CIExchangeRateLimitConfig sets the two budgets, per minute.
type CIExchangeRateLimitConfig struct {
	// PerIdentityPerMin bounds one organization + issuer at one address.
	PerIdentityPerMin int
	// PerIPPerMin bounds one address across all organizations.
	PerIPPerMin int
}

// ciExchangeBodyLimit is the most of the body read to find the key; the
// handler refuses larger bodies itself (an OIDC token is a few KB).
const ciExchangeBodyLimit = 32 << 10

// ciIssuerMaxLen bounds the issuer taken into the key.
const ciIssuerMaxLen = 512

// CIExchangeRateLimiter is the exchange route's limiter.
type CIExchangeRateLimiter struct {
	perIP       *authBucket
	perIdentity *authBucket
}

// NewCIExchangeRateLimiter builds the limiter. A nil backend keeps the
// budgets in memory (per replica).
func NewCIExchangeRateLimiter(cfg CIExchangeRateLimitConfig, backend AuthRateLimitBackend, log *logger.Logger) *CIExchangeRateLimiter {
	if cfg.PerIdentityPerMin <= 0 {
		cfg.PerIdentityPerMin = 60
	}
	if cfg.PerIPPerMin <= 0 {
		cfg.PerIPPerMin = 600
	}
	return &CIExchangeRateLimiter{
		perIP:       newAuthBucket("ci-oidc:ip", cfg.PerIPPerMin, time.Minute, backend, log),
		perIdentity: newAuthBucket("ci-oidc:identity", cfg.PerIdentityPerMin, time.Minute, backend, log),
	}
}

// Middleware applies the address backstop, then the identity budget.
func (l *CIExchangeRateLimiter) Middleware() func(http.Handler) http.Handler {
	perIP := l.perIP.middleware(getClientIP)
	perIdentity := l.perIdentity.middleware(ciExchangeKey)
	return func(next http.Handler) http.Handler {
		return perIP(perIdentity(next))
	}
}

// Stop ends the in-memory buckets' cleanup.
func (l *CIExchangeRateLimiter) Stop() {
	l.perIP.local.Stop()
	l.perIdentity.local.Stop()
}

// ciExchangeKey keys an exchange by (tenant_id, unverified issuer, address).
// The body is read (bounded) and handed back to the handler unchanged.
func ciExchangeKey(r *http.Request) string {
	ip := getClientIP(r)
	if r.Body == nil {
		return "ip:" + ip
	}
	head, err := io.ReadAll(io.LimitReader(r.Body, ciExchangeBodyLimit+1))
	// The rest (if any) stays readable, so the handler sees the whole body
	// and applies its own size limit.
	r.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(head), r.Body), r.Body}
	if err != nil || len(head) > ciExchangeBodyLimit {
		return "ip:" + ip
	}
	var v struct {
		TenantID string `json:"tenant_id"`
		IDToken  string `json:"id_token"`
	}
	if json.Unmarshal(head, &v) != nil {
		return "ip:" + ip
	}
	tenant := strings.ToLower(strings.TrimSpace(v.TenantID))
	iss := unverifiedIssuer(v.IDToken)
	if tenant == "" || iss == "" {
		return "ip:" + ip
	}
	sum := sha256.Sum256([]byte(tenant + "\x00" + iss + "\x00" + ip))
	return "id:" + hex.EncodeToString(sum[:16])
}

// unverifiedIssuer returns the `iss` claim of a compact JWT without checking
// its signature, or "" when it cannot be read. Used only to pick a bucket.
func unverifiedIssuer(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return ""
	}
	var c struct {
		Iss string `json:"iss"`
	}
	if json.Unmarshal(payload, &c) != nil {
		return ""
	}
	iss := strings.TrimRight(strings.TrimSpace(c.Iss), "/")
	if iss == "" || len(iss) > ciIssuerMaxLen {
		return ""
	}
	return iss
}
