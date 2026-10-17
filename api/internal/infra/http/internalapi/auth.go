// Package internalapi serves the internal entitlements API
// (docs/architecture/limits.md, "Internal entitlements API"): a separate
// listener for a hosted service's control plane. Every request needs a
// client certificate from the pinned CA (checked in the TLS handshake) and a
// short-lived, single-use Ed25519-signed token with the scope the endpoint
// requires. The API writes only limits, feature denies, the idle policy and
// new organizations, and reads only aggregate usage counts: no endpoint
// returns findings, assets or people's data.
package internalapi

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Audience is the aud claim every token must carry.
const Audience = "openctem-core"

// Scopes.
const (
	ScopeLimitsWrite   = "limits:write"
	ScopeOrgsProvision = "orgs:provision"
	ScopeUsageRead     = "usage:read"
)

const (
	maxTokenLifetime = 5 * time.Minute
	maxFutureIssue   = time.Minute
	clockSkew        = 30 * time.Second
	maxJTILength     = 128
	maxSubjectLength = 128
)

// ErrUnauthenticated is every token failure; the reason is logged, never
// returned.
var ErrUnauthenticated = errors.New("unauthenticated")

// Claims are the verified claims of one call.
type Claims struct {
	Subject string
	TokenID string
	Scopes  map[string]bool
	Expiry  time.Time
}

// Has reports whether the token carries scope.
func (c Claims) Has(scope string) bool { return c.Scopes[scope] }

// ReplayCache remembers token ids until they expire.
type ReplayCache interface {
	// FirstUse records jti until `until` and reports whether it was unseen.
	// An error refuses the call (fail-closed).
	FirstUse(ctx context.Context, jti string, until time.Time) (bool, error)
}

// Verifier checks the bearer tokens of the internal API.
type Verifier struct {
	keys   []ed25519.PublicKey
	issuer string
	replay ReplayCache
	now    func() time.Time
}

// NewVerifier creates a verifier for the given keys and issuer.
func NewVerifier(keys []ed25519.PublicKey, issuer string, replay ReplayCache) (*Verifier, error) {
	if len(keys) == 0 {
		return nil, errors.New("internal API: no token public key")
	}
	if strings.TrimSpace(issuer) == "" {
		return nil, errors.New("internal API: no token issuer")
	}
	if replay == nil {
		return nil, errors.New("internal API: no replay cache")
	}
	return &Verifier{keys: keys, issuer: issuer, replay: replay, now: time.Now}, nil
}

// ParsePublicKeys reads one or more PEM Ed25519 public keys.
func ParsePublicKeys(pemBytes []byte) ([]ed25519.PublicKey, error) {
	var keys []ed25519.PublicKey
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "PUBLIC KEY" {
			return nil, fmt.Errorf("internal API: unexpected PEM block %q", block.Type)
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("internal API: parse public key: %w", err)
		}
		k, ok := pub.(ed25519.PublicKey)
		if !ok {
			return nil, errors.New("internal API: token keys must be Ed25519")
		}
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		return nil, errors.New("internal API: no public key in the PEM file")
	}
	return keys, nil
}

type tokenClaims struct {
	Scope string `json:"scope"`
	jwt.RegisteredClaims
}

// Verify checks the token: EdDSA signed by a configured key, issuer and
// audience, a lifetime of at most 5 minutes, not issued in the future, a
// token id never seen before. Every failure is ErrUnauthenticated; the
// string is the detail, for the log only.
func (v *Verifier) Verify(ctx context.Context, raw string) (Claims, string, error) {
	now := v.now()
	var claims tokenClaims
	var lastErr error
	parsed := false
	for _, k := range v.keys {
		key := k
		_, err := jwt.ParseWithClaims(raw, &claims, func(t *jwt.Token) (any, error) { return key, nil },
			jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}),
			jwt.WithIssuer(v.issuer), jwt.WithAudience(Audience),
			jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithLeeway(clockSkew),
			jwt.WithTimeFunc(func() time.Time { return now }))
		if err == nil {
			parsed = true
			break
		}
		lastErr = err
		claims = tokenClaims{}
	}
	if !parsed {
		return Claims{}, fmt.Sprintf("token: %v", lastErr), ErrUnauthenticated
	}
	if claims.IssuedAt == nil || claims.ExpiresAt == nil {
		return Claims{}, "token: iat and exp are required", ErrUnauthenticated
	}
	iat, exp := claims.IssuedAt.Time, claims.ExpiresAt.Time
	if exp.Sub(iat) > maxTokenLifetime || exp.Before(iat) {
		return Claims{}, "token: lifetime over 5 minutes", ErrUnauthenticated
	}
	if iat.After(now.Add(maxFutureIssue)) {
		return Claims{}, "token: issued in the future", ErrUnauthenticated
	}
	if claims.ID == "" || len(claims.ID) > maxJTILength {
		return Claims{}, "token: jti missing or too long", ErrUnauthenticated
	}
	if claims.Subject == "" || len(claims.Subject) > maxSubjectLength {
		return Claims{}, "token: sub missing or too long", ErrUnauthenticated
	}
	first, err := v.replay.FirstUse(ctx, claims.ID, exp.Add(clockSkew))
	if err != nil {
		return Claims{}, fmt.Sprintf("token: replay cache: %v", err), ErrUnauthenticated
	}
	if !first {
		return Claims{}, "token: jti replayed", ErrUnauthenticated
	}
	out := Claims{Subject: claims.Subject, TokenID: claims.ID, Scopes: map[string]bool{}, Expiry: exp}
	for _, sc := range strings.Fields(claims.Scope) {
		out.Scopes[sc] = true
	}
	return out, "", nil
}

// MemoryReplayCache is a single-process replay cache (one replica, tests).
type MemoryReplayCache struct {
	mu   sync.Mutex
	seen map[string]time.Time
	now  func() time.Time
}

// NewMemoryReplayCache creates the cache.
func NewMemoryReplayCache() *MemoryReplayCache {
	return &MemoryReplayCache{seen: map[string]time.Time{}, now: time.Now}
}

// maxMemoryEntries bounds the cache; when full, unexpired ids are kept and a
// new one is refused rather than an old one forgotten (fail-closed).
const maxMemoryEntries = 100000

// FirstUse implements ReplayCache.
func (m *MemoryReplayCache) FirstUse(_ context.Context, jti string, until time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	if len(m.seen) >= maxMemoryEntries {
		for k, t := range m.seen {
			if now.After(t) {
				delete(m.seen, k)
			}
		}
		if len(m.seen) >= maxMemoryEntries {
			return false, errors.New("replay cache full")
		}
	}
	if t, ok := m.seen[jti]; ok && now.Before(t) {
		return false, nil
	}
	m.seen[jti] = until
	return true, nil
}

// SetNXer is the slice of the Redis client the shared replay cache needs.
type SetNXer interface {
	SetNX(ctx context.Context, key, value string, ttl time.Duration) (bool, error)
}

// RedisReplayCache shares token ids across replicas.
type RedisReplayCache struct {
	redis SetNXer
	now   func() time.Time
}

// NewRedisReplayCache creates the cache.
func NewRedisReplayCache(r SetNXer) *RedisReplayCache {
	return &RedisReplayCache{redis: r, now: time.Now}
}

// FirstUse implements ReplayCache.
func (r *RedisReplayCache) FirstUse(ctx context.Context, jti string, until time.Time) (bool, error) {
	ttl := until.Sub(r.now())
	if ttl < time.Second {
		ttl = time.Second
	}
	return r.redis.SetNX(ctx, "internalapi:jti:"+jti, "1", ttl)
}
