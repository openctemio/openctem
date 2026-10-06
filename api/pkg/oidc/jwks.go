package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"
)

// ErrJWKSUnavailable means no signing keys could be obtained from the JWKS:
// the fetch failed (or was throttled) and nothing usable is cached.
var ErrJWKSUnavailable = errors.New("jwks unavailable")

// ErrKeyNotFound means the JWKS has no key for the token's kid.
var ErrKeyNotFound = errors.New("no signing key for kid")

const (
	// jwksTTL is how long a fetched JWKS is used before it is fetched again.
	jwksTTL = time.Hour
	// jwksMaxStale is how long a fetched JWKS still verifies known kids when
	// the provider cannot be reached: an outage of the provider does not end
	// every session at once, and a key the provider removed stops working
	// at the first successful fetch.
	jwksMaxStale = 24 * time.Hour
	// jwksMinRefresh is the shortest interval between two fetch attempts of
	// one JWKS: a token naming an unknown kid, or a provider that is down,
	// cannot make every request fetch the keys again.
	jwksMinRefresh = 30 * time.Second
)

type jwksEntry struct {
	// fetchMu serializes fetches of this JWKS: concurrent callers wait for
	// the one in flight instead of fetching again or failing early.
	fetchMu sync.Mutex

	// Guarded by Client.mu.
	keys        map[string]any // kid -> *rsa.PublicKey | *ecdsa.PublicKey
	fetchedAt   time.Time      // last successful fetch
	attemptedAt time.Time      // last fetch attempt
	lastErr     error          // result of the last attempt
}

func (c *Client) entry(jwksURI string) *jwksEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.jwks[jwksURI]
	if !ok {
		e = &jwksEntry{}
		c.jwks[jwksURI] = e
	}
	return e
}

// key returns the signing key for kid. A fresh cache answers directly; an
// unknown kid or a stale cache fetches the JWKS at most once per
// jwksMinRefresh. Without a kid, a JWKS with a single key is used.
func (c *Client) key(ctx context.Context, jwksURI, kid string) (any, error) {
	if jwksURI == "" {
		return nil, fmt.Errorf("%w: no JWKS URI", ErrJWKSUnavailable)
	}
	if k, ok := c.cachedKey(jwksURI, kid, jwksTTL); ok {
		return k, nil
	}
	fetchErr := c.refreshThrottled(ctx, jwksURI)
	if k, ok := c.cachedKey(jwksURI, kid, jwksMaxStale); ok {
		return k, nil
	}
	if fetchErr != nil || !c.HasKeys(jwksURI) {
		return nil, fmt.Errorf("%w: %v", ErrJWKSUnavailable, fetchErr)
	}
	return nil, fmt.Errorf("%w %q", ErrKeyNotFound, kid)
}

func (c *Client) cachedKey(jwksURI, kid string, maxAge time.Duration) (any, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.jwks[jwksURI]
	if !ok || e.keys == nil || c.now().Sub(e.fetchedAt) > maxAge {
		return nil, false
	}
	if kid == "" {
		if len(e.keys) == 1 {
			for _, k := range e.keys {
				return k, true
			}
		}
		return nil, false
	}
	k, ok := e.keys[kid]
	return k, ok
}

// refreshThrottled fetches the JWKS unless an attempt was made within
// jwksMinRefresh, in which case it returns that attempt's result.
func (c *Client) refreshThrottled(ctx context.Context, jwksURI string) error {
	e := c.entry(jwksURI)
	e.fetchMu.Lock()
	defer e.fetchMu.Unlock()
	c.mu.Lock()
	if !e.attemptedAt.IsZero() && c.now().Sub(e.attemptedAt) < jwksMinRefresh {
		err := e.lastErr
		c.mu.Unlock()
		return err
	}
	c.mu.Unlock()
	return c.fetchJWKS(ctx, e, jwksURI)
}

// RefreshJWKS fetches the JWKS now, bypassing the throttle. It is for a
// caller that warms the cache on a fixed schedule; verification never needs
// it. A failed fetch keeps the keys already cached.
func (c *Client) RefreshJWKS(ctx context.Context, jwksURI string) error {
	e := c.entry(jwksURI)
	e.fetchMu.Lock()
	defer e.fetchMu.Unlock()
	return c.fetchJWKS(ctx, e, jwksURI)
}

// HasKeys reports whether keys from jwksURI are cached.
func (c *Client) HasKeys(jwksURI string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.jwks[jwksURI]
	return ok && len(e.keys) > 0
}

// fetchJWKS must be called with e.fetchMu held.
func (c *Client) fetchJWKS(ctx context.Context, e *jwksEntry, jwksURI string) error {
	c.mu.Lock()
	e.attemptedAt = c.now()
	c.mu.Unlock()

	var keys map[string]any
	body, err := c.get(ctx, jwksURI)
	if err == nil {
		keys, err = parseJWKS(body)
	} else {
		err = fmt.Errorf("jwks: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	e.lastErr = err
	if err == nil {
		e.keys = keys
		e.fetchedAt = c.now()
	}
	return err
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// parseJWKS keeps the RSA (2048 bits or more) and P-256 signing keys. A key
// without a kid is stored under a positional name, usable only by a token
// without a kid when it is the only key.
func parseJWKS(body []byte) (map[string]any, error) {
	var doc struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, errors.New("jwks: invalid document")
	}
	out := map[string]any{}
	for i, k := range doc.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		kid := k.Kid
		if kid == "" {
			kid = fmt.Sprintf("#%d", i)
		}
		switch k.Kty {
		case "RSA":
			if pk, err := rsaKey(k.N, k.E); err == nil {
				out[kid] = pk
			}
		case "EC":
			if pk, err := ecKey(k.Crv, k.X, k.Y); err == nil {
				out[kid] = pk
			}
		}
	}
	if len(out) == 0 {
		return nil, errors.New("jwks: no usable signing keys")
	}
	return out, nil
}

func rsaKey(nStr, eStr string) (*rsa.PublicKey, error) {
	n, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil || len(n) == 0 {
		return nil, errors.New("bad modulus")
	}
	eb, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil || len(eb) == 0 {
		return nil, errors.New("bad exponent")
	}
	e := new(big.Int).SetBytes(eb)
	if e.BitLen() == 0 || e.BitLen() > 31 {
		return nil, errors.New("bad exponent")
	}
	pk := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(e.Int64())}
	if pk.N.BitLen() < 2048 {
		return nil, errors.New("rsa key too small")
	}
	return pk, nil
}

func ecKey(crv, xStr, yStr string) (*ecdsa.PublicKey, error) {
	if crv != "P-256" {
		return nil, errors.New("unsupported curve")
	}
	x, err := ecCoordinate(xStr)
	if err != nil {
		return nil, err
	}
	y, err := ecCoordinate(yStr)
	if err != nil {
		return nil, err
	}
	// SEC 1 uncompressed point; the parser rejects points not on the curve.
	b := make([]byte, 0, 1+2*p256CoordinateSize)
	b = append(b, 4)
	b = append(b, x...)
	b = append(b, y...)
	return ecdsa.ParseUncompressedPublicKey(elliptic.P256(), b)
}

const p256CoordinateSize = 32

// ecCoordinate decodes a JWK P-256 coordinate and left-pads it to 32 bytes.
func ecCoordinate(raw string) ([]byte, error) {
	v, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return nil, err
	}
	if len(v) == 0 || len(v) > p256CoordinateSize {
		return nil, errors.New("invalid P-256 coordinate length")
	}
	out := make([]byte, p256CoordinateSize)
	copy(out[p256CoordinateSize-len(v):], v)
	return out, nil
}
