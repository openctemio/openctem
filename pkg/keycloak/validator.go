package keycloak

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	// ErrInvalidToken is returned when the token is invalid.
	ErrInvalidToken = errors.New("invalid token")
	// ErrExpiredToken is returned when the token has expired.
	ErrExpiredToken = errors.New("token has expired")
	// ErrInvalidIssuer is returned when the token issuer doesn't match.
	ErrInvalidIssuer = errors.New("invalid token issuer")
	// ErrInvalidAudience is returned when the token audience doesn't match.
	ErrInvalidAudience = errors.New("invalid token audience")
	// ErrJWKSUnavailable is returned when JWKS cannot be fetched.
	ErrJWKSUnavailable = errors.New("JWKS endpoint unavailable")
	// ErrKeyNotFound is returned when the key ID is not found in JWKS.
	ErrKeyNotFound = errors.New("key not found in JWKS")
)

// JWK represents a JSON Web Key.
type JWK struct {
	Kid string `json:"kid"` // Key ID
	Kty string `json:"kty"` // Key Type (RSA)
	Alg string `json:"alg"` // Algorithm (RS256)
	Use string `json:"use"` // Key Use (sig)
	N   string `json:"n"`   // RSA modulus
	E   string `json:"e"`   // RSA exponent
}

// JWKS represents a JSON Web Key Set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// RefreshErrorHandler is called when JWKS refresh fails.
// Use this to integrate with your alerting/monitoring system.
type RefreshErrorHandler func(err error, consecutiveFailures int)

// ValidatorConfig holds configuration for the token validator.
type ValidatorConfig struct {
	JWKSURL         string
	IssuerURL       string
	Audience        string // Optional
	RefreshInterval time.Duration
	HTTPTimeout     time.Duration
	// OnRefreshError is called when background JWKS refresh fails.
	// Use for logging, alerting, or metrics.
	OnRefreshError RefreshErrorHandler
	// RequireInitialFetch if true, NewValidator will fail if initial JWKS fetch fails.
	// If false (default), the validator will start and retry in background.
	RequireInitialFetch bool
}

// Validator validates Keycloak JWT tokens using JWKS.
type Validator struct {
	jwksURL    string
	issuerURL  string
	audience   string
	httpClient *http.Client

	mu                  sync.RWMutex
	keys                map[string]*rsa.PublicKey
	lastFetch           time.Time
	lastError           error
	consecutiveFailures int
	refreshInt          time.Duration
	onRefreshError      RefreshErrorHandler

	ctx    context.Context
	cancel context.CancelFunc
}

// NewValidator creates a new Keycloak token validator.
func NewValidator(ctx context.Context, cfg ValidatorConfig) (*Validator, error) {
	if cfg.JWKSURL == "" {
		return nil, fmt.Errorf("JWKS URL is required")
	}

	// Set defaults
	if cfg.RefreshInterval == 0 {
		cfg.RefreshInterval = time.Hour
	}
	if cfg.HTTPTimeout == 0 {
		cfg.HTTPTimeout = 10 * time.Second
	}

	ctx, cancel := context.WithCancel(ctx)

	v := &Validator{
		jwksURL:        cfg.JWKSURL,
		issuerURL:      cfg.IssuerURL,
		audience:       cfg.Audience,
		httpClient:     &http.Client{Timeout: cfg.HTTPTimeout},
		keys:           make(map[string]*rsa.PublicKey),
		refreshInt:     cfg.RefreshInterval,
		onRefreshError: cfg.OnRefreshError,
		ctx:            ctx,
		cancel:         cancel,
	}

	// Initial fetch - don't fail if RequireInitialFetch is false
	if err := v.refreshKeys(); err != nil {
		if cfg.RequireInitialFetch {
			cancel()
			return nil, fmt.Errorf("failed to fetch initial JWKS: %w", err)
		}
		// Store the error and notify via callback
		v.mu.Lock()
		v.consecutiveFailures = 1
		v.lastError = err
		v.mu.Unlock()

		if v.onRefreshError != nil {
			v.onRefreshError(err, 1)
		}
	}

	// Start background refresh
	go v.backgroundRefresh()

	return v, nil
}

// refreshKeys fetches the JWKS and updates the cached keys.
func (v *Validator) refreshKeys() error {
	req, err := http.NewRequestWithContext(v.ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	var jwks JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("failed to decode JWKS: %w", err)
	}

	newKeys := make(map[string]*rsa.PublicKey)
	for _, key := range jwks.Keys {
		if key.Kty != "RSA" {
			continue
		}
		pubKey, err := jwkToRSAPublicKey(key)
		if err != nil {
			continue // Skip invalid keys
		}
		newKeys[key.Kid] = pubKey
	}

	v.mu.Lock()
	v.keys = newKeys
	v.lastFetch = time.Now()
	v.mu.Unlock()

	return nil
}

// backgroundRefresh periodically refreshes the JWKS.
func (v *Validator) backgroundRefresh() {
	ticker := time.NewTicker(v.refreshInt)
	defer ticker.Stop()

	for {
		select {
		case <-v.ctx.Done():
			return
		case <-ticker.C:
			if err := v.refreshKeys(); err != nil {
				v.mu.Lock()
				v.consecutiveFailures++
				v.lastError = err
				failures := v.consecutiveFailures
				v.mu.Unlock()

				// Call error handler if configured
				if v.onRefreshError != nil {
					v.onRefreshError(err, failures)
				}
			} else {
				// Reset failure count on success
				v.mu.Lock()
				v.consecutiveFailures = 0
				v.lastError = nil
				v.mu.Unlock()
			}
		}
	}
}

// LastRefreshError returns the last refresh error and consecutive failure count.
// Returns nil, 0 if last refresh was successful.
func (v *Validator) LastRefreshError() (error, int) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.lastError, v.consecutiveFailures
}

// LastRefreshTime returns the time of the last successful JWKS refresh.
func (v *Validator) LastRefreshTime() time.Time {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.lastFetch
}

// getKey returns the RSA public key for the given key ID.
func (v *Validator) getKey(kid string) (*rsa.PublicKey, error) {
	v.mu.RLock()
	key, ok := v.keys[kid]
	keysEmpty := len(v.keys) == 0
	v.mu.RUnlock()

	if ok {
		return key, nil
	}

	// Key not found or no keys at all, try refreshing
	if err := v.refreshKeys(); err != nil {
		// If we have no keys at all, JWKS is unavailable
		if keysEmpty {
			return nil, ErrJWKSUnavailable
		}
		// We have some keys but not this one - key rotation or invalid kid
		return nil, ErrKeyNotFound
	}

	v.mu.RLock()
	key, ok = v.keys[kid]
	v.mu.RUnlock()

	if !ok {
		return nil, ErrKeyNotFound
	}

	return key, nil
}

// HasKeys returns true if the validator has at least one key loaded.
func (v *Validator) HasKeys() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.keys) > 0
}

// ValidateToken validates a Keycloak JWT token and returns the claims.
func (v *Validator) ValidateToken(tokenString string) (*Claims, error) {
	claims := &Claims{}

	// Parse without verification first to get the key ID
	parser := jwt.NewParser()
	token, _, err := parser.ParseUnverified(tokenString, claims)
	if err != nil {
		return nil, ErrInvalidToken
	}

	// Get key ID from header
	kid, ok := token.Header["kid"].(string)
	if !ok || kid == "" {
		return nil, fmt.Errorf("%w: missing key ID", ErrInvalidToken)
	}

	// Get the public key
	pubKey, err := v.getKey(kid)
	if err != nil {
		return nil, err
	}

	// Build parser options
	parserOpts := []jwt.ParserOption{
		jwt.WithExpirationRequired(),
	}
	if v.issuerURL != "" {
		parserOpts = append(parserOpts, jwt.WithIssuer(v.issuerURL))
	}

	// Parse and validate with the correct key
	keyFunc := func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return pubKey, nil
	}

	claims = &Claims{}
	token, err = jwt.ParseWithClaims(tokenString, claims, keyFunc, parserOpts...)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		if errors.Is(err, jwt.ErrTokenMalformed) || errors.Is(err, jwt.ErrSignatureInvalid) {
			return nil, ErrInvalidToken
		}
		if errors.Is(err, jwt.ErrTokenInvalidIssuer) {
			return nil, ErrInvalidIssuer
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	if !token.Valid {
		return nil, ErrInvalidToken
	}

	// Validate audience if configured
	if v.audience != "" {
		aud, err := claims.GetAudience()
		if err != nil {
			return nil, ErrInvalidAudience
		}
		validAudience := false
		for _, a := range aud {
			if a == v.audience {
				validAudience = true
				break
			}
		}
		// Also check azp (authorized party) as fallback
		if !validAudience && claims.Azp != v.audience {
			return nil, ErrInvalidAudience
		}
	}

	return claims, nil
}

// Close shuts down the JWKS background refresh.
func (v *Validator) Close() error {
	v.cancel()
	return nil
}

// jwkToRSAPublicKey converts a JWK to an RSA public key.
func jwkToRSAPublicKey(jwk JWK) (*rsa.PublicKey, error) {
	// Decode modulus (n)
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode modulus: %w", err)
	}
	n := new(big.Int).SetBytes(nBytes)

	// Decode exponent (e)
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode exponent: %w", err)
	}
	// Convert bytes to int
	var e int
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}

	return &rsa.PublicKey{
		N: n,
		E: e,
	}, nil
}
