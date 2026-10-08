package keycloak

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/openctemio/openctem/api/pkg/httpsec"
	"github.com/openctemio/openctem/api/pkg/oidc"
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

// accessTokenLeeway is the clock skew tolerated on exp, nbf and iat.
const accessTokenLeeway = 30 * time.Second

// RefreshErrorHandler is called when JWKS refresh fails.
// Use this to integrate with your alerting/monitoring system.
type RefreshErrorHandler func(err error, consecutiveFailures int)

// ValidatorConfig holds configuration for the token validator.
type ValidatorConfig struct {
	JWKSURL string
	// IssuerURL is the realm issuer every token must carry. Required.
	IssuerURL string
	// Audience, when set, must be one of aud or equal azp.
	Audience        string
	RefreshInterval time.Duration
	HTTPTimeout     time.Duration
	// OnRefreshError is called when background JWKS refresh fails.
	// Use for logging, alerting, or metrics.
	OnRefreshError RefreshErrorHandler
	// RequireInitialFetch if true, NewValidator will fail if initial JWKS fetch fails.
	// If false (default), the validator will start and retry in background.
	RequireInitialFetch bool
}

// Validator validates the external OIDC provider's (Keycloak) access tokens
// with the shared verification core (pkg/oidc): signature, algorithm
// allowlist, kid lookup with a throttled refresh, realm issuer, exp, nbf and
// iat. It adds the audience rule (aud or azp) and keeps the JWKS warm on a
// schedule.
type Validator struct {
	client    *oidc.Client
	jwksURL   string
	issuerURL string
	audience  string

	mu                  sync.RWMutex
	lastFetch           time.Time
	lastError           error
	consecutiveFailures int
	refreshInt          time.Duration
	onRefreshError      RefreshErrorHandler

	ctx    context.Context
	cancel context.CancelFunc
}

// NewValidator creates a new Keycloak token validator. The realm URL is
// operator configuration; the safe dialer still refuses loopback, link-local
// and metadata addresses (and private ranges the operator has not opened, see
// httpsec.EnvAllowPrivateCIDRs) at dial time.
func NewValidator(ctx context.Context, cfg ValidatorConfig) (*Validator, error) {
	timeout := cfg.HTTPTimeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	return newValidator(ctx, cfg, httpsec.SafeHTTPClient(timeout))
}

func newValidator(ctx context.Context, cfg ValidatorConfig, httpClient *http.Client) (*Validator, error) {
	if cfg.JWKSURL == "" {
		return nil, fmt.Errorf("JWKS URL is required")
	}
	if cfg.IssuerURL == "" {
		return nil, fmt.Errorf("issuer URL is required")
	}
	if cfg.RefreshInterval == 0 {
		cfg.RefreshInterval = time.Hour
	}

	ctx, cancel := context.WithCancel(ctx)
	v := &Validator{
		client:         oidc.NewClient(httpClient, nil),
		jwksURL:        cfg.JWKSURL,
		issuerURL:      cfg.IssuerURL,
		audience:       cfg.Audience,
		refreshInt:     cfg.RefreshInterval,
		onRefreshError: cfg.OnRefreshError,
		ctx:            ctx,
		cancel:         cancel,
	}

	if err := v.refresh(); err != nil && cfg.RequireInitialFetch {
		cancel()
		return nil, fmt.Errorf("failed to fetch initial JWKS: %w", err)
	}
	go v.backgroundRefresh()
	return v, nil
}

// refresh fetches the JWKS now and records the outcome.
func (v *Validator) refresh() error {
	err := v.client.RefreshJWKS(v.ctx, v.jwksURL)
	v.mu.Lock()
	if err != nil {
		v.consecutiveFailures++
		v.lastError = err
	} else {
		v.consecutiveFailures = 0
		v.lastError = nil
		v.lastFetch = time.Now()
	}
	failures := v.consecutiveFailures
	v.mu.Unlock()
	if err != nil && v.onRefreshError != nil {
		v.onRefreshError(err, failures)
	}
	return err
}

// backgroundRefresh keeps the JWKS warm so verification rarely fetches.
func (v *Validator) backgroundRefresh() {
	ticker := time.NewTicker(v.refreshInt)
	defer ticker.Stop()
	for {
		select {
		case <-v.ctx.Done():
			return
		case <-ticker.C:
			_ = v.refresh()
		}
	}
}

// LastRefreshError returns the consecutive failure count and last refresh error.
// Returns 0, nil if last refresh was successful.
func (v *Validator) LastRefreshError() (int, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.consecutiveFailures, v.lastError
}

// LastRefreshTime returns the time of the last successful JWKS refresh.
func (v *Validator) LastRefreshTime() time.Time {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.lastFetch
}

// HasKeys returns true if the validator has at least one key loaded.
func (v *Validator) HasKeys() bool {
	return v.client.HasKeys(v.jwksURL)
}

// ValidateToken validates a Keycloak access token and returns its claims.
func (v *Validator) ValidateToken(ctx context.Context, tokenString string) (*Claims, error) {
	claims := &Claims{}
	err := v.client.VerifyJWT(ctx, tokenString, claims, oidc.TokenPolicy{
		JWKSURI:                 v.jwksURL,
		Issuer:                  v.issuerURL,
		AudienceCheckedByCaller: true,
		Leeway:                  accessTokenLeeway,
	})
	switch {
	case err == nil:
	case errors.Is(err, jwt.ErrTokenExpired):
		return nil, ErrExpiredToken
	case errors.Is(err, jwt.ErrTokenInvalidIssuer):
		return nil, ErrInvalidIssuer
	case errors.Is(err, oidc.ErrKeyNotFound):
		return nil, ErrKeyNotFound
	case errors.Is(err, oidc.ErrJWKSUnavailable):
		return nil, ErrJWKSUnavailable
	default:
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	// The audience, when configured, must name this API or be the
	// authorized party the token was issued to.
	if v.audience != "" && !slices.Contains(claims.Audience, v.audience) && claims.Azp != v.audience {
		return nil, ErrInvalidAudience
	}
	return claims, nil
}

// Close shuts down the JWKS background refresh.
func (v *Validator) Close() error {
	v.cancel()
	return nil
}
