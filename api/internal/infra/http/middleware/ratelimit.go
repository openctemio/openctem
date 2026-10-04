package middleware

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/openctemio/openctem/api/internal/config"
	redisinfra "github.com/openctemio/openctem/api/internal/infra/redis"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/httpsec"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Security event constants for logging and metrics.
const (
	SecurityEventAuthFailure        = "security.auth.failure"
	SecurityEventSensorNotFound     = "security.sensor.not_found"
	SecurityEventAPIKeyInvalid      = "security.apikey.invalid"
	SecurityEventSensorInactive     = "security.sensor.inactive"
	SecurityEventSensorTypeMismatch = "security.sensor.type_mismatch"
	SecurityEventJobAccessDenied    = "security.job.access_denied"
	SecurityEventTokenInvalid       = "security.token.invalid"
)

// RateLimiter implements a per-IP rate limiter.
type RateLimiter struct {
	visitors map[string]*visitor
	mu       sync.RWMutex
	rate     rate.Limit
	burst    int
	cleanup  time.Duration
	log      *logger.Logger
	done     chan struct{}
	stopped  chan struct{} // signals goroutine has exited
	stopOnce sync.Once     // prevents double-close panic
}

type visitor struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// NewRateLimiter creates a new rate limiter.
func NewRateLimiter(cfg *config.RateLimitConfig, log *logger.Logger) *RateLimiter {
	rl := &RateLimiter{
		visitors: make(map[string]*visitor),
		rate:     rate.Limit(cfg.RequestsPerSec),
		burst:    cfg.Burst,
		cleanup:  cfg.CleanupInterval,
		log:      log,
		done:     make(chan struct{}),
		stopped:  make(chan struct{}),
	}

	// Start cleanup goroutine
	go rl.cleanupVisitors()

	return rl
}

// Stop stops the cleanup goroutine and waits for it to exit.
// Safe to call multiple times.
func (rl *RateLimiter) Stop() {
	rl.stopOnce.Do(func() {
		close(rl.done)
	})
	<-rl.stopped // Wait for goroutine to exit
}

// getVisitor retrieves or creates a rate limiter for an IP.
func (rl *RateLimiter) getVisitor(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	v, exists := rl.visitors[ip]
	if !exists {
		limiter := rate.NewLimiter(rl.rate, rl.burst)
		rl.visitors[ip] = &visitor{limiter: limiter, lastSeen: time.Now()}
		return limiter
	}

	v.lastSeen = time.Now()
	return v.limiter
}

// cleanupVisitors removes old visitor entries.
func (rl *RateLimiter) cleanupVisitors() {
	ticker := time.NewTicker(rl.cleanup)
	defer ticker.Stop()
	defer close(rl.stopped) // Signal that goroutine has exited

	for {
		select {
		case <-rl.done:
			return
		case <-ticker.C:
			rl.mu.Lock()
			for ip, v := range rl.visitors {
				if time.Since(v.lastSeen) > 3*time.Minute {
					delete(rl.visitors, ip)
				}
			}
			rl.mu.Unlock()
		}
	}
}

// Middleware returns the rate limiting middleware, keyed by client IP.
func (rl *RateLimiter) Middleware() func(http.Handler) http.Handler {
	return rl.keyedMiddleware(getClientIP)
}

// UserMiddleware returns the rate limiting middleware keyed by the
// authenticated user (the client IP when there is none). Mount it after the
// auth middleware.
func (rl *RateLimiter) UserMiddleware() func(http.Handler) http.Handler {
	return rl.keyedMiddleware(UserKeyFunc)
}

// keyedMiddleware rate limits by the bucket key returns. The client IP is
// still what gets logged.
func (rl *RateLimiter) keyedMiddleware(key func(*http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rl.serveKeyed(w, r, key(r), next)
		})
	}
}

// serveKeyed applies the in-memory bucket for k, then calls next or writes 429.
func (rl *RateLimiter) serveKeyed(w http.ResponseWriter, r *http.Request, k string, next http.Handler) {
	ip := getClientIP(r)
	limiter := rl.getVisitor(k)

	// Get current tokens before Allow() consumes one
	tokens := limiter.Tokens()
	remaining := int(math.Max(0, math.Floor(tokens)-1)) // -1 because Allow() will consume one

	// Calculate reset time (time until bucket is full)
	tokensToRefill := float64(rl.burst) - tokens
	var resetTime time.Time
	if tokensToRefill > 0 && rl.rate > 0 {
		secondsToRefill := tokensToRefill / float64(rl.rate)
		resetTime = time.Now().Add(time.Duration(secondsToRefill * float64(time.Second)))
	} else {
		resetTime = time.Now()
	}

	// Set rate limit headers on all responses
	w.Header().Set("X-RateLimit-Limit", strconv.Itoa(rl.burst))
	w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
	w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(resetTime.Unix(), 10))

	if !limiter.Allow() {
		if rl.log != nil {
			rl.log.Warn("rate limit exceeded",
				"ip", logSafe(ip),
				"path", logSafe(RedactPath(r.URL.Path)),
				"request_id", logSafe(GetRequestID(r.Context())),
			)
		}

		// Update remaining to 0 since we're rate limited
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.Header().Set("Retry-After", strconv.Itoa(rl.retryAfterSeconds()))
		apierror.RateLimitExceeded().WriteJSON(w)
		return
	}

	next.ServeHTTP(w, r)
}

// retryAfterSeconds is how long until one request is allowed again.
func (rl *RateLimiter) retryAfterSeconds() int {
	if rl.rate <= 0 {
		return 1
	}
	return max(1, int(math.Ceil(1/float64(rl.rate))))
}

// RateLimitWithStop creates a rate limiting middleware and returns a stop function.
// The stop function should be called during graceful shutdown.
func RateLimitWithStop(cfg *config.RateLimitConfig, log *logger.Logger) (func(http.Handler) http.Handler, func()) {
	if !cfg.Enabled {
		return func(next http.Handler) http.Handler {
			return next
		}, func() {} // No-op stop function
	}

	rl := NewRateLimiter(cfg, log)
	return rl.Middleware(), rl.Stop
}

// RateLimit creates a rate limiting middleware from config.
// Note: For proper cleanup, use RateLimitWithStop instead.
func RateLimit(cfg *config.RateLimitConfig, log *logger.Logger) func(http.Handler) http.Handler {
	mw, _ := RateLimitWithStop(cfg, log)
	return mw
}

// getClientIP extracts the real client IP from the request.
//
// SECURITY (S-4): Forwarding headers (X-Real-IP, X-Forwarded-For) are
// honored ONLY when the immediate TCP peer (r.RemoteAddr) is in the
// configured trusted-proxy CIDR allowlist. Without this guard, attackers
// could spoof IPs to defeat the per-IP rate limit and corrupt audit
// logging on login / password-reset flows.
//
// trustedProxies is package-level state populated once at startup via
// SetTrustedProxies. When unset (e.g. tests, no SERVER_TRUSTED_PROXIES),
// only r.RemoteAddr is trusted — which is correct for direct-Internet
// deployments.
func getClientIP(r *http.Request) string {
	return httpsec.ClientIP(r, trustedProxies)
}

// trustedProxies is wired by cmd/server during init. It can stay nil for
// tests / direct-Internet deployments — ClientIP falls back to r.RemoteAddr.
var trustedProxies *httpsec.TrustedProxySet //nolint:gochecknoglobals // set once at startup

// SetTrustedProxies configures the package-level trusted-proxy set used by
// rate-limit and audit-log paths. Call once during server bootstrap.
func SetTrustedProxies(set *httpsec.TrustedProxySet) {
	trustedProxies = set
}

// DistributedRateLimitConfig configures the distributed rate limit middleware.
type DistributedRateLimitConfig struct {
	// Limiter is the Redis-backed rate limiter adapter.
	Limiter *redisinfra.MiddlewareAdapter
	// KeyFunc extracts the rate limit key from the request.
	// Defaults to using client IP.
	KeyFunc func(r *http.Request) string
	// Logger for rate limit events.
	Logger *logger.Logger
	// SkipFunc optionally skips rate limiting for certain requests.
	SkipFunc func(r *http.Request) bool
}

// DistributedRateLimit creates middleware using Redis-backed rate limiting.
// Essential for production multi-instance deployments where in-memory
// rate limiting is insufficient.
//
// Example usage:
//
//	rateLimiter, _ := redis.NewRateLimiter(client, "api", 100, time.Minute, log)
//	adapter := redis.NewMiddlewareAdapter(rateLimiter)
//	router.Use(middleware.DistributedRateLimit(middleware.DistributedRateLimitConfig{
//	    Limiter: adapter,
//	    Logger:  log,
//	}))
func DistributedRateLimit(cfg DistributedRateLimitConfig) func(http.Handler) http.Handler {
	if cfg.KeyFunc == nil {
		cfg.KeyFunc = getClientIP
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip if configured
			if cfg.SkipFunc != nil && cfg.SkipFunc(r) {
				next.ServeHTTP(w, r)
				return
			}

			key := cfg.KeyFunc(r)
			result, err := cfg.Limiter.Allow(r.Context(), key)

			if err != nil {
				// Fail-open: allow request if Redis is unavailable
				if cfg.Logger != nil {
					cfg.Logger.Error("distributed rate limit check failed",
						"error", err,
						"key", key,
						"request_id", GetRequestID(r.Context()),
					)
				}
				next.ServeHTTP(w, r)
				return
			}

			// Set standard rate limit headers
			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(cfg.Limiter.Limit()))
			w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(result.Remaining))
			w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(result.ResetAt.Unix(), 10))

			if !result.Allowed {
				retryAfter := int(time.Until(result.RetryAt).Seconds())
				if retryAfter < 1 {
					retryAfter = 1
				}
				w.Header().Set("Retry-After", strconv.Itoa(retryAfter))

				if cfg.Logger != nil {
					cfg.Logger.Warn("distributed rate limit exceeded",
						"key", key,
						"retry_at", result.RetryAt,
						"request_id", GetRequestID(r.Context()),
					)
				}

				apierror.RateLimitExceeded().WriteJSON(w)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// UserKeyFunc returns a key function that uses authenticated user ID.
// Falls back to IP address for unauthenticated requests.
func UserKeyFunc(r *http.Request) string {
	if userID := GetUserID(r.Context()); userID != "" {
		return "user:" + userID
	}
	return "ip:" + getClientIP(r)
}

// EndpointKeyFunc returns a key function that includes the endpoint.
// Useful for per-endpoint rate limiting.
func EndpointKeyFunc(r *http.Request) string {
	base := UserKeyFunc(r)
	return base + ":" + r.Method + ":" + r.URL.Path
}

// =============================================================================
// Auth-Specific Rate Limiting
// =============================================================================

// AuthRateLimiter provides stricter rate limiting for authentication endpoints.
// This is critical for preventing brute-force attacks.
//
// Each bucket is in-memory by default. Built with NewDistributedAuthRateLimiter
// it counts in a shared store (Redis) instead, so every API replica spends the
// same budget; the in-memory bucket is then only the fallback for a store
// error (see authBucket).
type AuthRateLimiter struct {
	loginLimiter         *authBucket // Very strict: 5 attempts per minute per IP
	registerLimiter      *authBucket // Strict: 3 attempts per minute per IP
	passwordLimiter      *authBucket // Very strict: 3 attempts per minute per IP
	tokenExchangeLimiter *authBucket // Moderate: 20 per minute per IP (tenant switch)
	mfaLimiter           *authBucket // Second login step: 10 per minute per challenge
	mfaIPLimiter         *authBucket // Second login step: 30 per minute per IP
	log                  *logger.Logger
}

// AuthRateLimitConfig configures auth-specific rate limits.
type AuthRateLimitConfig struct {
	// LoginRatePerMin is the max login attempts per minute per IP.
	// Default: 5
	LoginRatePerMin int
	// RegisterRatePerMin is the max registration attempts per minute per IP.
	// Default: 3
	RegisterRatePerMin int
	// PasswordResetRatePerMin is the max password reset/forgot attempts per minute per IP.
	// Default: 3
	PasswordResetRatePerMin int
	// TokenExchangeRatePerMin is the max token exchange/refresh attempts per minute per IP.
	// Higher than login because token exchange requires a valid refresh token (not brute-forceable)
	// and is used for tenant switching which may happen frequently.
	// Default: 20
	TokenExchangeRatePerMin int
	// MFARatePerMin is the max second-factor attempts per minute per login
	// challenge (mfa_token). Default: 10. Guessing is bounded anyway by the
	// challenge's attempt cap (mfa.MaxChallengeAttempts) and the per-user
	// lockout; this only stops hammering one challenge.
	MFARatePerMin int
	// MFAIPRatePerMin is the max second-factor attempts per minute per IP,
	// across challenges. Default: 30.
	MFAIPRatePerMin int
	// CleanupInterval for visitor entries.
	// Default: 1 minute
	CleanupInterval time.Duration
}

// DefaultAuthRateLimitConfig returns secure defaults for auth rate limiting.
func DefaultAuthRateLimitConfig() AuthRateLimitConfig {
	return AuthRateLimitConfig{
		LoginRatePerMin:         5,
		RegisterRatePerMin:      3,
		PasswordResetRatePerMin: 3,
		TokenExchangeRatePerMin: 20,
		MFARatePerMin:           10,
		MFAIPRatePerMin:         30,
		CleanupInterval:         time.Minute,
	}
}

// NewAuthRateLimiter creates an in-memory rate limiter specialized for
// authentication endpoints. Its budgets are per process: with N API replicas a
// client gets N times the budget. Production wiring uses
// NewDistributedAuthRateLimiter.
func NewAuthRateLimiter(cfg AuthRateLimitConfig, log *logger.Logger) *AuthRateLimiter {
	return NewDistributedAuthRateLimiter(cfg, log, nil, "")
}

// NewDistributedAuthRateLimiter creates an auth rate limiter whose buckets
// count in backend, shared by every API replica. scope names this limiter's
// buckets in the store ("auth", "console", ...), so limiters mounted on
// different routes keep separate budgets, while the same scope on another
// replica shares them. A nil backend gives the in-memory limiter.
func NewDistributedAuthRateLimiter(cfg AuthRateLimitConfig, log *logger.Logger, backend AuthRateLimitBackend, scope string) *AuthRateLimiter {
	if cfg.LoginRatePerMin == 0 {
		cfg.LoginRatePerMin = 5
	}
	if cfg.RegisterRatePerMin == 0 {
		cfg.RegisterRatePerMin = 3
	}
	if cfg.PasswordResetRatePerMin == 0 {
		cfg.PasswordResetRatePerMin = 3
	}
	if cfg.CleanupInterval == 0 {
		cfg.CleanupInterval = time.Minute
	}
	if cfg.TokenExchangeRatePerMin == 0 {
		cfg.TokenExchangeRatePerMin = 20
	}
	if cfg.MFARatePerMin == 0 {
		cfg.MFARatePerMin = 10
	}
	if cfg.MFAIPRatePerMin == 0 {
		cfg.MFAIPRatePerMin = 30
	}
	if scope == "" {
		scope = "auth"
	}

	bucket := func(name string, perMin int) *authBucket {
		return newAuthBucket(scope+":"+name, perMin, cfg.CleanupInterval, backend, log)
	}
	return &AuthRateLimiter{
		loginLimiter:         bucket("login", cfg.LoginRatePerMin),
		registerLimiter:      bucket("register", cfg.RegisterRatePerMin),
		passwordLimiter:      bucket("password", cfg.PasswordResetRatePerMin),
		tokenExchangeLimiter: bucket("token", cfg.TokenExchangeRatePerMin),
		mfaLimiter:           bucket("mfa", cfg.MFARatePerMin),
		mfaIPLimiter:         bucket("mfa-ip", cfg.MFAIPRatePerMin),
		log:                  log,
	}
}

// Stop gracefully shuts down all rate limiters.
func (a *AuthRateLimiter) Stop() {
	a.loginLimiter.local.Stop()
	a.registerLimiter.local.Stop()
	a.passwordLimiter.local.Stop()
	a.tokenExchangeLimiter.local.Stop()
	a.mfaLimiter.local.Stop()
	a.mfaIPLimiter.local.Stop()
}

// LoginMiddleware returns middleware for login endpoints.
// Applies strict rate limiting to prevent brute-force attacks.
func (a *AuthRateLimiter) LoginMiddleware() func(http.Handler) http.Handler {
	return a.loginLimiter.middleware(getClientIP)
}

// MFAMiddleware returns middleware for the second login step
// (/auth/mfa/verify and required enrollment). It has its own buckets, so the
// sign-ins that led to a challenge do not use up its attempts: per challenge
// (the mfa_token in the JSON body, hashed) and a looser per-IP ceiling across
// challenges. A request without a token is limited by IP only.
func (a *AuthRateLimiter) MFAMiddleware() func(http.Handler) http.Handler {
	perIP := a.mfaIPLimiter.middleware(func(r *http.Request) string { return "mfa-ip:" + getClientIP(r) })
	perChallenge := a.mfaLimiter.middleware(mfaChallengeKey)
	return func(next http.Handler) http.Handler {
		return perIP(perChallenge(next))
	}
}

// mfaChallengeKey keys a second-factor request by its challenge token. The
// body is read (bounded) and restored for the handler; only a hash of the
// token is kept as the bucket key.
func mfaChallengeKey(r *http.Request) string {
	if r.Body == nil {
		return "mfa-ip:" + getClientIP(r)
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, mfaBodyLimit))
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(body))
	var v struct {
		MFAToken string `json:"mfa_token"`
	}
	if err != nil || json.Unmarshal(body, &v) != nil || v.MFAToken == "" {
		return "mfa-ip:" + getClientIP(r)
	}
	sum := sha256.Sum256([]byte(v.MFAToken))
	return "mfa-challenge:" + hex.EncodeToString(sum[:16])
}

// mfaBodyLimit bounds the body read to find the challenge token. The second
// login step's bodies are a few hundred bytes.
const mfaBodyLimit = 4096

// TokenExchangeMiddleware returns middleware for token exchange/refresh endpoints.
// Uses a higher rate limit than login because token exchange requires a valid
// refresh token (not brute-forceable) and is used for tenant switching.
func (a *AuthRateLimiter) TokenExchangeMiddleware() func(http.Handler) http.Handler {
	return a.tokenExchangeLimiter.middleware(getClientIP)
}

// RegisterMiddleware returns middleware for registration endpoints.
func (a *AuthRateLimiter) RegisterMiddleware() func(http.Handler) http.Handler {
	return a.registerLimiter.middleware(getClientIP)
}

// PasswordMiddleware returns middleware for password reset/forgot endpoints.
func (a *AuthRateLimiter) PasswordMiddleware() func(http.Handler) http.Handler {
	return a.passwordLimiter.middleware(getClientIP)
}

// =============================================================================
// Platform Sensor Auth Failure Rate Limiting
// =============================================================================

// AuthFailureLimiter tracks auth failures and blocks IPs after too many failures.
// This provides protection against brute-force attacks on platform sensor credentials.
type AuthFailureLimiter struct {
	mu              sync.RWMutex
	failures        map[string]*authFailureEntry // IP -> failure info
	maxFailures     int                          // Max failures before ban
	banDuration     time.Duration                // How long to ban
	windowDuration  time.Duration                // Time window for counting failures
	cleanupInterval time.Duration
	log             *logger.Logger
	done            chan struct{}
	stopped         chan struct{}
	stopOnce        sync.Once
}

type authFailureEntry struct {
	count     int
	firstFail time.Time
	bannedAt  *time.Time
}

// AuthFailureLimiterConfig configures the auth failure limiter.
type AuthFailureLimiterConfig struct {
	// MaxFailures is the max auth failures before IP is banned.
	// Default: 5
	MaxFailures int
	// BanDuration is how long an IP is banned after max failures.
	// Default: 15 minutes
	BanDuration time.Duration
	// WindowDuration is the time window for counting failures.
	// Default: 5 minutes
	WindowDuration time.Duration
	// CleanupInterval for removing old entries.
	// Default: 1 minute
	CleanupInterval time.Duration
}

// DefaultAuthFailureLimiterConfig returns secure defaults.
func DefaultAuthFailureLimiterConfig() AuthFailureLimiterConfig {
	return AuthFailureLimiterConfig{
		MaxFailures:     5,
		BanDuration:     15 * time.Minute,
		WindowDuration:  5 * time.Minute,
		CleanupInterval: time.Minute,
	}
}

// NewAuthFailureLimiter creates a new auth failure limiter.
func NewAuthFailureLimiter(cfg AuthFailureLimiterConfig, log *logger.Logger) *AuthFailureLimiter {
	if cfg.MaxFailures == 0 {
		cfg.MaxFailures = 5
	}
	if cfg.BanDuration == 0 {
		cfg.BanDuration = 15 * time.Minute
	}
	if cfg.WindowDuration == 0 {
		cfg.WindowDuration = 5 * time.Minute
	}
	if cfg.CleanupInterval == 0 {
		cfg.CleanupInterval = time.Minute
	}

	afl := &AuthFailureLimiter{
		failures:        make(map[string]*authFailureEntry),
		maxFailures:     cfg.MaxFailures,
		banDuration:     cfg.BanDuration,
		windowDuration:  cfg.WindowDuration,
		cleanupInterval: cfg.CleanupInterval,
		log:             log,
		done:            make(chan struct{}),
		stopped:         make(chan struct{}),
	}

	go afl.cleanup()

	return afl
}

// Stop stops the cleanup goroutine.
func (afl *AuthFailureLimiter) Stop() {
	afl.stopOnce.Do(func() {
		close(afl.done)
	})
	<-afl.stopped
}

// cleanup removes expired entries.
func (afl *AuthFailureLimiter) cleanup() {
	ticker := time.NewTicker(afl.cleanupInterval)
	defer ticker.Stop()
	defer close(afl.stopped)

	for {
		select {
		case <-afl.done:
			return
		case <-ticker.C:
			afl.mu.Lock()
			now := time.Now()
			for ip, entry := range afl.failures {
				// Remove if ban expired
				if entry.bannedAt != nil && now.Sub(*entry.bannedAt) > afl.banDuration {
					delete(afl.failures, ip)
					continue
				}
				// Remove if window expired and not banned
				if entry.bannedAt == nil && now.Sub(entry.firstFail) > afl.windowDuration {
					delete(afl.failures, ip)
				}
			}
			afl.mu.Unlock()
		}
	}
}

// IsBanned checks if an IP is currently banned.
func (afl *AuthFailureLimiter) IsBanned(ip string) bool {
	afl.mu.RLock()
	defer afl.mu.RUnlock()

	entry, exists := afl.failures[ip]
	if !exists || entry.bannedAt == nil {
		return false
	}

	// Check if ban has expired
	if time.Since(*entry.bannedAt) > afl.banDuration {
		return false
	}

	return true
}

// RecordFailure records an auth failure for an IP.
// Returns true if the IP is now banned.
func (afl *AuthFailureLimiter) RecordFailure(ip string) bool {
	afl.mu.Lock()
	defer afl.mu.Unlock()

	now := time.Now()
	entry, exists := afl.failures[ip]

	if !exists {
		afl.failures[ip] = &authFailureEntry{
			count:     1,
			firstFail: now,
		}
		return false
	}

	// If already banned, extend ban
	if entry.bannedAt != nil {
		entry.bannedAt = &now
		return true
	}

	// If window expired, reset counter
	if now.Sub(entry.firstFail) > afl.windowDuration {
		entry.count = 1
		entry.firstFail = now
		return false
	}

	// Increment counter
	entry.count++

	// Check if should ban
	if entry.count >= afl.maxFailures {
		entry.bannedAt = &now
		if afl.log != nil {
			afl.log.Warn("IP banned due to auth failures",
				"event", SecurityEventAuthFailure,
				"ip", ip,
				"failure_count", entry.count,
				"ban_duration", afl.banDuration,
			)
		}
		return true
	}

	return false
}

// RecordSuccess clears failure count for an IP (on successful auth).
func (afl *AuthFailureLimiter) RecordSuccess(ip string) {
	afl.mu.Lock()
	defer afl.mu.Unlock()

	delete(afl.failures, ip)
}

// GetStats returns current limiter stats.
func (afl *AuthFailureLimiter) GetStats() (trackedIPs int, bannedIPs int) {
	afl.mu.RLock()
	defer afl.mu.RUnlock()

	trackedIPs = len(afl.failures)
	for _, entry := range afl.failures {
		if entry.bannedAt != nil && time.Since(*entry.bannedAt) <= afl.banDuration {
			bannedIPs++
		}
	}
	return
}

// =============================================================================
// Trigger Rate Limiting (Pipeline/Scan Execution)
// =============================================================================

// TriggerRateLimiter provides rate limiting for pipeline and scan trigger endpoints.
// This prevents abuse and ensures fair resource usage.
type TriggerRateLimiter struct {
	pipelineLimiter  *RateLimiter // Per-tenant pipeline triggers
	scanLimiter      *RateLimiter // Per-tenant scan triggers
	quickScanLimiter *RateLimiter // Per-tenant quick scan triggers (stricter)
	log              *logger.Logger
}

// TriggerRateLimitConfig configures trigger-specific rate limits.
type TriggerRateLimitConfig struct {
	// PipelineTriggersPerMin is the max pipeline triggers per minute per tenant.
	// Default: 30
	PipelineTriggersPerMin int
	// ScanTriggersPerMin is the max scan triggers per minute per tenant.
	// Default: 20
	ScanTriggersPerMin int
	// QuickScanTriggersPerMin is the max quick scan triggers per minute per tenant.
	// Default: 10 (stricter as quick scans can be resource-intensive)
	QuickScanTriggersPerMin int
	// CleanupInterval for visitor entries.
	// Default: 1 minute
	CleanupInterval time.Duration
}

// DefaultTriggerRateLimitConfig returns secure defaults for trigger rate limiting.
func DefaultTriggerRateLimitConfig() TriggerRateLimitConfig {
	return TriggerRateLimitConfig{
		PipelineTriggersPerMin:  30,
		ScanTriggersPerMin:      20,
		QuickScanTriggersPerMin: 10,
		CleanupInterval:         time.Minute,
	}
}

// NewTriggerRateLimiter creates a rate limiter specialized for trigger endpoints.
func NewTriggerRateLimiter(cfg TriggerRateLimitConfig, log *logger.Logger) *TriggerRateLimiter {
	if cfg.PipelineTriggersPerMin == 0 {
		cfg.PipelineTriggersPerMin = 30
	}
	if cfg.ScanTriggersPerMin == 0 {
		cfg.ScanTriggersPerMin = 20
	}
	if cfg.QuickScanTriggersPerMin == 0 {
		cfg.QuickScanTriggersPerMin = 10
	}
	if cfg.CleanupInterval == 0 {
		cfg.CleanupInterval = time.Minute
	}

	// Convert per-minute rates to per-second for rate.Limit
	pipelineRate := float64(cfg.PipelineTriggersPerMin) / 60.0
	scanRate := float64(cfg.ScanTriggersPerMin) / 60.0
	quickScanRate := float64(cfg.QuickScanTriggersPerMin) / 60.0

	return &TriggerRateLimiter{
		pipelineLimiter: NewRateLimiter(&config.RateLimitConfig{
			Enabled:         true,
			RequestsPerSec:  pipelineRate,
			Burst:           cfg.PipelineTriggersPerMin,
			CleanupInterval: cfg.CleanupInterval,
		}, log),
		scanLimiter: NewRateLimiter(&config.RateLimitConfig{
			Enabled:         true,
			RequestsPerSec:  scanRate,
			Burst:           cfg.ScanTriggersPerMin,
			CleanupInterval: cfg.CleanupInterval,
		}, log),
		quickScanLimiter: NewRateLimiter(&config.RateLimitConfig{
			Enabled:         true,
			RequestsPerSec:  quickScanRate,
			Burst:           cfg.QuickScanTriggersPerMin,
			CleanupInterval: cfg.CleanupInterval,
		}, log),
		log: log,
	}
}

// Stop gracefully shuts down all rate limiters.
func (t *TriggerRateLimiter) Stop() {
	t.pipelineLimiter.Stop()
	t.scanLimiter.Stop()
	t.quickScanLimiter.Stop()
}

// PipelineMiddleware returns middleware for pipeline trigger endpoints.
// Uses tenant ID as the rate limit key for per-tenant limiting.
func (t *TriggerRateLimiter) PipelineMiddleware() func(http.Handler) http.Handler {
	return t.wrapWithTenantKey(t.pipelineLimiter)
}

// ScanMiddleware returns middleware for scan trigger endpoints.
// Uses tenant ID as the rate limit key for per-tenant limiting.
func (t *TriggerRateLimiter) ScanMiddleware() func(http.Handler) http.Handler {
	return t.wrapWithTenantKey(t.scanLimiter)
}

// QuickScanMiddleware returns middleware for quick scan trigger endpoints.
// Uses tenant ID as the rate limit key for per-tenant limiting.
func (t *TriggerRateLimiter) QuickScanMiddleware() func(http.Handler) http.Handler {
	return t.wrapWithTenantKey(t.quickScanLimiter)
}

// =============================================================================
// Finding Activity Rate Limiting
// =============================================================================

// FindingActivityRateLimiter provides rate limiting for finding activity endpoints.
// This prevents enumeration attacks and DoS on activity APIs.
type FindingActivityRateLimiter struct {
	listLimiter *RateLimiter // Per-user activity list requests
	log         *logger.Logger
}

// FindingActivityRateLimitConfig configures finding activity rate limits.
type FindingActivityRateLimitConfig struct {
	// ListRequestsPerMin is the max list activity requests per minute per user.
	// Default: 60
	ListRequestsPerMin int
	// CleanupInterval for visitor entries.
	// Default: 1 minute
	CleanupInterval time.Duration
}

// DefaultFindingActivityRateLimitConfig returns secure defaults.
func DefaultFindingActivityRateLimitConfig() FindingActivityRateLimitConfig {
	return FindingActivityRateLimitConfig{
		ListRequestsPerMin: 60,
		CleanupInterval:    time.Minute,
	}
}

// NewFindingActivityRateLimiter creates a rate limiter for finding activity endpoints.
func NewFindingActivityRateLimiter(cfg FindingActivityRateLimitConfig, log *logger.Logger) *FindingActivityRateLimiter {
	if cfg.ListRequestsPerMin == 0 {
		cfg.ListRequestsPerMin = 60
	}
	if cfg.CleanupInterval == 0 {
		cfg.CleanupInterval = time.Minute
	}

	// Convert per-minute rate to per-second for rate.Limit
	listRate := float64(cfg.ListRequestsPerMin) / 60.0

	return &FindingActivityRateLimiter{
		listLimiter: NewRateLimiter(&config.RateLimitConfig{
			Enabled:         true,
			RequestsPerSec:  listRate,
			Burst:           cfg.ListRequestsPerMin,
			CleanupInterval: cfg.CleanupInterval,
		}, log),
		log: log,
	}
}

// Stop gracefully shuts down the rate limiter.
func (f *FindingActivityRateLimiter) Stop() {
	f.listLimiter.Stop()
}

// ListMiddleware returns middleware for activity list endpoints.
// Uses user ID (or IP) as the rate limit key for per-user limiting.
func (f *FindingActivityRateLimiter) ListMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Use user ID as the key for per-user rate limiting
			key := UserKeyFunc(r)
			limiter := f.listLimiter.getVisitor(key)

			// Get current tokens before Allow() consumes one
			tokens := limiter.Tokens()
			remaining := int(math.Max(0, math.Floor(tokens)-1))

			// Calculate reset time
			tokensToRefill := float64(f.listLimiter.burst) - tokens
			var resetTime time.Time
			if tokensToRefill > 0 && f.listLimiter.rate > 0 {
				secondsToRefill := tokensToRefill / float64(f.listLimiter.rate)
				resetTime = time.Now().Add(time.Duration(secondsToRefill * float64(time.Second)))
			} else {
				resetTime = time.Now()
			}

			// Set rate limit headers
			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(f.listLimiter.burst))
			w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
			w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(resetTime.Unix(), 10))

			if !limiter.Allow() {
				f.log.Warn("finding activity rate limit exceeded",
					"key", key,
					"path", RedactPath(r.URL.Path),
					"request_id", GetRequestID(r.Context()),
				)

				w.Header().Set("X-RateLimit-Remaining", "0")
				w.Header().Set("Retry-After", "1")
				apierror.RateLimitExceeded().WriteJSON(w)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// =============================================================================
// Analytics Rate Limiting
// =============================================================================

// AnalyticsRateLimiter provides rate limiting for sensor analytics endpoints.
// This prevents abuse and ensures fair resource usage for analytics queries.
type AnalyticsRateLimiter struct {
	listLimiter       *RateLimiter // Per-tenant list requests (sessions, daily stats)
	aggregatedLimiter *RateLimiter // Per-tenant aggregated stats requests (more expensive)
	log               *logger.Logger
}

// AnalyticsRateLimitConfig configures analytics-specific rate limits.
type AnalyticsRateLimitConfig struct {
	// ListRequestsPerMin is the max list requests per minute per tenant.
	// Default: 60 (1 per second)
	ListRequestsPerMin int
	// AggregatedRequestsPerMin is the max aggregated stats requests per minute per tenant.
	// Default: 30 (more expensive queries)
	AggregatedRequestsPerMin int
	// CleanupInterval for visitor entries.
	// Default: 1 minute
	CleanupInterval time.Duration
}

// DefaultAnalyticsRateLimitConfig returns secure defaults for analytics rate limiting.
func DefaultAnalyticsRateLimitConfig() AnalyticsRateLimitConfig {
	return AnalyticsRateLimitConfig{
		ListRequestsPerMin:       60,
		AggregatedRequestsPerMin: 30,
		CleanupInterval:          time.Minute,
	}
}

// NewAnalyticsRateLimiter creates a rate limiter for analytics endpoints.
func NewAnalyticsRateLimiter(cfg AnalyticsRateLimitConfig, log *logger.Logger) *AnalyticsRateLimiter {
	if cfg.ListRequestsPerMin == 0 {
		cfg.ListRequestsPerMin = 60
	}
	if cfg.AggregatedRequestsPerMin == 0 {
		cfg.AggregatedRequestsPerMin = 30
	}
	if cfg.CleanupInterval == 0 {
		cfg.CleanupInterval = time.Minute
	}

	// Convert per-minute rates to per-second for rate.Limit
	listRate := float64(cfg.ListRequestsPerMin) / 60.0
	aggregatedRate := float64(cfg.AggregatedRequestsPerMin) / 60.0

	return &AnalyticsRateLimiter{
		listLimiter: NewRateLimiter(&config.RateLimitConfig{
			Enabled:         true,
			RequestsPerSec:  listRate,
			Burst:           cfg.ListRequestsPerMin,
			CleanupInterval: cfg.CleanupInterval,
		}, log),
		aggregatedLimiter: NewRateLimiter(&config.RateLimitConfig{
			Enabled:         true,
			RequestsPerSec:  aggregatedRate,
			Burst:           cfg.AggregatedRequestsPerMin,
			CleanupInterval: cfg.CleanupInterval,
		}, log),
		log: log,
	}
}

// Stop gracefully shuts down all rate limiters.
func (a *AnalyticsRateLimiter) Stop() {
	a.listLimiter.Stop()
	a.aggregatedLimiter.Stop()
}

// ListMiddleware returns middleware for analytics list endpoints.
// Uses tenant ID (or user ID for admin) as the rate limit key.
func (a *AnalyticsRateLimiter) ListMiddleware() func(http.Handler) http.Handler {
	return a.wrapWithKey(a.listLimiter, "analytics_list")
}

// AggregatedMiddleware returns middleware for aggregated stats endpoints.
// Uses tenant ID (or user ID for admin) as the rate limit key.
// More restrictive as aggregated queries are more expensive.
func (a *AnalyticsRateLimiter) AggregatedMiddleware() func(http.Handler) http.Handler {
	return a.wrapWithKey(a.aggregatedLimiter, "analytics_aggregated")
}

// wrapWithKey wraps a rate limiter to use tenant/user ID as the key.
func (a *AnalyticsRateLimiter) wrapWithKey(rl *RateLimiter, category string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Use tenant ID if available, otherwise use user ID or IP
			key := GetTenantID(r.Context())
			if key == "" {
				key = UserKeyFunc(r)
			} else {
				key = "tenant:" + key
			}

			limiter := rl.getVisitor(key)

			// Get current tokens before Allow() consumes one
			tokens := limiter.Tokens()
			remaining := int(math.Max(0, math.Floor(tokens)-1))

			// Calculate reset time
			tokensToRefill := float64(rl.burst) - tokens
			var resetTime time.Time
			if tokensToRefill > 0 && rl.rate > 0 {
				secondsToRefill := tokensToRefill / float64(rl.rate)
				resetTime = time.Now().Add(time.Duration(secondsToRefill * float64(time.Second)))
			} else {
				resetTime = time.Now()
			}

			// Set rate limit headers
			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(rl.burst))
			w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
			w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(resetTime.Unix(), 10))

			if !limiter.Allow() {
				a.log.Warn("analytics rate limit exceeded",
					"category", category,
					"key", key,
					"path", RedactPath(r.URL.Path),
					"request_id", GetRequestID(r.Context()),
				)

				w.Header().Set("X-RateLimit-Remaining", "0")
				w.Header().Set("Retry-After", "1")
				apierror.RateLimitExceeded().WriteJSON(w)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// =============================================================================
// AI Triage Rate Limiting
// =============================================================================

// AITriageRateLimiter provides rate limiting for AI triage endpoints.
// This prevents abuse of expensive LLM API calls.
type AITriageRateLimiter struct {
	requestLimiter *RateLimiter // Per-tenant triage requests
	log            *logger.Logger
}

// AITriageRateLimitConfig configures AI triage rate limits.
type AITriageRateLimitConfig struct {
	// TriageRequestsPerMin is the max triage requests per minute per tenant.
	// Default: 10 (AI calls are expensive)
	TriageRequestsPerMin int
	// CleanupInterval for visitor entries.
	// Default: 1 minute
	CleanupInterval time.Duration
}

// DefaultAITriageRateLimitConfig returns secure defaults for AI triage rate limiting.
func DefaultAITriageRateLimitConfig() AITriageRateLimitConfig {
	return AITriageRateLimitConfig{
		TriageRequestsPerMin: 10,
		CleanupInterval:      time.Minute,
	}
}

// NewAITriageRateLimiter creates a rate limiter for AI triage endpoints.
func NewAITriageRateLimiter(cfg AITriageRateLimitConfig, log *logger.Logger) *AITriageRateLimiter {
	if cfg.TriageRequestsPerMin == 0 {
		cfg.TriageRequestsPerMin = 10
	}
	if cfg.CleanupInterval == 0 {
		cfg.CleanupInterval = time.Minute
	}

	// Convert per-minute rate to per-second for rate.Limit
	requestRate := float64(cfg.TriageRequestsPerMin) / 60.0

	return &AITriageRateLimiter{
		requestLimiter: NewRateLimiter(&config.RateLimitConfig{
			Enabled:         true,
			RequestsPerSec:  requestRate,
			Burst:           cfg.TriageRequestsPerMin,
			CleanupInterval: cfg.CleanupInterval,
		}, log),
		log: log,
	}
}

// Stop gracefully shuts down the rate limiter.
func (a *AITriageRateLimiter) Stop() {
	a.requestLimiter.Stop()
}

// RequestMiddleware returns middleware for AI triage request endpoints (POST).
// Uses tenant ID as the rate limit key for per-tenant limiting.
func (a *AITriageRateLimiter) RequestMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Use tenant ID as the key for per-tenant rate limiting
			tenantID := GetTenantID(r.Context())
			if tenantID == "" {
				// Fall back to IP-based limiting if no tenant
				tenantID = "ip:" + getClientIP(r)
			} else {
				tenantID = "ai_triage:tenant:" + tenantID
			}

			limiter := a.requestLimiter.getVisitor(tenantID)

			// Get current tokens before Allow() consumes one
			tokens := limiter.Tokens()
			remaining := int(math.Max(0, math.Floor(tokens)-1))

			// Calculate reset time
			tokensToRefill := float64(a.requestLimiter.burst) - tokens
			var resetTime time.Time
			if tokensToRefill > 0 && a.requestLimiter.rate > 0 {
				secondsToRefill := tokensToRefill / float64(a.requestLimiter.rate)
				resetTime = time.Now().Add(time.Duration(secondsToRefill * float64(time.Second)))
			} else {
				resetTime = time.Now()
			}

			// Set rate limit headers
			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(a.requestLimiter.burst))
			w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
			w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(resetTime.Unix(), 10))

			if !limiter.Allow() {
				a.log.Warn("AI triage rate limit exceeded",
					"tenant_key", tenantID,
					"path", RedactPath(r.URL.Path),
					"request_id", GetRequestID(r.Context()),
				)

				w.Header().Set("X-RateLimit-Remaining", "0")
				w.Header().Set("Retry-After", "6") // 6 seconds for 10 requests/min
				apierror.RateLimitExceeded().WriteJSON(w)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// wrapWithTenantKey wraps a rate limiter to use tenant ID as the key.
func (t *TriggerRateLimiter) wrapWithTenantKey(rl *RateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Use tenant ID as the key for per-tenant rate limiting
			tenantID := GetTenantID(r.Context())
			if tenantID == "" {
				// Fall back to IP-based limiting if no tenant
				tenantID = "ip:" + getClientIP(r)
			} else {
				tenantID = "tenant:" + tenantID
			}

			limiter := rl.getVisitor(tenantID)

			// Get current tokens before Allow() consumes one
			tokens := limiter.Tokens()
			remaining := int(math.Max(0, math.Floor(tokens)-1))

			// Calculate reset time
			tokensToRefill := float64(rl.burst) - tokens
			var resetTime time.Time
			if tokensToRefill > 0 && rl.rate > 0 {
				secondsToRefill := tokensToRefill / float64(rl.rate)
				resetTime = time.Now().Add(time.Duration(secondsToRefill * float64(time.Second)))
			} else {
				resetTime = time.Now()
			}

			// Set rate limit headers
			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(rl.burst))
			w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
			w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(resetTime.Unix(), 10))

			if !limiter.Allow() {
				t.log.Warn("trigger rate limit exceeded",
					"tenant_key", tenantID,
					"path", RedactPath(r.URL.Path),
					"request_id", GetRequestID(r.Context()),
				)

				w.Header().Set("X-RateLimit-Remaining", "0")
				w.Header().Set("Retry-After", "1")
				apierror.RateLimitExceeded().WriteJSON(w)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// =============================================================================
// Admin Target Mapping Rate Limiting
// =============================================================================

// AdminMappingRateLimiter provides rate limiting for admin target mapping endpoints.
// This prevents abuse of admin configuration APIs.
type AdminMappingRateLimiter struct {
	writeLimiter *RateLimiter // Per-IP write operations (create/update/delete)
	log          *logger.Logger
}

// AdminMappingRateLimitConfig configures admin mapping rate limits.
type AdminMappingRateLimitConfig struct {
	// WriteRequestsPerMin is the max write requests per minute per admin.
	// Default: 10 (as per RFC 2026-02-02-asset-types-cleanup.md)
	WriteRequestsPerMin int
	// CleanupInterval for visitor entries.
	// Default: 1 minute
	CleanupInterval time.Duration
}

// DefaultAdminMappingRateLimitConfig returns secure defaults for admin mapping rate limiting.
func DefaultAdminMappingRateLimitConfig() AdminMappingRateLimitConfig {
	return AdminMappingRateLimitConfig{
		WriteRequestsPerMin: 10,
		CleanupInterval:     time.Minute,
	}
}

// NewAdminMappingRateLimiter creates a rate limiter for admin target mapping endpoints.
func NewAdminMappingRateLimiter(cfg AdminMappingRateLimitConfig, log *logger.Logger) *AdminMappingRateLimiter {
	if cfg.WriteRequestsPerMin == 0 {
		cfg.WriteRequestsPerMin = 10
	}
	if cfg.CleanupInterval == 0 {
		cfg.CleanupInterval = time.Minute
	}

	// Convert per-minute rate to per-second for rate.Limit
	writeRate := float64(cfg.WriteRequestsPerMin) / 60.0

	return &AdminMappingRateLimiter{
		writeLimiter: NewRateLimiter(&config.RateLimitConfig{
			Enabled:         true,
			RequestsPerSec:  writeRate,
			Burst:           cfg.WriteRequestsPerMin,
			CleanupInterval: cfg.CleanupInterval,
		}, log),
		log: log,
	}
}

// Stop gracefully shuts down the rate limiter.
func (a *AdminMappingRateLimiter) Stop() {
	a.writeLimiter.Stop()
}

// WriteMiddleware returns middleware for admin mapping write endpoints (POST/PATCH/DELETE).
// Uses admin ID (from context) or IP as the rate limit key.
func (a *AdminMappingRateLimiter) WriteMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get admin user from context for key
			adminUser := GetAdminUser(r.Context())
			var key string
			if adminUser != nil {
				key = "admin:" + adminUser.ID().String()
			} else {
				// Fall back to IP-based limiting
				key = "ip:" + getClientIP(r)
			}

			limiter := a.writeLimiter.getVisitor(key)

			// Get current tokens before Allow() consumes one
			tokens := limiter.Tokens()
			remaining := int(math.Max(0, math.Floor(tokens)-1))

			// Calculate reset time
			tokensToRefill := float64(a.writeLimiter.burst) - tokens
			var resetTime time.Time
			if tokensToRefill > 0 && a.writeLimiter.rate > 0 {
				secondsToRefill := tokensToRefill / float64(a.writeLimiter.rate)
				resetTime = time.Now().Add(time.Duration(secondsToRefill * float64(time.Second)))
			} else {
				resetTime = time.Now()
			}

			// Set rate limit headers
			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(a.writeLimiter.burst))
			w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
			w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(resetTime.Unix(), 10))

			if !limiter.Allow() {
				a.log.Warn("admin mapping rate limit exceeded",
					"key", key,
					"path", RedactPath(r.URL.Path),
					"request_id", GetRequestID(r.Context()),
				)

				w.Header().Set("X-RateLimit-Remaining", "0")
				w.Header().Set("Retry-After", "6") // 6 seconds for 10 requests/min
				apierror.RateLimitExceeded().WriteJSON(w)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// =============================================================================
// Read Endpoint Rate Limiting (per-user for GET requests)
// =============================================================================

// ReadEndpointRateLimiter provides per-user rate limiting for read/list endpoints.
// This prevents enumeration attacks and excessive polling on GET endpoints
// across all authenticated API routes.
type ReadEndpointRateLimiter struct {
	limiter *RateLimiter
	log     *logger.Logger
}

// ReadEndpointRateLimitConfig configures read endpoint rate limits.
type ReadEndpointRateLimitConfig struct {
	// ReadRequestsPerMin is the max GET requests per minute per user.
	// Default: 120 (2 per second — generous for normal usage, blocks scraping)
	ReadRequestsPerMin int
	// CleanupInterval for visitor entries.
	// Default: 1 minute
	CleanupInterval time.Duration
}

// DefaultReadEndpointRateLimitConfig returns secure defaults for read endpoint rate limiting.
func DefaultReadEndpointRateLimitConfig() ReadEndpointRateLimitConfig {
	return ReadEndpointRateLimitConfig{
		ReadRequestsPerMin: 120,
		CleanupInterval:    time.Minute,
	}
}

// ReadEndpointRateLimitConfigFrom derives the read-endpoint limiter config
// from the global rate-limit config (RATE_LIMIT_READ_PER_MIN,
// RATE_LIMIT_CLEANUP). A non-positive value keeps the secure default rather
// than disabling the limiter; turning rate limiting off is only possible via
// RATE_LIMIT_ENABLED, which production config validation rejects.
func ReadEndpointRateLimitConfigFrom(rl config.RateLimitConfig) ReadEndpointRateLimitConfig {
	cfg := DefaultReadEndpointRateLimitConfig()
	if rl.ReadRequestsPerMin > 0 {
		cfg.ReadRequestsPerMin = rl.ReadRequestsPerMin
	}
	if rl.CleanupInterval > 0 {
		cfg.CleanupInterval = rl.CleanupInterval
	}
	return cfg
}

// NewReadEndpointRateLimiter creates a rate limiter for read/list endpoints.
func NewReadEndpointRateLimiter(cfg ReadEndpointRateLimitConfig, log *logger.Logger) *ReadEndpointRateLimiter {
	if cfg.ReadRequestsPerMin <= 0 {
		cfg.ReadRequestsPerMin = 120
	}
	if cfg.CleanupInterval == 0 {
		cfg.CleanupInterval = time.Minute
	}

	// Convert per-minute rate to per-second for rate.Limit
	readRate := float64(cfg.ReadRequestsPerMin) / 60.0

	return &ReadEndpointRateLimiter{
		limiter: NewRateLimiter(&config.RateLimitConfig{
			Enabled:         true,
			RequestsPerSec:  readRate,
			Burst:           cfg.ReadRequestsPerMin,
			CleanupInterval: cfg.CleanupInterval,
		}, log),
		log: log,
	}
}

// Stop gracefully shuts down the rate limiter.
func (rel *ReadEndpointRateLimiter) Stop() {
	rel.limiter.Stop()
}

// Middleware returns middleware that rate-limits GET requests per user.
// Non-GET requests pass through without rate limiting.
func (rel *ReadEndpointRateLimiter) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Only rate-limit GET (read/list) requests
			if r.Method != http.MethodGet {
				next.ServeHTTP(w, r)
				return
			}

			// Use user ID as the key for per-user rate limiting
			key := UserKeyFunc(r)
			limiter := rel.limiter.getVisitor(key)

			// Get current tokens before Allow() consumes one
			tokens := limiter.Tokens()
			remaining := int(math.Max(0, math.Floor(tokens)-1))

			// Calculate reset time
			tokensToRefill := float64(rel.limiter.burst) - tokens
			var resetTime time.Time
			if tokensToRefill > 0 && rel.limiter.rate > 0 {
				secondsToRefill := tokensToRefill / float64(rel.limiter.rate)
				resetTime = time.Now().Add(time.Duration(secondsToRefill * float64(time.Second)))
			} else {
				resetTime = time.Now()
			}

			// Set rate limit headers
			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(rel.limiter.burst))
			w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
			w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(resetTime.Unix(), 10))

			if !limiter.Allow() {
				if rel.log != nil {
					rel.log.Warn("read endpoint rate limit exceeded",
						"key", key,
						"path", RedactPath(r.URL.Path),
						"request_id", GetRequestID(r.Context()),
					)
				}

				w.Header().Set("X-RateLimit-Remaining", "0")
				w.Header().Set("Retry-After", "1")
				apierror.RateLimitExceeded().WriteJSON(w)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
