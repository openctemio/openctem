package redis

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/openctemio/api/pkg/logger"
)

// Lua scripts are compiled once at package initialization for performance.
// These scripts ensure atomic operations for rate limiting.
var (
	// allowScript checks and consumes one request token atomically.
	allowScript = redis.NewScript(`
		local key = KEYS[1]
		local now = tonumber(ARGV[1])
		local window_start = tonumber(ARGV[2])
		local window_ms = tonumber(ARGV[3])
		local limit = tonumber(ARGV[4])
		local request_id = ARGV[5]

		-- Remove expired entries
		redis.call('ZREMRANGEBYSCORE', key, '-inf', window_start)

		-- Count current requests
		local count = redis.call('ZCARD', key)

		if count < limit then
			-- Add new request
			redis.call('ZADD', key, now, request_id)
			redis.call('PEXPIRE', key, window_ms)
			return {1, limit - count - 1, now + window_ms}
		else
			-- Get oldest entry for retry time
			local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
			local retry_at = oldest[2] and (tonumber(oldest[2]) + window_ms) or (now + window_ms)
			return {0, 0, retry_at}
		end
	`)

	// allowNScript checks and consumes N request tokens atomically.
	allowNScript = redis.NewScript(`
		local key = KEYS[1]
		local now = tonumber(ARGV[1])
		local window_start = tonumber(ARGV[2])
		local window_ms = tonumber(ARGV[3])
		local limit = tonumber(ARGV[4])
		local n = tonumber(ARGV[5])
		local request_prefix = ARGV[6]

		-- Remove expired entries
		redis.call('ZREMRANGEBYSCORE', key, '-inf', window_start)

		-- Count current requests
		local count = redis.call('ZCARD', key)

		if count + n <= limit then
			-- Add new requests with unique IDs
			for i = 1, n do
				redis.call('ZADD', key, now, request_prefix .. ':' .. i)
			end
			redis.call('PEXPIRE', key, window_ms)
			return {1, limit - count - n, now + window_ms}
		else
			local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
			local retry_at = oldest[2] and (tonumber(oldest[2]) + window_ms) or (now + window_ms)
			return {0, math.max(0, limit - count), retry_at}
		end
	`)

	// statusScript gets current rate limit status atomically without consuming tokens.
	statusScript = redis.NewScript(`
		local key = KEYS[1]
		local now = tonumber(ARGV[1])
		local window_start = tonumber(ARGV[2])
		local window_ms = tonumber(ARGV[3])
		local limit = tonumber(ARGV[4])

		-- Remove expired entries
		redis.call('ZREMRANGEBYSCORE', key, '-inf', window_start)

		-- Count current requests
		local count = redis.call('ZCARD', key)

		-- Get TTL
		local ttl = redis.call('PTTL', key)
		if ttl < 0 then
			ttl = window_ms
		end

		local remaining = limit - count
		if remaining < 0 then
			remaining = 0
		end

		local allowed = 0
		if count < limit then
			allowed = 1
		end

		return {allowed, remaining, now + ttl}
	`)
)

// RateLimiter implements distributed rate limiting using Redis.
// It uses the sliding window log algorithm with sorted sets for accurate
// rate limiting across distributed systems.
//
// The sliding window algorithm tracks individual request timestamps,
// providing more accurate rate limiting compared to fixed windows.
type RateLimiter struct {
	client    *Client
	keyPrefix string
	limit     int
	window    time.Duration
	logger    *logger.Logger
}

// RateLimitResult contains the result of a rate limit check.
type RateLimitResult struct {
	// Allowed indicates if the request is permitted.
	Allowed bool

	// Remaining is the number of requests left in the current window.
	Remaining int

	// ResetAt is when the rate limit window resets.
	ResetAt time.Time

	// RetryAt is when the client should retry (only set when not allowed).
	RetryAt time.Time
}

// NewRateLimiter creates a new distributed rate limiter.
//
// Parameters:
//   - client: Redis client for storage
//   - prefix: Key prefix for namespacing (e.g., "ratelimit:api")
//   - limit: Maximum requests allowed per window
//   - window: Time window duration
//   - log: Logger for debugging
//
// Example:
//
//	rl, err := redis.NewRateLimiter(client, "api", 100, time.Minute, logger)
func NewRateLimiter(client *Client, prefix string, limit int, window time.Duration, log *logger.Logger) (*RateLimiter, error) {
	if client == nil {
		return nil, errors.New("redis client is required")
	}
	if prefix == "" {
		return nil, errors.New("key prefix is required")
	}
	if limit <= 0 {
		return nil, errors.New("limit must be positive")
	}
	if window <= 0 {
		return nil, errors.New("window must be positive")
	}
	if log == nil {
		return nil, errors.New("logger is required")
	}

	return &RateLimiter{
		client:    client,
		keyPrefix: prefix,
		limit:     limit,
		window:    window,
		logger:    log,
	}, nil
}

// MustNewRateLimiter creates a rate limiter or panics on error.
// Use only in initialization code where failure is unrecoverable.
func MustNewRateLimiter(client *Client, prefix string, limit int, window time.Duration, log *logger.Logger) *RateLimiter {
	rl, err := NewRateLimiter(client, prefix, limit, window, log)
	if err != nil {
		panic(fmt.Sprintf("failed to create rate limiter: %v", err))
	}
	return rl
}

// buildKey creates the full rate limit key with prefix.
func (rl *RateLimiter) buildKey(key string) string {
	return fmt.Sprintf("%s:%s", rl.keyPrefix, key)
}

// Allow checks if a request is allowed and consumes one token atomically.
// Returns the result with remaining count and reset time.
//
// This method is safe for concurrent use and uses Lua scripting to ensure
// atomic check-and-update operations.
func (rl *RateLimiter) Allow(ctx context.Context, key string) (*RateLimitResult, error) {
	if key == "" {
		return nil, errors.New("key is required")
	}

	start := time.Now()
	fullKey := rl.buildKey(key)
	now := time.Now()
	windowStart := now.Add(-rl.window)

	nowMs := now.UnixMilli()
	windowStartMs := windowStart.UnixMilli()
	windowMs := rl.window.Milliseconds()
	requestID := uuid.New().String()

	result, err := allowScript.Run(ctx, rl.client.client, []string{fullKey},
		nowMs, windowStartMs, windowMs, rl.limit, requestID).Slice()
	if err != nil {
		DefaultMetrics.ObserveOperation("ratelimit_allow", time.Since(start), err)
		return nil, fmt.Errorf("rate limit check: %w", err)
	}

	allowed := result[0].(int64) == 1
	remaining := int(result[1].(int64))
	resetMs := result[2].(int64)
	resetAt := time.UnixMilli(resetMs)

	rateLimitResult := &RateLimitResult{
		Allowed:   allowed,
		Remaining: remaining,
		ResetAt:   resetAt,
	}

	// Record metrics
	DefaultMetrics.RecordRateLimitResult(rl.keyPrefix, allowed)
	DefaultMetrics.ObserveOperation("ratelimit_allow", time.Since(start), nil)

	if !allowed {
		rateLimitResult.RetryAt = resetAt
		rl.logger.Debug("rate limit exceeded",
			"key", key,
			"retry_at", resetAt,
		)
	}

	return rateLimitResult, nil
}

// Status returns the current rate limit status without consuming a token.
// This is useful for displaying rate limit information to clients.
//
// This method uses Lua scripting to ensure atomic reads, preventing
// race conditions between cleanup and count operations.
func (rl *RateLimiter) Status(ctx context.Context, key string) (*RateLimitResult, error) {
	if key == "" {
		return nil, errors.New("key is required")
	}

	fullKey := rl.buildKey(key)
	now := time.Now()
	windowStart := now.Add(-rl.window)

	nowMs := now.UnixMilli()
	windowStartMs := windowStart.UnixMilli()
	windowMs := rl.window.Milliseconds()

	result, err := statusScript.Run(ctx, rl.client.client, []string{fullKey},
		nowMs, windowStartMs, windowMs, rl.limit).Slice()
	if err != nil {
		return nil, fmt.Errorf("rate limit status: %w", err)
	}

	allowed := result[0].(int64) == 1
	remaining := int(result[1].(int64))
	resetMs := result[2].(int64)
	resetAt := time.UnixMilli(resetMs)

	return &RateLimitResult{
		Allowed:   allowed,
		Remaining: remaining,
		ResetAt:   resetAt,
	}, nil
}

// Reset removes the rate limit for a key, allowing immediate access.
// Use with caution as this bypasses rate limiting protections.
func (rl *RateLimiter) Reset(ctx context.Context, key string) error {
	if key == "" {
		return errors.New("key is required")
	}

	fullKey := rl.buildKey(key)

	if err := rl.client.client.Del(ctx, fullKey).Err(); err != nil {
		return fmt.Errorf("rate limit reset: %w", err)
	}

	rl.logger.Debug("rate limit reset", "key", key)
	return nil
}

// AllowN checks if N requests are allowed and consumes them atomically.
// This is useful for operations that consume multiple tokens (e.g., bulk APIs).
func (rl *RateLimiter) AllowN(ctx context.Context, key string, n int) (*RateLimitResult, error) {
	if key == "" {
		return nil, errors.New("key is required")
	}
	if n <= 0 {
		return nil, errors.New("n must be positive")
	}

	fullKey := rl.buildKey(key)
	now := time.Now()
	windowStart := now.Add(-rl.window)

	nowMs := now.UnixMilli()
	windowStartMs := windowStart.UnixMilli()
	windowMs := rl.window.Milliseconds()
	requestPrefix := uuid.New().String()

	result, err := allowNScript.Run(ctx, rl.client.client, []string{fullKey},
		nowMs, windowStartMs, windowMs, rl.limit, n, requestPrefix).Slice()
	if err != nil {
		return nil, fmt.Errorf("rate limit check n: %w", err)
	}

	allowed := result[0].(int64) == 1
	remaining := int(result[1].(int64))
	resetMs := result[2].(int64)
	resetAt := time.UnixMilli(resetMs)

	rateLimitResult := &RateLimitResult{
		Allowed:   allowed,
		Remaining: remaining,
		ResetAt:   resetAt,
	}

	if !allowed {
		rateLimitResult.RetryAt = resetAt
		rl.logger.Debug("rate limit exceeded",
			"key", key,
			"requested", n,
			"retry_at", resetAt,
		)
	}

	return rateLimitResult, nil
}

// Limit returns the configured maximum requests per window.
func (rl *RateLimiter) Limit() int {
	return rl.limit
}

// Window returns the configured time window duration.
func (rl *RateLimiter) Window() time.Duration {
	return rl.window
}

// MiddlewareAdapter wraps RateLimiter to implement the middleware interface.
// This adapter converts the internal RateLimitResult to the middleware's expected type.
type MiddlewareAdapter struct {
	limiter *RateLimiter
}

// MiddlewareRateLimitResult is the result type expected by the middleware.
type MiddlewareRateLimitResult struct {
	Allowed   bool
	Remaining int
	ResetAt   time.Time
	RetryAt   time.Time
}

// NewMiddlewareAdapter creates an adapter for use with the HTTP middleware.
func NewMiddlewareAdapter(rl *RateLimiter) *MiddlewareAdapter {
	return &MiddlewareAdapter{limiter: rl}
}

// Allow checks if a request is allowed and returns the result in middleware format.
func (a *MiddlewareAdapter) Allow(ctx context.Context, key string) (*MiddlewareRateLimitResult, error) {
	result, err := a.limiter.Allow(ctx, key)
	if err != nil {
		return nil, err
	}

	return &MiddlewareRateLimitResult{
		Allowed:   result.Allowed,
		Remaining: result.Remaining,
		ResetAt:   result.ResetAt,
		RetryAt:   result.RetryAt,
	}, nil
}

// Limit returns the configured maximum requests per window.
func (a *MiddlewareAdapter) Limit() int {
	return a.limiter.Limit()
}
