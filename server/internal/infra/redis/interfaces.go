package redis

import (
	"context"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

// Pinger is an interface for health check operations.
type Pinger interface {
	Ping(ctx context.Context) error
}

// Closer is an interface for graceful shutdown.
type Closer interface {
	Close() error
}

// CacheStore defines the interface for cache operations.
// Use this interface in application code for better testability.
type CacheStore[T any] interface {
	// Get retrieves a cached value by key.
	// Returns ErrCacheMiss if the key does not exist.
	Get(ctx context.Context, key string) (*T, error)

	// Set stores a value in the cache with the default TTL.
	Set(ctx context.Context, key string, value T) error

	// SetWithTTL stores a value in the cache with a custom TTL.
	SetWithTTL(ctx context.Context, key string, value T, ttl time.Duration) error

	// Delete removes a key from the cache.
	Delete(ctx context.Context, key string) error

	// Exists checks if a key exists in the cache.
	Exists(ctx context.Context, key string) (bool, error)

	// GetOrSet retrieves from cache or calls loader and caches the result.
	GetOrSet(ctx context.Context, key string, loader func(ctx context.Context) (*T, error)) (*T, error)
}

// TokenStorer defines the interface for token/session operations.
// Use this interface in application code for better testability.
type TokenStorer interface {
	// JWT Blacklist
	BlacklistToken(ctx context.Context, jti string, expiry time.Duration) error
	IsBlacklisted(ctx context.Context, jti string) (bool, error)

	// Session Management
	StoreSession(ctx context.Context, userID, sessionID string, data map[string]string, ttl time.Duration) error
	GetSession(ctx context.Context, userID, sessionID string) (map[string]string, error)
	DeleteSession(ctx context.Context, userID, sessionID string) error
	DeleteAllUserSessions(ctx context.Context, userID string) error
	GetUserSessions(ctx context.Context, userID string) ([]string, error)
	RefreshSession(ctx context.Context, userID, sessionID string, ttl time.Duration) error
	CountActiveSessions(ctx context.Context, userID string) (int64, error)

	// Refresh Tokens
	StoreRefreshToken(ctx context.Context, userID, tokenHash string, ttl time.Duration) error
	ValidateRefreshToken(ctx context.Context, userID, tokenHash string) (bool, error)
	RevokeRefreshToken(ctx context.Context, userID, tokenHash string) error
	RevokeAllRefreshTokens(ctx context.Context, userID string) error
	RotateRefreshToken(ctx context.Context, userID, oldTokenHash, newTokenHash string, ttl time.Duration) error
}

// RateLimiterStore defines the interface for rate limiting operations.
// Use this interface in application code for better testability.
type RateLimiterStore interface {
	// Allow checks if a request is allowed and consumes one token.
	Allow(ctx context.Context, key string) (*RateLimitResult, error)

	// AllowN checks if N requests are allowed and consumes them.
	AllowN(ctx context.Context, key string, n int) (*RateLimitResult, error)

	// Status returns the current rate limit status without consuming a token.
	Status(ctx context.Context, key string) (*RateLimitResult, error)

	// Reset removes the rate limit for a key.
	Reset(ctx context.Context, key string) error

	// Limit returns the configured limit.
	Limit() int

	// Window returns the configured window duration.
	Window() time.Duration
}

// Ensure implementations satisfy interfaces.
var (
	_ Pinger           = (*Client)(nil)
	_ Closer           = (*Client)(nil)
	_ TokenStorer      = (*TokenStore)(nil)
	_ RateLimiterStore = (*RateLimiter)(nil)
)

// RedisClient is an interface that wraps the essential redis.Client methods.
// This allows for easier testing with mock implementations.
type RedisClient interface {
	Ping(ctx context.Context) *goredis.StatusCmd
	Get(ctx context.Context, key string) *goredis.StringCmd
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *goredis.StatusCmd
	Del(ctx context.Context, keys ...string) *goredis.IntCmd
	Exists(ctx context.Context, keys ...string) *goredis.IntCmd
	Expire(ctx context.Context, key string, expiration time.Duration) *goredis.BoolCmd
	TTL(ctx context.Context, key string) *goredis.DurationCmd
	Close() error
}
