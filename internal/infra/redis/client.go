package redis

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/openctemio/api/internal/config"
	"github.com/openctemio/api/pkg/logger"
)

// Client wraps redis.Client with additional functionality.
type Client struct {
	client *redis.Client
	logger *logger.Logger
	cfg    *config.RedisConfig
}

// New creates a new Redis client.
func New(cfg *config.RedisConfig, log *logger.Logger) (*Client, error) {
	if cfg == nil {
		return nil, errors.New("redis config is required")
	}
	if log == nil {
		return nil, errors.New("logger is required")
	}

	opts := &redis.Options{
		Addr:            cfg.Addr(),
		Password:        cfg.Password,
		DB:              cfg.DB,
		PoolSize:        cfg.PoolSize,
		MinIdleConns:    cfg.MinIdleConns,
		DialTimeout:     cfg.DialTimeout,
		ReadTimeout:     cfg.ReadTimeout,
		WriteTimeout:    cfg.WriteTimeout,
		MaxRetries:      cfg.MaxRetries,
		MinRetryBackoff: cfg.MinRetryDelay,
		MaxRetryBackoff: cfg.MaxRetryDelay,
	}

	// Configure TLS if enabled
	if cfg.TLSEnabled {
		opts.TLSConfig = &tls.Config{
			InsecureSkipVerify: cfg.TLSSkipVerify,
			MinVersion:         tls.VersionTLS12,
		}
		log.Info("redis TLS enabled", "skip_verify", cfg.TLSSkipVerify)
	}

	client := redis.NewClient(opts)

	// Verify connection with retry
	var lastErr error
	for attempt := 0; attempt <= cfg.MaxRetries; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), cfg.DialTimeout)
		err := client.Ping(ctx).Err()
		cancel()

		if err == nil {
			log.Info("redis connected",
				"addr", cfg.Addr(),
				"pool_size", cfg.PoolSize,
				"tls", cfg.TLSEnabled,
			)
			return &Client{
				client: client,
				logger: log,
				cfg:    cfg,
			}, nil
		}

		lastErr = err
		if attempt < cfg.MaxRetries {
			backoff := cfg.MinRetryDelay * time.Duration(1<<attempt)
			if backoff > cfg.MaxRetryDelay {
				backoff = cfg.MaxRetryDelay
			}
			log.Warn("redis connection failed, retrying",
				"attempt", attempt+1,
				"max_retries", cfg.MaxRetries,
				"backoff", backoff,
				"error", err,
			)
			time.Sleep(backoff)
		}
	}

	return nil, fmt.Errorf("failed to connect to redis after %d attempts: %w", cfg.MaxRetries+1, lastErr)
}

// Close closes the Redis connection.
func (c *Client) Close() error {
	c.logger.Info("closing redis connection")
	return c.client.Close()
}

// Ping checks if Redis is available.
func (c *Client) Ping(ctx context.Context) error {
	return c.client.Ping(ctx).Err()
}

// Client returns the underlying redis.Client for advanced operations.
func (c *Client) Client() *redis.Client {
	return c.client
}

// Get retrieves a string value by key.
func (c *Client) Get(ctx context.Context, key string) (string, error) {
	if key == "" {
		return "", errors.New("key is required")
	}

	val, err := c.client.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return "", ErrKeyNotFound
	}
	if err != nil {
		return "", fmt.Errorf("redis get: %w", err)
	}
	return val, nil
}

// Set stores a string value with optional TTL.
func (c *Client) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	if key == "" {
		return errors.New("key is required")
	}

	if err := c.client.Set(ctx, key, value, ttl).Err(); err != nil {
		return fmt.Errorf("redis set: %w", err)
	}
	return nil
}

// Del deletes one or more keys.
func (c *Client) Del(ctx context.Context, keys ...string) error {
	if len(keys) == 0 {
		return nil
	}

	if err := c.client.Del(ctx, keys...).Err(); err != nil {
		return fmt.Errorf("redis del: %w", err)
	}
	return nil
}

// Exists checks if a key exists.
func (c *Client) Exists(ctx context.Context, key string) (bool, error) {
	if key == "" {
		return false, errors.New("key is required")
	}

	n, err := c.client.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("redis exists: %w", err)
	}
	return n > 0, nil
}

// Expire sets a TTL on a key.
func (c *Client) Expire(ctx context.Context, key string, ttl time.Duration) error {
	if key == "" {
		return errors.New("key is required")
	}

	if err := c.client.Expire(ctx, key, ttl).Err(); err != nil {
		return fmt.Errorf("redis expire: %w", err)
	}
	return nil
}

// TTL returns the remaining TTL of a key.
func (c *Client) TTL(ctx context.Context, key string) (time.Duration, error) {
	if key == "" {
		return 0, errors.New("key is required")
	}

	ttl, err := c.client.TTL(ctx, key).Result()
	if err != nil {
		return 0, fmt.Errorf("redis ttl: %w", err)
	}
	return ttl, nil
}

// Keys returns all keys matching a pattern.
// Warning: Use with caution in production as it can be slow.
func (c *Client) Keys(ctx context.Context, pattern string) ([]string, error) {
	if pattern == "" {
		return nil, errors.New("pattern is required")
	}

	keys, err := c.client.Keys(ctx, pattern).Result()
	if err != nil {
		return nil, fmt.Errorf("redis keys: %w", err)
	}
	return keys, nil
}

// Scan iterates through keys matching a pattern.
// This is more production-safe than Keys().
func (c *Client) Scan(ctx context.Context, pattern string, count int64) ([]string, error) {
	if pattern == "" {
		return nil, errors.New("pattern is required")
	}
	if count <= 0 {
		count = 100
	}

	var allKeys []string
	var cursor uint64

	for {
		keys, nextCursor, err := c.client.Scan(ctx, cursor, pattern, count).Result()
		if err != nil {
			return nil, fmt.Errorf("redis scan: %w", err)
		}
		allKeys = append(allKeys, keys...)
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	return allKeys, nil
}

// PoolStats returns connection pool statistics.
func (c *Client) PoolStats() *redis.PoolStats {
	return c.client.PoolStats()
}

// Logger returns the client's logger for use by other redis components.
func (c *Client) Logger() *logger.Logger {
	return c.logger
}
