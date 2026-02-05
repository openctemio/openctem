package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// Cache provides type-safe caching operations.
type Cache[T any] struct {
	client    *Client
	keyPrefix string
	ttl       time.Duration
}

// NewCache creates a new type-safe cache.
// Returns error if any parameter is invalid.
func NewCache[T any](client *Client, prefix string, ttl time.Duration) (*Cache[T], error) {
	if client == nil {
		return nil, errors.New("redis client is required")
	}
	if prefix == "" {
		return nil, errors.New("key prefix is required")
	}
	if ttl <= 0 {
		return nil, errors.New("TTL must be positive")
	}

	return &Cache[T]{
		client:    client,
		keyPrefix: prefix,
		ttl:       ttl,
	}, nil
}

// MustNewCache creates a new cache or panics on error.
// Use only in initialization code where failure is unrecoverable.
func MustNewCache[T any](client *Client, prefix string, ttl time.Duration) *Cache[T] {
	cache, err := NewCache[T](client, prefix, ttl)
	if err != nil {
		panic(fmt.Sprintf("failed to create cache: %v", err))
	}
	return cache
}

// buildKey creates the full cache key with prefix.
func (c *Cache[T]) buildKey(key string) string {
	return fmt.Sprintf("%s:%s", c.keyPrefix, key)
}

// Get retrieves a cached value by key.
// Returns ErrCacheMiss if the key does not exist.
func (c *Cache[T]) Get(ctx context.Context, key string) (*T, error) {
	if key == "" {
		return nil, errors.New("key is required")
	}

	start := time.Now()
	fullKey := c.buildKey(key)

	data, err := c.client.client.Get(ctx, fullKey).Bytes()
	if errors.Is(err, redis.Nil) {
		DefaultMetrics.RecordCacheMiss(c.keyPrefix)
		DefaultMetrics.ObserveOperation("cache_get", time.Since(start), nil)
		return nil, ErrCacheMiss
	}
	if err != nil {
		DefaultMetrics.ObserveOperation("cache_get", time.Since(start), err)
		return nil, fmt.Errorf("cache get: %w", err)
	}

	var value T
	if err := json.Unmarshal(data, &value); err != nil {
		DefaultMetrics.ObserveOperation("cache_get", time.Since(start), err)
		return nil, fmt.Errorf("cache unmarshal: %w", err)
	}

	DefaultMetrics.RecordCacheHit(c.keyPrefix)
	DefaultMetrics.ObserveOperation("cache_get", time.Since(start), nil)
	return &value, nil
}

// Set stores a value in the cache with the default TTL.
func (c *Cache[T]) Set(ctx context.Context, key string, value T) error {
	return c.SetWithTTL(ctx, key, value, c.ttl)
}

// SetWithTTL stores a value in the cache with a custom TTL.
func (c *Cache[T]) SetWithTTL(ctx context.Context, key string, value T, ttl time.Duration) error {
	if key == "" {
		return errors.New("key is required")
	}
	if ttl <= 0 {
		return errors.New("TTL must be positive")
	}

	start := time.Now()
	fullKey := c.buildKey(key)

	data, err := json.Marshal(value)
	if err != nil {
		DefaultMetrics.ObserveOperation("cache_set", time.Since(start), err)
		return fmt.Errorf("cache marshal: %w", err)
	}

	if err := c.client.client.Set(ctx, fullKey, data, ttl).Err(); err != nil {
		DefaultMetrics.ObserveOperation("cache_set", time.Since(start), err)
		return fmt.Errorf("cache set: %w", err)
	}

	DefaultMetrics.ObserveOperation("cache_set", time.Since(start), nil)
	return nil
}

// Delete removes a key from the cache.
func (c *Cache[T]) Delete(ctx context.Context, key string) error {
	if key == "" {
		return errors.New("key is required")
	}

	fullKey := c.buildKey(key)

	if err := c.client.client.Del(ctx, fullKey).Err(); err != nil {
		return fmt.Errorf("cache delete: %w", err)
	}

	return nil
}

// Exists checks if a key exists in the cache.
func (c *Cache[T]) Exists(ctx context.Context, key string) (bool, error) {
	if key == "" {
		return false, errors.New("key is required")
	}

	fullKey := c.buildKey(key)

	n, err := c.client.client.Exists(ctx, fullKey).Result()
	if err != nil {
		return false, fmt.Errorf("cache exists: %w", err)
	}

	return n > 0, nil
}

// MGet retrieves multiple values by keys.
// Returns a map of key to value. Missing keys are not included in the result.
func (c *Cache[T]) MGet(ctx context.Context, keys ...string) (map[string]*T, error) {
	if len(keys) == 0 {
		return make(map[string]*T), nil
	}

	fullKeys := make([]string, len(keys))
	for i, key := range keys {
		if key == "" {
			return nil, fmt.Errorf("key at index %d is empty", i)
		}
		fullKeys[i] = c.buildKey(key)
	}

	values, err := c.client.client.MGet(ctx, fullKeys...).Result()
	if err != nil {
		return nil, fmt.Errorf("cache mget: %w", err)
	}

	result := make(map[string]*T)
	for i, v := range values {
		if v == nil {
			continue
		}

		data, ok := v.(string)
		if !ok {
			continue
		}

		var value T
		if err := json.Unmarshal([]byte(data), &value); err != nil {
			c.client.logger.Warn("cache mget unmarshal failed",
				"key", keys[i],
				"error", err,
			)
			continue
		}

		result[keys[i]] = &value
	}

	return result, nil
}

// MSet stores multiple values in the cache.
func (c *Cache[T]) MSet(ctx context.Context, items map[string]T) error {
	if len(items) == 0 {
		return nil
	}

	pipe := c.client.client.Pipeline()

	for key, value := range items {
		if key == "" {
			return errors.New("empty key in items map")
		}
		fullKey := c.buildKey(key)
		data, err := json.Marshal(value)
		if err != nil {
			return fmt.Errorf("cache marshal key %s: %w", key, err)
		}
		pipe.Set(ctx, fullKey, data, c.ttl)
	}

	_, err := pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("cache mset: %w", err)
	}

	return nil
}

// DeletePattern removes all keys matching a pattern.
// Pattern example: "*" removes all keys with the cache prefix.
func (c *Cache[T]) DeletePattern(ctx context.Context, pattern string) error {
	if pattern == "" {
		return errors.New("pattern is required")
	}

	fullPattern := c.buildKey(pattern)

	// Use SCAN to find keys (production-safe)
	var cursor uint64
	var totalDeleted int64
	for {
		keys, nextCursor, err := c.client.client.Scan(ctx, cursor, fullPattern, 100).Result()
		if err != nil {
			return fmt.Errorf("cache scan: %w", err)
		}

		if len(keys) > 0 {
			deleted, err := c.client.client.Del(ctx, keys...).Result()
			if err != nil {
				return fmt.Errorf("cache delete pattern: %w", err)
			}
			totalDeleted += deleted
		}

		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	c.client.logger.Debug("cache delete pattern completed",
		"pattern", fullPattern,
		"deleted", totalDeleted,
	)

	return nil
}

// GetOrSet retrieves a value from cache, or calls the loader function and caches the result.
// On cache miss, loads from source and caches the result.
// On Redis errors (connection, timeout), fails fast to prevent cascading failures.
// Cache set errors are logged but do not fail the operation.
func (c *Cache[T]) GetOrSet(ctx context.Context, key string, loader func(ctx context.Context) (*T, error)) (*T, error) {
	return c.GetOrSetWithTTL(ctx, key, c.ttl, loader)
}

// GetOrSetWithTTL is like GetOrSet but with a custom TTL.
// On cache miss, loads from source and caches the result.
// On Redis errors (connection, timeout), fails fast to prevent cascading failures.
// Cache set errors are logged but do not fail the operation.
func (c *Cache[T]) GetOrSetWithTTL(ctx context.Context, key string, ttl time.Duration, loader func(ctx context.Context) (*T, error)) (*T, error) {
	if key == "" {
		return nil, errors.New("key is required")
	}
	if loader == nil {
		return nil, errors.New("loader function is required")
	}
	if ttl <= 0 {
		return nil, errors.New("TTL must be positive")
	}

	// Try to get from cache first
	value, err := c.Get(ctx, key)
	if err == nil {
		return value, nil
	}

	// On cache miss, load from source
	if errors.Is(err, ErrCacheMiss) {
		return c.loadAndCache(ctx, key, ttl, loader)
	}

	// On Redis errors, fail fast to prevent cascading failures
	// This prevents all requests hitting the database when Redis is down
	return nil, fmt.Errorf("cache unavailable: %w", err)
}

// GetOrSetFallback is like GetOrSet but falls back to loader on any cache error.
// Use this when availability is more important than protecting the database.
// WARNING: If Redis is down, ALL requests will hit your database.
func (c *Cache[T]) GetOrSetFallback(ctx context.Context, key string, loader func(ctx context.Context) (*T, error)) (*T, error) {
	return c.GetOrSetFallbackWithTTL(ctx, key, c.ttl, loader)
}

// GetOrSetFallbackWithTTL is like GetOrSetFallback but with a custom TTL.
func (c *Cache[T]) GetOrSetFallbackWithTTL(ctx context.Context, key string, ttl time.Duration, loader func(ctx context.Context) (*T, error)) (*T, error) {
	if key == "" {
		return nil, errors.New("key is required")
	}
	if loader == nil {
		return nil, errors.New("loader function is required")
	}
	if ttl <= 0 {
		return nil, errors.New("TTL must be positive")
	}

	// Try to get from cache first
	value, err := c.Get(ctx, key)
	if err == nil {
		return value, nil
	}

	// On any error (miss or Redis error), load from source
	if !errors.Is(err, ErrCacheMiss) {
		c.client.logger.Warn("cache get failed, falling back to source",
			"key", key,
			"error", err,
		)
	}

	return c.loadAndCache(ctx, key, ttl, loader)
}

// loadAndCache loads value from loader and caches it.
func (c *Cache[T]) loadAndCache(ctx context.Context, key string, ttl time.Duration, loader func(ctx context.Context) (*T, error)) (*T, error) {
	value, err := loader(ctx)
	if err != nil {
		return nil, err
	}

	// Cache the value - log errors but don't fail
	if err := c.SetWithTTL(ctx, key, *value, ttl); err != nil {
		c.client.logger.Warn("cache set failed after load",
			"key", key,
			"error", err,
		)
	}

	return value, nil
}

// Invalidate removes a key from the cache (alias for Delete).
func (c *Cache[T]) Invalidate(ctx context.Context, key string) error {
	return c.Delete(ctx, key)
}

// Refresh updates the TTL of a cached key without changing its value.
func (c *Cache[T]) Refresh(ctx context.Context, key string) error {
	if key == "" {
		return errors.New("key is required")
	}

	fullKey := c.buildKey(key)

	if err := c.client.client.Expire(ctx, fullKey, c.ttl).Err(); err != nil {
		return fmt.Errorf("cache refresh: %w", err)
	}

	return nil
}

// TTL returns the default TTL for this cache.
func (c *Cache[T]) TTL() time.Duration {
	return c.ttl
}

// Prefix returns the key prefix for this cache.
func (c *Cache[T]) Prefix() string {
	return c.keyPrefix
}
