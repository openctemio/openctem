package redis

import "errors"

// Redis-specific errors.
var (
	// ErrKeyNotFound is returned when a key does not exist.
	ErrKeyNotFound = errors.New("redis: key not found")

	// ErrCacheMiss is returned when a cached item is not found.
	ErrCacheMiss = errors.New("cache: key not found")
)
