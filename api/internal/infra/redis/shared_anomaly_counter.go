package redis

import (
	"context"
	"time"
)

// SharedAnomalyCounter keeps the per-organization daily counters of shared
// sensor use (docs/rfcs/RFC-100-shared-sensors.md §9) across API replicas.
// Distinct counts are HyperLogLog estimates, so no member (target) is ever
// stored; every key carries the organization and the day and expires.
type SharedAnomalyCounter struct {
	client *Client
}

// NewSharedAnomalyCounter returns the counter store on client.
func NewSharedAnomalyCounter(client *Client) *SharedAnomalyCounter {
	return &SharedAnomalyCounter{client: client}
}

// AddDistinct adds members to the estimate under key and returns it.
func (c *SharedAnomalyCounter) AddDistinct(ctx context.Context, key string, members []string, ttl time.Duration) (int64, error) {
	args := make([]any, len(members))
	for i, m := range members {
		args[i] = m
	}
	pipe := c.client.Client().TxPipeline()
	pipe.PFAdd(ctx, key, args...)
	count := pipe.PFCount(ctx, key)
	pipe.Expire(ctx, key, ttl)
	if _, err := pipe.Exec(ctx); err != nil {
		return 0, err
	}
	return count.Val(), nil
}

// Incr adds n to the count under key and returns it.
func (c *SharedAnomalyCounter) Incr(ctx context.Context, key string, n int64, ttl time.Duration) (int64, error) {
	pipe := c.client.Client().TxPipeline()
	v := pipe.IncrBy(ctx, key, n)
	pipe.Expire(ctx, key, ttl)
	if _, err := pipe.Exec(ctx); err != nil {
		return 0, err
	}
	return v.Val(), nil
}

// Once reports true the first time it is called for key (SET NX).
func (c *SharedAnomalyCounter) Once(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	return c.client.SetNX(ctx, key, "1", ttl)
}
