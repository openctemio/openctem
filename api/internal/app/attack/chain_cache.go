package attack

import (
	"context"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

const (
	// chainCacheTTL is how long a tenant's exposure chains are reused. The
	// attack surface changes slowly and every reader (page, MCP, priority
	// oracle, threat models) accepts a result a few minutes old.
	chainCacheTTL = 5 * time.Minute
	// chainComputeTimeout bounds one computation, so a huge graph cannot hold
	// a request (and the callers waiting on it) indefinitely.
	chainComputeTimeout = 30 * time.Second
)

// chainCache holds the full exposure-chain result per tenant for a short time.
// The key is the tenant id only: the result is tenant-wide and unscoped, and
// every member-facing read narrows it to the caller's data scope afterwards.
type chainCache struct {
	ttl time.Duration
	now func() time.Time

	mu      sync.Mutex
	entries map[string]chainCacheEntry
	group   singleflight.Group
}

type chainCacheEntry struct {
	res *ExposureChainResult
	exp time.Time
}

func newChainCache(ttl time.Duration) *chainCache {
	return &chainCache{ttl: ttl, now: time.Now, entries: make(map[string]chainCacheEntry)}
}

// get returns a copy of the tenant's cached result, computing it with compute
// on a miss. Concurrent misses for one tenant share one computation, which runs
// detached from the first caller's cancellation (a canceled request must not
// fail the others) under chainComputeTimeout.
func (c *chainCache) get(ctx context.Context, tenantID shared.ID, compute func(context.Context) (*ExposureChainResult, error)) (*ExposureChainResult, error) {
	key := tenantID.String()
	if res, ok := c.lookup(key); ok {
		return res, nil
	}
	v, err, _ := c.group.Do(key, func() (any, error) {
		if res, ok := c.lookup(key); ok {
			return res, nil
		}
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), chainComputeTimeout)
		defer cancel()
		res, err := compute(cctx)
		if err != nil {
			return nil, err
		}
		c.store(key, res)
		return res, nil
	})
	if err != nil {
		return nil, err
	}
	return cloneChainResult(v.(*ExposureChainResult)), nil
}

func (c *chainCache) lookup(key string) (*ExposureChainResult, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok || !c.now().Before(e.exp) {
		return nil, false
	}
	return cloneChainResult(e.res), true
}

func (c *chainCache) store(key string, res *ExposureChainResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	for k, e := range c.entries {
		if !now.Before(e.exp) {
			delete(c.entries, k)
		}
	}
	c.entries[key] = chainCacheEntry{res: res, exp: now.Add(c.ttl)}
}

// cloneChainResult copies the summary and the chain list so a reader can
// reslice, filter or cap its copy without touching the cached one. Hops are
// shared and read-only.
func cloneChainResult(r *ExposureChainResult) *ExposureChainResult {
	out := &ExposureChainResult{Summary: r.Summary, Chains: make([]ExposureChain, len(r.Chains))}
	copy(out.Chains, r.Chains)
	return out
}
