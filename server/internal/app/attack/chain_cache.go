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
	// scoreCacheTTL is the same for attack-path scores.
	scoreCacheTTL = 5 * time.Minute
	// graphComputeTimeout bounds one computation, so a huge graph cannot hold
	// a request (and the callers waiting on it) indefinitely.
	graphComputeTimeout = 30 * time.Second
)

// tenantCache holds a tenant-wide, unscoped graph result per tenant for a short
// time (exposure chains, attack-path scores). The key is the tenant id only:
// every member-facing read narrows its copy to the caller's data scope
// afterwards.
type tenantCache[T any] struct {
	ttl   time.Duration
	now   func() time.Time
	clone func(*T) *T

	mu      sync.Mutex
	entries map[string]cacheEntry[T]
	group   singleflight.Group
}

type cacheEntry[T any] struct {
	res *T
	exp time.Time
}

func newTenantCache[T any](ttl time.Duration, clone func(*T) *T) *tenantCache[T] {
	return &tenantCache[T]{ttl: ttl, now: time.Now, clone: clone, entries: make(map[string]cacheEntry[T])}
}

// get returns a copy of the tenant's cached result, computing it with compute
// on a miss. Concurrent misses for one tenant share one computation, which runs
// detached from the first caller's cancellation (a canceled request must not
// fail the others) under graphComputeTimeout.
func (c *tenantCache[T]) get(ctx context.Context, tenantID shared.ID, compute func(context.Context) (*T, error)) (*T, error) {
	key := tenantID.String()
	if res, ok := c.lookup(key); ok {
		return res, nil
	}
	v, err, _ := c.group.Do(key, func() (any, error) {
		if res, ok := c.lookup(key); ok {
			return res, nil
		}
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), graphComputeTimeout)
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
	return c.clone(v.(*T)), nil
}

func (c *tenantCache[T]) lookup(key string) (*T, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok || !c.now().Before(e.exp) {
		return nil, false
	}
	return c.clone(e.res), true
}

func (c *tenantCache[T]) store(key string, res *T) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	for k, e := range c.entries {
		if !now.Before(e.exp) {
			delete(c.entries, k)
		}
	}
	c.entries[key] = cacheEntry[T]{res: res, exp: now.Add(c.ttl)}
}

// cloneChainResult copies the summary and the chain list so a reader can
// reslice, filter or cap its copy without touching the cached one. Hops are
// shared and read-only.
func cloneChainResult(r *ExposureChainResult) *ExposureChainResult {
	out := &ExposureChainResult{Summary: r.Summary, Chains: make([]ExposureChain, len(r.Chains))}
	copy(out.Chains, r.Chains)
	return out
}

// cloneScoreResult copies what a reader may modify: the summary, the ranked
// list and the basis pointer. The basis itself is read-only and shared.
func cloneScoreResult(r *PathScoringResult) *PathScoringResult {
	out := *r
	out.TopAssets = make([]AssetPathScore, len(r.TopAssets))
	copy(out.TopAssets, r.TopAssets)
	return &out
}
