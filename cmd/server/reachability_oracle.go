package main

import (
	"context"
	"sync"
	"time"

	"github.com/openctemio/api/internal/app/attack"
	"github.com/openctemio/api/pkg/domain/shared"
)

// reachabilityOracle bridges the attack-surface exposure-chain graph to the
// priority classifier (close-the-loop): it returns the set of asset IDs sitting
// on a validated internet→KEV/crown-jewel attack path — the entry points, hops,
// and targets of the exposure chains. Feeding this into classification makes an
// internal asset on such a path count as "reachable", so the exposure-chain
// engine actually drives prioritization instead of being display-only.
//
// The whole-graph computation is cached per tenant with a short TTL, since the
// attack surface changes slowly and classification runs per-finding.
type reachabilityOracle struct {
	surface *attack.SurfaceService
	ttl     time.Duration
	mu      sync.Mutex
	cache   map[string]reachEntry
}

type reachEntry struct {
	set map[string]bool
	exp time.Time
}

func newReachabilityOracle(surface *attack.SurfaceService, ttl time.Duration) *reachabilityOracle {
	return &reachabilityOracle{surface: surface, ttl: ttl, cache: make(map[string]reachEntry)}
}

// ReachableFromPublic returns the tenant's attack-path-reachable asset set,
// cached for ttl. On a cache miss it recomputes from the exposure-chain graph.
func (o *reachabilityOracle) ReachableFromPublic(ctx context.Context, tenantID shared.ID) (map[string]bool, error) {
	key := tenantID.String()
	now := time.Now()

	o.mu.Lock()
	if e, ok := o.cache[key]; ok && now.Before(e.exp) {
		set := e.set
		o.mu.Unlock()
		return set, nil
	}
	o.mu.Unlock()

	res, err := o.surface.GetExposureChains(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	set := make(map[string]bool)
	for i := range res.Chains {
		c := &res.Chains[i]
		if c.EntryPointID != "" {
			set[c.EntryPointID] = true
		}
		if c.TargetID != "" {
			set[c.TargetID] = true
		}
		for _, h := range c.Hops {
			if h.AssetID != "" {
				set[h.AssetID] = true
			}
		}
	}

	o.mu.Lock()
	o.cache[key] = reachEntry{set: set, exp: now.Add(o.ttl)}
	o.mu.Unlock()
	return set, nil
}
