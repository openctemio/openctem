package main

import (
	"context"
	"sync"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// defaultThreatScoreThreshold is the minimum threat_model_threats.score for a
// threat to count as "high-score" and feed prioritization. A threat's score is
// chain.Score × technique-weight (see internal/app/threatmodel): chain.Score is
// KEVCount×10 + CriticalCount×3, scaled by target criticality / crown-jewel and
// divided by (path length + 1); technique-weight is (0.1,1]. A single directly-
// exposed critical finding therefore lands around 3, so a threshold of 1.0
// admits any genuine open threat while dropping near-zero, deeply-buried, or
// low-weight noise. Tunable; conservative by design (an OPEN threat already
// means a live matching finding exists on the hop).
const defaultThreatScoreThreshold = 1.0

// threatPathReader is the narrow read port the oracle needs: the set of asset
// IDs on open, high-score modeled threat paths for a tenant. Implemented by
// *postgres.ThreatModelRepository.
type threatPathReader interface {
	AssetsOnOpenThreatPaths(ctx context.Context, tenantID shared.ID, minScore float64) (map[string]bool, error)
}

// threatModelOracle bridges the threat-model engine's output to the priority
// classifier (close-the-loop): it returns the set of asset IDs sitting on an
// OPEN, high-score modeled attack chain (entry points, hops, targets). Feeding
// this into classification makes an asset the threat-model engine placed on a
// live, unmitigated chain count as "reachable", so the engine actually drives
// prioritization instead of being a dead-end parallel signal.
//
// Mirrors reachabilityOracle: the whole-set computation is cached per tenant
// with a short TTL, since the threat model changes slowly (regenerated per CTEM
// cycle) and classification runs per-finding.
type threatModelOracle struct {
	reader   threatPathReader
	minScore float64
	ttl      time.Duration
	mu       sync.Mutex
	cache    map[string]threatEntry
}

type threatEntry struct {
	set map[string]bool
	exp time.Time
}

func newThreatModelOracle(reader threatPathReader, minScore float64, ttl time.Duration) *threatModelOracle {
	return &threatModelOracle{reader: reader, minScore: minScore, ttl: ttl, cache: make(map[string]threatEntry)}
}

// OnOpenThreatPath returns the tenant's open-threat-path asset set, cached for
// ttl. On a cache miss it recomputes from the threat-model store.
func (o *threatModelOracle) OnOpenThreatPath(ctx context.Context, tenantID shared.ID) (map[string]bool, error) {
	key := tenantID.String()
	now := time.Now()

	o.mu.Lock()
	if e, ok := o.cache[key]; ok && now.Before(e.exp) {
		set := e.set
		o.mu.Unlock()
		return set, nil
	}
	o.mu.Unlock()

	set, err := o.reader.AssetsOnOpenThreatPaths(ctx, tenantID, o.minScore)
	if err != nil {
		return nil, err
	}

	o.mu.Lock()
	o.cache[key] = threatEntry{set: set, exp: now.Add(o.ttl)}
	o.mu.Unlock()
	return set, nil
}
