package app

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
)

// Q4/WS-C: P0 flood protection (anti-flap).
//
// Problem scenario: a noisy scanner (misconfigured rule, upstream
// catalog error in EPSS/KEV) produces a burst of 10k+ findings that
// ClassifyPriority stamps P0. Every P0 triggers: Jira ticket, outbox
// notification, priority-queue jump, assignment-rule sweep. The
// tenant's inbox melts; operators start treating P0 as noise; a real
// P0 arriving in the middle of the burst is lost.
//
// Solution: per-tenant rolling-window cap on P0 emissions. Once the
// cap is hit, additional P0 classifications are:
//   - still RECORDED (class=P0, reason kept, audit-logged as
//     "throttled" — the classification decision is NOT altered)
//   - but the DOWNSTREAM side effects (notification, ticket creation,
//     priority-queue fast-lane) are SUPPRESSED until the window
//     re-opens
//
// This is the minimum anti-flap without hiding signal. Operators see
// the accurate P0 count on the dashboard; only the operational
// firehose is dampened.

// P0FloodConfig tunes the guard. Zero values take documented
// defaults.
type P0FloodConfig struct {
	// MaxPerHour is the ceiling of "newly-P0" findings per tenant
	// per rolling hour at which we start suppressing downstream
	// side effects. Default 50 — chosen because a single tenant
	// realistically cannot action more than ~50 P0s/hr.
	MaxPerHour int
	// Now is injectable for deterministic tests.
	Now func() time.Time
}

// P0FloodGuard is per-process in-memory. A future iteration moves it
// to Redis for cross-replica dedup; as long as there is ONE background
// worker doing classification (the sweep controller), in-memory is
// sufficient.
type P0FloodGuard struct {
	cfg   P0FloodConfig
	mu    sync.Mutex
	usage map[shared.ID][]time.Time
}

// NewP0FloodGuard constructs the guard with defaults.
func NewP0FloodGuard(cfg P0FloodConfig) *P0FloodGuard {
	if cfg.MaxPerHour <= 0 {
		cfg.MaxPerHour = 50
	}
	if cfg.Now == nil {
		cfg.Now = func() time.Time { return time.Now().UTC() }
	}
	return &P0FloodGuard{cfg: cfg, usage: make(map[shared.ID][]time.Time)}
}

// ErrP0FloodSuppressed is returned by ShouldFanOut when the tenant
// has already consumed its rolling budget. Classification is NOT
// reverted; only downstream side effects are skipped.
var ErrP0FloodSuppressed = errors.New("tenant P0 flood budget exceeded; downstream fan-out suppressed")

// ShouldFanOut reports whether the downstream side effects (Jira,
// outbox, fast-lane queue) should run for a newly-P0 classification.
//
// Returns (true, nil) under budget — record AND fire.
// Returns (false, ErrP0FloodSuppressed) over budget — record only.
//
// A classification that is NOT P0 short-circuits immediately and the
// budget is not charged.
func (g *P0FloodGuard) ShouldFanOut(
	ctx context.Context,
	tenantID shared.ID,
	class vulnerability.PriorityClass,
) (bool, error) {
	if class != "P0" {
		return true, nil
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	now := g.cfg.Now()
	kept := g.pruneLocked(tenantID, now)

	if len(kept) >= g.cfg.MaxPerHour {
		return false, ErrP0FloodSuppressed
	}
	// Record consumption now — the caller will actually fan out.
	// If the caller's fan-out fails, they MUST NOT call ShouldFanOut
	// again for the same finding; use Refund to give the slot back
	// (for downstream-delivery retries).
	kept = append(kept, now)
	g.usage[tenantID] = kept
	return true, nil
}

// Refund returns a slot to the tenant's budget. Used when the
// caller's fan-out fails and will retry — otherwise a delivery
// failure would permanently burn the slot.
func (g *P0FloodGuard) Refund(tenantID shared.ID) {
	g.mu.Lock()
	defer g.mu.Unlock()
	entries := g.usage[tenantID]
	if len(entries) == 0 {
		return
	}
	g.usage[tenantID] = entries[:len(entries)-1]
}

// CurrentUsage exposes the rolling-hour count for dashboards.
func (g *P0FloodGuard) CurrentUsage(tenantID shared.ID) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.pruneLocked(tenantID, g.cfg.Now()))
}

// pruneLocked drops entries older than one hour from `at`.
func (g *P0FloodGuard) pruneLocked(tenantID shared.ID, at time.Time) []time.Time {
	cutoff := at.Add(-time.Hour)
	entries := g.usage[tenantID]
	kept := entries[:0]
	for _, e := range entries {
		if e.After(cutoff) {
			kept = append(kept, e)
		}
	}
	g.usage[tenantID] = kept
	return kept
}
