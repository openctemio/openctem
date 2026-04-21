package finding

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// (Bulk-action safety rails).
//
// Problem: bulk operations on findings (bulk-fix-applied, bulk-verify,
// bulk-accept, bulk-close) can, on a large tenant, touch tens of
// thousands of rows. Three failure modes deserve guards:
//
//   1. Accidental mass-flip — a UI misclick or a loosely-scoped
//      filter touches far more rows than the operator intended.
//   2. Runaway automation — an outbound integration webhook fires a
//      bulk endpoint in a loop.
//   3. Audit pollution — a bulk op that resolves 20k rows floods the
//      audit log, obscuring real events.
//
// Two knobs:
//   - A per-request size ceiling (default 500). Requests above the
//     ceiling must carry an `operator_approved=true` flag, which the
//     handler enforces by requiring an OwnerOrAdmin role + recent MFA.
//   - A per-tenant hourly budget (default 10k). Tracks rolling count;
//     rejects once exhausted.
//
// Both knobs are in-memory (per-process) in this first pass. A future
// iteration can move the budget to Redis so it works across replicas.

// BulkGuardConfig tunes the two thresholds. Zero values take the
// documented defaults.
type BulkGuardConfig struct {
	// SizeCeiling is the max number of rows a single bulk request
	// can touch without operator approval. Default 500.
	SizeCeiling int
	// HourlyBudget is the max rows per tenant per hour. Default 10_000.
	HourlyBudget int
	// Now is injectable for deterministic tests.
	Now func() time.Time
}

// BulkGuard is the single service used by all bulk handlers before
// executing. Usage:
//
//	if err := guard.CheckBulk(tenantID, len(findingIDs), operatorApproved); err != nil {
//	    return apierror.BadRequest(err.Error()).WriteJSON(w)
//	}
type BulkGuard struct {
	cfg BulkGuardConfig
	mu  sync.Mutex
	// usage[tenant] = slice of per-op (timestamp, count) records
	// within the last rolling hour. Old records are pruned on read.
	usage map[shared.ID][]bulkEntry
}

type bulkEntry struct {
	at    time.Time
	count int
}

// NewBulkGuard constructs a guard with defaults applied.
func NewBulkGuard(cfg BulkGuardConfig) *BulkGuard {
	if cfg.SizeCeiling <= 0 {
		cfg.SizeCeiling = 500
	}
	if cfg.HourlyBudget <= 0 {
		cfg.HourlyBudget = 10_000
	}
	if cfg.Now == nil {
		cfg.Now = func() time.Time { return time.Now().UTC() }
	}
	return &BulkGuard{
		cfg:   cfg,
		usage: make(map[shared.ID][]bulkEntry),
	}
}

// ErrBulkTooLarge is returned when a single request exceeds the
// per-request ceiling without operator approval.
var ErrBulkTooLarge = errors.New("bulk request exceeds size ceiling; requires operator approval")

// ErrBulkBudgetExceeded is returned when the rolling-hour budget is
// exhausted for the tenant.
var ErrBulkBudgetExceeded = errors.New("bulk operation budget exceeded for this hour")

// ErrBulkNegativeSize defends against callers passing a computed
// size that went negative (overflow bugs, bad filters).
var ErrBulkNegativeSize = errors.New("bulk request size must be positive")

// CheckBulk enforces both guards for a single request. On success,
// records the usage so subsequent calls see it. On rejection,
// usage is NOT recorded (the operation didn't happen).
//
// The operator-approved flag bypasses SizeCeiling but NOT the
// hourly budget — even an approved operator cannot blast the tenant.
func (g *BulkGuard) CheckBulk(ctx context.Context, tenantID shared.ID, size int, operatorApproved bool) error {
	if size <= 0 {
		return ErrBulkNegativeSize
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !operatorApproved && size > g.cfg.SizeCeiling {
		return fmt.Errorf("%w: request touches %d rows, ceiling %d (acquire operator approval)",
			ErrBulkTooLarge, size, g.cfg.SizeCeiling)
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	now := g.cfg.Now()
	pruned := g.pruneLocked(tenantID, now)
	usedThisHour := 0
	for _, e := range pruned {
		usedThisHour += e.count
	}
	if usedThisHour+size > g.cfg.HourlyBudget {
		return fmt.Errorf("%w: would use %d of %d remaining this hour",
			ErrBulkBudgetExceeded, size, g.cfg.HourlyBudget-usedThisHour)
	}
	pruned = append(pruned, bulkEntry{at: now, count: size})
	g.usage[tenantID] = pruned
	return nil
}

// UsageThisHour returns the number of rows consumed in the rolling
// hour window for `tenantID`. Exposed for the maturity dashboard.
func (g *BulkGuard) UsageThisHour(tenantID shared.ID) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	pruned := g.pruneLocked(tenantID, g.cfg.Now())
	total := 0
	for _, e := range pruned {
		total += e.count
	}
	return total
}

// pruneLocked drops entries older than one hour from `at`. Caller
// holds g.mu.
func (g *BulkGuard) pruneLocked(tenantID shared.ID, at time.Time) []bulkEntry {
	cutoff := at.Add(-time.Hour)
	entries := g.usage[tenantID]
	kept := entries[:0]
	for _, e := range entries {
		if e.at.After(cutoff) {
			kept = append(kept, e)
		}
	}
	g.usage[tenantID] = kept
	return kept
}
