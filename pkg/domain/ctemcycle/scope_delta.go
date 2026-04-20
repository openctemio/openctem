package ctemcycle

import (
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// B7 (Q4/WS-E): mid-cycle scope delta.
//
// Activate() freezes the asset snapshot. During an active cycle,
// assets get added (new cloud instances, new services onboarded)
// or removed (decommissioned). Today those changes are invisible
// until StartReview(). B7 makes them a first-class event: the
// assets-writing service emits a ScopeChangeEvent, the cycle
// handler records it into ctem_cycle_scope_changes, and the risk
// snapshot controller recomputes the cycle's "true" open-exposure
// count.

// ScopeChangeKind enumerates what happened.
type ScopeChangeKind string

const (
	ScopeChangeAdded   ScopeChangeKind = "added"
	ScopeChangeRemoved ScopeChangeKind = "removed"
)

// ScopeChangeEvent is the in-memory domain shape. Emitted by the
// assets service + consumed by the cycle handler.
type ScopeChangeEvent struct {
	CycleID  shared.ID
	TenantID shared.ID
	AssetID  shared.ID
	Kind     ScopeChangeKind
	At       time.Time
	// Reason is a short string for audit / UI ("asset created",
	// "asset decommissioned", "business service membership
	// changed").
	Reason string
}

// Validate ensures required fields are set.
func (e ScopeChangeEvent) Validate() error {
	if e.CycleID.IsZero() {
		return fmt.Errorf("%w: cycle_id required", shared.ErrValidation)
	}
	if e.TenantID.IsZero() {
		return fmt.Errorf("%w: tenant_id required", shared.ErrValidation)
	}
	if e.AssetID.IsZero() {
		return fmt.Errorf("%w: asset_id required", shared.ErrValidation)
	}
	if e.Kind != ScopeChangeAdded && e.Kind != ScopeChangeRemoved {
		return fmt.Errorf("%w: kind must be added|removed", shared.ErrValidation)
	}
	return nil
}

// ScopeDeltaRollup aggregates a batch of ScopeChangeEvents for
// display. The cycle-review endpoint returns this so the UI shows
// "during this cycle so far: +12 assets, -3 assets".
type ScopeDeltaRollup struct {
	CycleID        shared.ID
	AddedAssets    []shared.ID
	RemovedAssets  []shared.ID
	AddedByReason  map[string]int
	RemovedByReason map[string]int
	ComputedAt     time.Time
}

// RollupChanges folds a sequence of ScopeChangeEvents into a
// ScopeDeltaRollup. Malformed events (validation fails) are
// skipped, not fatal — the rollup is best-effort aggregation for
// the UI.
func RollupChanges(cycleID shared.ID, events []ScopeChangeEvent) ScopeDeltaRollup {
	out := ScopeDeltaRollup{
		CycleID:         cycleID,
		AddedByReason:   make(map[string]int),
		RemovedByReason: make(map[string]int),
		ComputedAt:      time.Now().UTC(),
	}
	for _, e := range events {
		if err := e.Validate(); err != nil {
			continue
		}
		if e.CycleID != cycleID {
			continue
		}
		switch e.Kind {
		case ScopeChangeAdded:
			out.AddedAssets = append(out.AddedAssets, e.AssetID)
			if e.Reason != "" {
				out.AddedByReason[e.Reason]++
			}
		case ScopeChangeRemoved:
			out.RemovedAssets = append(out.RemovedAssets, e.AssetID)
			if e.Reason != "" {
				out.RemovedByReason[e.Reason]++
			}
		}
	}
	return out
}

// IsEmpty returns true when no added/removed events contributed.
func (r ScopeDeltaRollup) IsEmpty() bool {
	return len(r.AddedAssets) == 0 && len(r.RemovedAssets) == 0
}

// Size returns the absolute drift magnitude.
func (r ScopeDeltaRollup) Size() int {
	return len(r.AddedAssets) + len(r.RemovedAssets)
}
