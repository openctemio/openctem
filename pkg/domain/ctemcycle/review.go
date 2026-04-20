package ctemcycle

import (
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// B5 (Q1/WS-E): the cycle "review" phase does actual work, not just a
// status flip.
//
// Three concerns come together when a cycle transitions active → review:
//   1. SCOPE DELTA — which assets that were in-scope at Activate() are
//      no longer present (retired, moved to a different service), and
//      which new assets now match the scope targets but weren't frozen
//      into the snapshot.
//   2. OPEN-FINDING VERIFICATION — every finding on snapshot assets
//      that is still in_progress or fix_applied deserves a re-scan so
//      the cycle's closing metrics reflect the current truth.
//   3. METRICS FINALISATION — MTTR, P-class churn, resolution rate
//      are computed and persisted to ctem_cycle_metrics.
//
// This file defines the domain-level types for those concerns. The
// SQL that actually computes each lives in the handler / repo layer,
// but the contract is here so a reviewer can check the shape at a
// glance.

// ScopeDelta describes the difference between a cycle's frozen
// scope snapshot and the current tenant asset set.
type ScopeDelta struct {
	// AddedAssetIDs are assets that NOW match the cycle's scope
	// targets but were not in the frozen snapshot (created or
	// retagged during the active phase).
	AddedAssetIDs []shared.ID
	// RemovedAssetIDs are assets that were in the frozen snapshot
	// but no longer exist or no longer match the scope (deleted,
	// decommissioned, untagged).
	RemovedAssetIDs []shared.ID
	// UnchangedCount is the number of assets in both sets. Kept as
	// a count (not a list) because it is typically the vast majority
	// and we do not need the IDs.
	UnchangedCount int
	// ComputedAt is the wall-clock time the delta was produced.
	// Exposed to the UI so reviewers know the freshness.
	ComputedAt time.Time
}

// IsEmpty returns true when the snapshot matches the current scope
// exactly — no assets added, none removed.
func (d ScopeDelta) IsEmpty() bool {
	return len(d.AddedAssetIDs) == 0 && len(d.RemovedAssetIDs) == 0
}

// Size returns the total magnitude of the delta (added + removed).
// Used by the UI to show a single "scope drift" badge without
// exposing the full lists.
func (d ScopeDelta) Size() int {
	return len(d.AddedAssetIDs) + len(d.RemovedAssetIDs)
}

// ReviewSnapshot bundles everything the handler computes on
// transition into review. Persisting this record gives the reviewer
// a deterministic view of the cycle outcome.
type ReviewSnapshot struct {
	CycleID             shared.ID
	TenantID            shared.ID
	Delta               ScopeDelta
	FindingsToRevalidate []shared.ID
	ComputedAt          time.Time
}

// NewReviewSnapshot builds an empty snapshot for a cycle at a given
// moment. Callers fill Delta and FindingsToRevalidate via the
// handler's SQL computations.
func NewReviewSnapshot(cycleID, tenantID shared.ID) ReviewSnapshot {
	return ReviewSnapshot{
		CycleID:             cycleID,
		TenantID:            tenantID,
		Delta:               ScopeDelta{ComputedAt: time.Now().UTC()},
		FindingsToRevalidate: nil,
		ComputedAt:          time.Now().UTC(),
	}
}

// Cycle-level metric types used in the `ctem_cycle_metrics` table.
// These are the minimum set the review phase produces; the handler
// can add more without changing this contract — metric_type is just
// a string in the table.
const (
	MetricMTTRHours          = "mttr_hours"
	MetricFindingsOpened     = "findings_opened"
	MetricFindingsResolved   = "findings_resolved"
	MetricPClassChurn        = "p_class_churn"      // count of priority transitions during the cycle
	MetricValidationCoverage = "validation_coverage" // % of closed findings with validation evidence
	MetricScopeDriftSize     = "scope_drift_size"
)
