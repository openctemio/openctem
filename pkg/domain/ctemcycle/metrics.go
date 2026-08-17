package ctemcycle

import (
	"context"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// This file turns the metric-key constants in review.go into a real,
// persisted, queryable layer. The six metrics are computed over a
// cycle's active window [activated_at, closed_at], written to
// ctem_cycle_metrics at Close (best-effort) and lazily on read, then
// served back per-cycle and as a cross-cycle trend + maturity
// breakdown. See RFC-005 (CTEM cycles) — this is the "measured
// program" (Tier 3) layer.

// CycleMetricSet is the computed metric map for one cycle:
// metric_type → value. Values are DECIMAL(12,2) in storage.
type CycleMetricSet map[string]float64

// StoredMetric is one persisted ctem_cycle_metrics row.
type StoredMetric struct {
	MetricType string    `json:"metric_type"`
	Value      float64   `json:"value"`
	ComputedAt time.Time `json:"computed_at"`
}

// CycleMetrics bundles a closed cycle with its latest metric values —
// the unit the trend endpoint iterates over. Metrics holds the most
// recent value per metric_type for the cycle.
type CycleMetrics struct {
	CycleID  shared.ID          `json:"cycle_id"`
	Name     string             `json:"name"`
	ClosedAt time.Time          `json:"closed_at"`
	Metrics  map[string]float64 `json:"metrics"`
}

// Value returns the metric value for key, or 0 when absent.
func (c CycleMetrics) Value(key string) float64 {
	if c.Metrics == nil {
		return 0
	}
	return c.Metrics[key]
}

// MetricsRepository computes, persists and reads per-cycle metrics.
// All methods are tenant-scoped: the tenant is checked by joining
// ctem_cycles (ctem_cycle_metrics itself has no tenant_id column).
type MetricsRepository interface {
	// Compute runs the metric queries over the cycle's active window
	// and returns the values WITHOUT persisting them. Returns
	// shared.ErrNotFound when the cycle does not belong to the tenant.
	Compute(ctx context.Context, tenantID, cycleID shared.ID) (CycleMetricSet, error)
	// UpsertBatch replaces the stored metric rows for one cycle with
	// the given set (delete-then-insert inside a transaction). No-op on
	// an empty set. Tenant-scoped: writes nothing for a foreign cycle.
	UpsertBatch(ctx context.Context, tenantID, cycleID shared.ID, metrics CycleMetricSet) error
	// Get returns the persisted metric rows for one cycle, newest
	// first. Empty (not an error) when none are stored yet.
	Get(ctx context.Context, tenantID, cycleID shared.ID) ([]StoredMetric, error)
	// ListClosedForTenant batch-loads every closed cycle's latest
	// metrics in a single query, ordered by closed_at ascending, for
	// the trend/maturity endpoint. No N+1.
	ListClosedForTenant(ctx context.Context, tenantID shared.ID) ([]CycleMetrics, error)
}
