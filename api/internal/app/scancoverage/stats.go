package scancoverage

import (
	"context"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// CoverageStats is a point-in-time summary of how well a tenant's scannable
// estate is covered by rolling scans (RFC-007 Phase 4 observability). It turns
// "we ran scans" into a verifiable coverage figure — the freshness/utilisation
// view the use case needs (and that Tenable.sc reporting provides).
type CoverageStats struct {
	// WindowDays is the freshness window the stats were computed against.
	WindowDays int `json:"window_days"`
	// TotalScannable is the count of active, network-scannable assets.
	TotalScannable int `json:"total_scannable"`
	// NeverScanned have no coverage cursor row yet.
	NeverScanned int `json:"never_scanned"`
	// CoveredInWindow were dispatched within WindowDays.
	CoveredInWindow int `json:"covered_in_window"`
	// Stale were dispatched, but longer ago than WindowDays.
	Stale int `json:"stale"`
	// CriticalNeverScanned is the headline risk: critical assets never covered.
	CriticalNeverScanned int `json:"critical_never_scanned"`
	// CriticalUncovered are critical assets either never scanned or stale.
	CriticalUncovered int `json:"critical_uncovered"`
	// OldestDispatchedAt is the least-recently covered asset's timestamp (nil if
	// nothing has been dispatched yet).
	OldestDispatchedAt *time.Time `json:"oldest_dispatched_at,omitempty"`
	// CoveragePercent = CoveredInWindow / TotalScannable * 100 (0 when none).
	CoveragePercent float64 `json:"coverage_percent"`
}

// CoverageStatsReader reads coverage observability stats for a tenant.
// *postgres.ScanCoverageRepository implements it.
type CoverageStatsReader interface {
	CoverageStats(ctx context.Context, tenantID shared.ID, windowDays int) (*CoverageStats, error)
}

// DefaultCoverageWindowDays is the freshness window used when a caller does not
// specify one.
const DefaultCoverageWindowDays = 30
