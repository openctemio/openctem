package dashboard

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Snapshot is the stored result of one dashboard
// (docs/architecture/dashboards.md, "Snapshots and refresh").
type Snapshot struct {
	TenantID    shared.ID
	DashboardID shared.ID
	Kind        Kind
	// OwnerID is the owner of a personal dashboard (zero for organization).
	OwnerID shared.ID
	// ScopeKey fingerprints the scope the figures were computed for; a
	// personal snapshot whose key differs from the owner's current one is
	// never served.
	ScopeKey string
	// LayoutHash fingerprints the widgets it was computed from.
	LayoutHash    string
	Data          []byte
	ComputedAt    time.Time
	DurationMS    int
	NextRefreshAt *time.Time
	LastError     string
	FailedAt      *time.Time
	ViewedAt      time.Time
}

// DueSnapshot names a snapshot the refresher should recompute.
type DueSnapshot struct {
	TenantID    shared.ID
	DashboardID shared.ID
	Kind        Kind
	OwnerID     shared.ID
}

// RefreshBudget limits Refresh now: one per minute per person and dashboard,
// MaxTenantRefreshesPerHour per organization.
const (
	RefreshPerUserEvery       = time.Minute
	MaxTenantRefreshesPerHour = 30
)

// SnapshotStore keeps dashboard snapshots and the Refresh now budget. The
// per-tenant methods take the tenant from the caller; the ForPlatform ones
// work across tenants and are called only by the refresher.
type SnapshotStore interface {
	// GetSnapshot returns the snapshot of a dashboard, nil when none.
	GetSnapshot(ctx context.Context, tenantID, dashboardID shared.ID) (*Snapshot, error)
	// PutSnapshot stores a snapshot (replacing the previous one, clearing
	// any failure) and writes next_refresh_at on the dashboard.
	PutSnapshot(ctx context.Context, s Snapshot) error
	// MarkSnapshotFailed keeps the last good snapshot and records why the
	// refresh failed and when to try again.
	MarkSnapshotFailed(ctx context.Context, tenantID, dashboardID shared.ID, code string, next *time.Time) error
	// TouchSnapshot records that the snapshot was viewed (at most once an
	// hour is written).
	TouchSnapshot(ctx context.Context, tenantID, dashboardID shared.ID, at time.Time) error
	// DeleteSnapshot removes a snapshot.
	DeleteSnapshot(ctx context.Context, tenantID, dashboardID shared.ID) error
	// TakeRefreshBudget records a Refresh now when the budget allows it, in
	// one serialized statement per tenant; otherwise it returns how long to
	// wait.
	TakeRefreshBudget(ctx context.Context, tenantID, dashboardID, userID shared.ID) (ok bool, retryAfter time.Duration, err error)
	// ScopeFingerprint fingerprints a read scope: the kind of scope, the
	// owner's scope rows (restricted) or the assets hidden from them
	// (unrestricted), and their pentest campaigns (unless allCampaigns).
	ScopeFingerprint(ctx context.Context, tenantID, userID shared.ID, scope *shared.DataScope, allCampaigns bool) (string, error)
	// ClaimDueSnapshotsForPlatform returns up to limit snapshots due for a
	// refresh and moves their next_refresh_at by lease, so another replica
	// does not take them meanwhile.
	ClaimDueSnapshotsForPlatform(ctx context.Context, now time.Time, limit int, lease time.Duration) ([]DueSnapshot, error)
	// PruneForPlatform deletes Refresh now records older than before and the
	// personal snapshots not viewed since staleBefore (they are recomputed on
	// the next open).
	PruneForPlatform(ctx context.Context, before, staleBefore time.Time) error
}
