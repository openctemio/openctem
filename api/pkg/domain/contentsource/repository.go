package contentsource

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ListFilter narrows an organization's view of sources.
type ListFilter struct {
	Kind  Kind
	Scope Scope // "" both
}

// SyncOutcome is what a sync writes back to its source.
type SyncOutcome struct {
	Status        SyncStatus
	Error         string
	Commit        string
	Report        []byte
	At            time.Time
	NextSyncAt    *time.Time
	ClearRequest  bool
	ResetFailures bool
	KeepFailures  bool // neither reset nor count (a skipped sync)
}

// Repository stores sources and snapshots.
//
// Methods without a suffix are tenant-scoped: they act on the tenant's own
// rows only (a platform row, tenant_id NULL, never matches), except the
// Visible reads, which also return platform rows that are offered. Methods
// ending in Unscoped serve the sync worker and the webhook, which work
// across tenants, and are never called from an organization's request
// with an id it supplied without the secret check.
type Repository interface {
	Create(ctx context.Context, s *Source) error
	// Get returns the tenant's own source.
	Get(ctx context.Context, tenantID, id shared.ID) (*Source, error)
	// GetVisible returns the tenant's own source or an offered platform
	// source; anything else is ErrNotFound.
	GetVisible(ctx context.Context, tenantID, id shared.ID) (*Source, error)
	// ListVisible lists the tenant's own sources and the offered platform
	// sources, platform first.
	ListVisible(ctx context.Context, tenantID shared.ID, f ListFilter) ([]*Source, error)
	CountForTenant(ctx context.Context, tenantID shared.ID) (int, error)
	// Update writes the tenant's own source's configuration.
	Update(ctx context.Context, s *Source) error
	Delete(ctx context.Context, tenantID, id shared.ID) error
	// RequestSync queues a sync of the tenant's own source.
	RequestSync(ctx context.Context, tenantID, id shared.ID, at time.Time) error

	// ClaimDueUnscoped leases up to limit enabled tenant sources whose
	// schedule is due or whose sync was requested, so one worker syncs each.
	ClaimDueUnscoped(ctx context.Context, now time.Time, lease time.Duration, limit int) ([]*Source, error)
	// GetUnscoped loads any source by id (worker and webhook only).
	GetUnscoped(ctx context.Context, id shared.ID) (*Source, error)
	// RequestSyncUnscoped queues a sync unless one was requested within
	// minGap (webhook): queued is false then.
	RequestSyncUnscoped(ctx context.Context, id shared.ID, at time.Time, minGap time.Duration) (queued bool, err error)
	// SaveSyncUnscoped writes a sync's outcome and releases the lease.
	SaveSyncUnscoped(ctx context.Context, id shared.ID, o SyncOutcome) error

	CreateSnapshot(ctx context.Context, sn *Snapshot) error
	// GetSnapshotVisible returns a snapshot of a source visible to tenantID.
	GetSnapshotVisible(ctx context.Context, tenantID, sourceID, id shared.ID) (*Snapshot, error)
	// GetSnapshotUnscoped returns a snapshot by id (worker only).
	GetSnapshotUnscoped(ctx context.Context, id shared.ID) (*Snapshot, error)
	// FindSnapshotByDigestUnscoped returns the source's snapshot of digest,
	// or ErrSnapshotNotFound.
	FindSnapshotByDigestUnscoped(ctx context.Context, sourceID shared.ID, digest string) (*Snapshot, error)
	ListSnapshotsVisible(ctx context.Context, tenantID, sourceID shared.ID, limit, offset int) ([]*Snapshot, int, error)
	// SupersedeCandidatesUnscoped marks the source's candidates other than
	// keep as superseded.
	SupersedeCandidatesUnscoped(ctx context.Context, sourceID, keep shared.ID) error

	// Promote makes a candidate of the tenant's own source current; the
	// current one becomes previous and the old previous is superseded. The
	// check function runs inside the transaction with the locked source and
	// snapshot (four-eyes).
	Promote(ctx context.Context, tenantID, sourceID, snapshotID shared.ID, by *shared.ID, at time.Time, check func(*Source, *Snapshot) error) error
	// PromoteUnscoped is Promote for the sync worker's automatic promotion.
	PromoteUnscoped(ctx context.Context, sourceID, snapshotID shared.ID, at time.Time) error
	// Rollback swaps current and previous of the tenant's own source.
	Rollback(ctx context.Context, tenantID, sourceID shared.ID) (*Source, error)
	// Reject rejects a candidate of the tenant's own source.
	Reject(ctx context.Context, tenantID, sourceID, snapshotID shared.ID, by *shared.ID, reason string, at time.Time) error

	// ListCollectableUnscoped returns tenant snapshots that are superseded
	// or rejected, neither current nor previous, and older than before.
	ListCollectableUnscoped(ctx context.Context, before time.Time, limit int) ([]*Snapshot, error)
	// DeleteSnapshotUnscoped deletes a collectable snapshot (never current or
	// previous); deleted is false when it no longer qualifies.
	DeleteSnapshotUnscoped(ctx context.Context, id shared.ID) (deleted bool, err error)
	// ListOrphanPacksUnscoped returns rule source packs created before the
	// given time that no snapshot references (a failed sync, or a collected
	// snapshot whose pack could not be deleted).
	ListOrphanPacksUnscoped(ctx context.Context, before time.Time, limit int) ([]OrphanPack, error)
}

// OrphanPack is a rule source pack no snapshot references.
type OrphanPack struct {
	TenantID shared.ID
	PackID   shared.ID
}
