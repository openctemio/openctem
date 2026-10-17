package asset

// Asset risk score freshness (docs/architecture/asset-risk-score.md):
// database triggers queue an asset whenever an input of its risk score
// changes; the asset-risk-score worker claims queued assets and rescores
// them per tenant.

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// RiskQueueItem is one queued asset.
type RiskQueueItem struct {
	TenantID shared.ID
	AssetID  shared.ID
}

// RiskQueueStats describes the queue for metrics.
type RiskQueueStats struct {
	Depth     int64
	OldestAge time.Duration
}

// RiskQueueRepository is the rescore queue.
type RiskQueueRepository interface {
	// ClaimForPlatform removes up to limit due assets from the queue,
	// oldest first, across tenants (the worker regroups them per tenant and
	// every read and write after the claim is tenant-scoped). Concurrent
	// claimers never receive the same asset.
	ClaimForPlatform(ctx context.Context, limit int) ([]RiskQueueItem, error)

	// Enqueue queues assets of one tenant (a failed rescore puts its assets
	// back). Asset ids of another tenant are ignored.
	Enqueue(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) error

	// EnqueueTenant queues every live asset of the tenant (risk settings
	// changed). Returns the number of assets queued.
	EnqueueTenant(ctx context.Context, tenantID shared.ID) (int64, error)

	// EnqueueAllForPlatform queues every live asset of every tenant with a
	// due time of now+delay, so rows queued by real changes are claimed
	// first; an asset whose score version is missing or older than the
	// tenant's current one is due now. An asset already queued keeps its earlier due time. Used by the
	// periodic reconcile. Returns the number of assets newly queued.
	EnqueueAllForPlatform(ctx context.Context, delay time.Duration) (int64, error)

	// StampRiskVersion records the scoring version the given assets of the
	// tenant were scored with.
	StampRiskVersion(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID, version int64) error

	// StatsForPlatform returns the queue depth and the age of its oldest
	// due row.
	StatsForPlatform(ctx context.Context) (RiskQueueStats, error)

	// RefreshRollups recomputes the stored roll-ups (business units, asset
	// groups) that contain any of the given assets of the tenant.
	RefreshRollups(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) error
}

// RiskContributor is one open finding that drives an asset's score.
type RiskContributor struct {
	FindingID        shared.ID
	Title            string
	Severity         string
	EPSSScore        *float64
	InKEV            bool
	ExploitAvailable bool
}

// RiskContributorReader lists the open findings that drive an asset's score.
type RiskContributorReader interface {
	// TopContributors returns up to limit active findings of the asset of
	// the tenant, worst first: severity, then KEV, known exploit, EPSS.
	TopContributors(ctx context.Context, tenantID, assetID shared.ID, limit int) ([]RiskContributor, error)
}
