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
	// first. An asset already queued keeps its earlier due time. Used by the
	// periodic reconcile. Returns the number of assets newly queued.
	EnqueueAllForPlatform(ctx context.Context, delay time.Duration) (int64, error)

	// StatsForPlatform returns the queue depth and the age of its oldest
	// due row.
	StatsForPlatform(ctx context.Context) (RiskQueueStats, error)
}
