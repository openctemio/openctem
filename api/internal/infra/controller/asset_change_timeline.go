package controller

// Asset change timeline upkeep (RFC-069 §11,
// docs/architecture/asset-attribute-reconciliation.md):
//   - creates the monthly partitions ahead of time;
//   - drops events past retention (whole months);
//   - once a day re-resolves the reconciled attributes of every asset with a
//     recorded source, so a value whose deciding source went past its TTL
//     moves to the next fresh source (and the timeline says why) without
//     waiting for that asset's next report.

import (
	"context"
	"time"

	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// AssetChangeTimelineStore is the storage the controller needs
// (*postgres.AssetChangeEventRepository).
type AssetChangeTimelineStore interface {
	assetdom.ChangeTimelineMaintainer
	TenantsWithAttributeSources(ctx context.Context) ([]shared.ID, error)
	AssetsWithAttributeSources(ctx context.Context, tenantID shared.ID, after *shared.ID, limit int) ([]shared.ID, error)
}

// AttributeResolver re-resolves assets' reconciled attributes
// (*assetapp.AssetService).
type AttributeResolver interface {
	ResolveAttributes(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID, reason assetdom.ChangeReason) (int, error)
}

// minAssetChangeRetentionDays is the floor of the configured retention.
const minAssetChangeRetentionDays = 30

// assetResolveBatch is how many assets one re-resolution transaction locks.
const assetResolveBatch = 200

// AssetChangeTimelineController keeps the timeline's partitions, retention
// and TTL expiry.
type AssetChangeTimelineController struct {
	store         AssetChangeTimelineStore
	resolver      AttributeResolver
	retentionDays int
	sweepEvery    time.Duration
	lastSweep     time.Time
	now           func() time.Time
	logger        *logger.Logger
}

// NewAssetChangeTimelineController creates the controller. retentionDays
// below 30 is raised to 30; 0 means the default (400).
func NewAssetChangeTimelineController(store AssetChangeTimelineStore, resolver AttributeResolver, retentionDays int, log *logger.Logger) *AssetChangeTimelineController {
	if retentionDays == 0 {
		retentionDays = assetdom.DefaultChangeRetentionDays
	}
	if retentionDays < minAssetChangeRetentionDays {
		retentionDays = minAssetChangeRetentionDays
	}
	if log == nil {
		log = logger.NewNop()
	}
	return &AssetChangeTimelineController{
		store: store, resolver: resolver, retentionDays: retentionDays,
		sweepEvery: 24 * time.Hour, now: time.Now, logger: log,
	}
}

// Name returns the controller name.
func (c *AssetChangeTimelineController) Name() string { return "asset-change-timeline" }

// Interval returns the reconciliation interval.
func (c *AssetChangeTimelineController) Interval() time.Duration { return time.Hour }

// Exclusive: one replica at a time (partition DDL and the sweep).
func (c *AssetChangeTimelineController) Exclusive() bool { return true }

// Reconcile creates partitions, applies retention and, once a day,
// re-resolves attributes whose deciding source may have gone stale.
func (c *AssetChangeTimelineController) Reconcile(ctx context.Context) (int, error) {
	now := c.now()
	processed := 0
	if n, err := c.store.EnsurePartitions(ctx, now, 3); err != nil {
		c.logger.Error("asset change partitions not created", "error", err)
	} else {
		processed += n
	}
	cutoff := now.AddDate(0, 0, -c.retentionDays)
	if parts, rows, err := c.store.DropBefore(ctx, cutoff); err != nil {
		c.logger.Error("asset change retention failed", "error", err)
	} else if parts > 0 || rows > 0 {
		c.logger.Info("asset change retention", "partitions_dropped", parts, "rows_deleted", rows,
			"retention_days", c.retentionDays)
		processed += parts
	}
	if c.resolver == nil || (!c.lastSweep.IsZero() && now.Sub(c.lastSweep) < c.sweepEvery) {
		return processed, nil
	}
	changed, err := c.sweep(ctx)
	if err != nil {
		return processed, err
	}
	c.lastSweep = now
	return processed + changed, nil
}

// sweep re-resolves every asset with a recorded source, tenant by tenant,
// in batches. The reason is left to the resolver (TTL expiry or a policy
// change, from the record that decided before).
func (c *AssetChangeTimelineController) sweep(ctx context.Context) (int, error) {
	tenants, err := c.store.TenantsWithAttributeSources(ctx)
	if err != nil {
		return 0, err
	}
	changed := 0
	for _, tid := range tenants {
		var after *shared.ID
		for {
			if ctx.Err() != nil {
				return changed, ctx.Err()
			}
			ids, err := c.store.AssetsWithAttributeSources(ctx, tid, after, assetResolveBatch)
			if err != nil {
				return changed, err
			}
			if len(ids) == 0 {
				break
			}
			n, err := c.resolver.ResolveAttributes(ctx, tid, ids, "")
			if err != nil {
				c.logger.Warn("asset attribute sweep failed", "tenant_id", tid.String(), "error", err)
				break
			}
			changed += n
			last := ids[len(ids)-1]
			after = &last
			if len(ids) < assetResolveBatch {
				break
			}
		}
	}
	return changed, nil
}
