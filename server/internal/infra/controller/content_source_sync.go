package controller

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/logger"
)

// ContentSourceSyncer runs due rule source syncs and collects old snapshots
// (contentsource.Service).
type ContentSourceSyncer interface {
	RunDue(ctx context.Context) (int, error)
	CollectGarbage(ctx context.Context) (int, error)
}

// ContentSourceSyncController is the rule source sync worker
// (docs/architecture/content-sources.md): every minute it claims the
// sources whose schedule is due or whose sync was requested (Sync now, a
// webhook) and syncs them; once an hour it collects superseded and rejected
// snapshots. Claims are leased in the database, so several API replicas
// never sync the same source at once.
type ContentSourceSyncController struct {
	syncer      ContentSourceSyncer
	logger      *logger.Logger
	lastCollect time.Time
	now         func() time.Time
}

// NewContentSourceSyncController creates the controller.
func NewContentSourceSyncController(s ContentSourceSyncer, log *logger.Logger) *ContentSourceSyncController {
	if log == nil {
		log = logger.NewNop()
	}
	return &ContentSourceSyncController{syncer: s, logger: log, now: time.Now}
}

// Name returns the controller name.
func (c *ContentSourceSyncController) Name() string { return "content-source-sync" }

// Interval returns the reconciliation interval.
func (c *ContentSourceSyncController) Interval() time.Duration { return time.Minute }

// ReconcileTimeout allows a batch of syncs (each bounded to 5 minutes).
func (c *ContentSourceSyncController) ReconcileTimeout() time.Duration { return 30 * time.Minute }

// Reconcile syncs what is due and, hourly, collects old snapshots.
func (c *ContentSourceSyncController) Reconcile(ctx context.Context) (int, error) {
	if c.syncer == nil {
		return 0, nil
	}
	n, err := c.syncer.RunDue(ctx)
	if err != nil {
		c.logger.Error("rule source sync failed", "error", err)
		return n, err
	}
	if c.now().Sub(c.lastCollect) >= time.Hour {
		c.lastCollect = c.now()
		if m, err := c.syncer.CollectGarbage(ctx); err != nil {
			c.logger.Warn("rule source snapshot collection failed", "error", err)
		} else if m > 0 {
			c.logger.Info("rule source snapshots collected", "count", m)
		}
	}
	return n, nil
}
