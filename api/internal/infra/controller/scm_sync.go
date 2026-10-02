package controller

import (
	"context"
	"time"

	"github.com/openctemio/api/pkg/logger"
)

// SCMSyncer is the integration-service surface the scheduled sync needs.
type SCMSyncer interface {
	// SyncAllConnectedSCMIntegrations imports repositories + branches for every
	// connected SCM integration across all tenants. Returns repos created+updated.
	SyncAllConnectedSCMIntegrations(ctx context.Context) (int, error)
}

// SCMSyncController periodically imports repositories and syncs branches for all
// connected SCM integrations. It reuses the on-demand import path, so it also
// refreshes branch defaults and flips a connection to "error" when its token has
// expired. Disabled unless SCM_SYNC_INTERVAL is set (interval > 0).
type SCMSyncController struct {
	syncer   SCMSyncer
	interval time.Duration
	logger   *logger.Logger
}

// NewSCMSyncController creates a new scheduled SCM sync controller.
func NewSCMSyncController(syncer SCMSyncer, interval time.Duration, log *logger.Logger) *SCMSyncController {
	return &SCMSyncController{syncer: syncer, interval: interval, logger: log}
}

// Name returns the controller name.
func (c *SCMSyncController) Name() string { return "scm-sync" }

// Interval returns the configured sync interval.
func (c *SCMSyncController) Interval() time.Duration { return c.interval }

// Reconcile runs one scheduled SCM sync pass.
func (c *SCMSyncController) Reconcile(ctx context.Context) (int, error) {
	return c.syncer.SyncAllConnectedSCMIntegrations(ctx)
}
