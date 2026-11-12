package controller

// Asset liveness (docs/architecture/asset-liveness.md): re-decides the
// liveness of every organization's assets with the guards (dangling names,
// pins, a service's host name), closes the open findings of gone assets
// where the organization turned it on, and reopens those of assets that are
// no longer gone.

import (
	"context"
	"time"

	"github.com/openctemio/openctem/server/pkg/logger"
)

// assetLivenessReconciler is the slice of *liveness.Service this controller drives.
type assetLivenessReconciler interface {
	ReconcileAll(ctx context.Context) (int, error)
}

// AssetLivenessController runs the asset liveness pass on a schedule.
type AssetLivenessController struct {
	svc      assetLivenessReconciler
	interval time.Duration
	logger   *logger.Logger
}

// NewAssetLivenessController creates the controller. A non-positive interval
// falls back to 15 minutes.
func NewAssetLivenessController(svc assetLivenessReconciler, interval time.Duration, log *logger.Logger) *AssetLivenessController {
	if interval <= 0 {
		interval = 15 * time.Minute
	}
	return &AssetLivenessController{svc: svc, interval: interval, logger: log}
}

// Name returns the controller name.
func (c *AssetLivenessController) Name() string { return "asset-liveness" }

// Interval returns how often the reconcile runs.
func (c *AssetLivenessController) Interval() time.Duration { return c.interval }

// Reconcile runs one pass over every organization with liveness rows.
func (c *AssetLivenessController) Reconcile(ctx context.Context) (int, error) {
	n, err := c.svc.ReconcileAll(ctx)
	if err != nil {
		return 0, err
	}
	if n > 0 && c.logger != nil {
		c.logger.Info("asset liveness pass changed states or findings", "changes", n)
	}
	return n, nil
}
