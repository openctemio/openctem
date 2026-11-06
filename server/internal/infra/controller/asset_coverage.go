package controller

// The asset coverage loop (docs/rfcs/RFC-093-asset-coverage.md).

import (
	"context"
	"time"
)

// AssetCoverageRunner runs one pass of the coverage loop.
type AssetCoverageRunner interface {
	Run(ctx context.Context) (int, error)
}

// AssetCoverageController runs the coverage loop on one replica at a time.
type AssetCoverageController struct {
	runner   AssetCoverageRunner
	interval time.Duration
}

// NewAssetCoverageController creates the controller (interval default 1m).
func NewAssetCoverageController(runner AssetCoverageRunner, interval time.Duration) *AssetCoverageController {
	if interval <= 0 {
		interval = time.Minute
	}
	return &AssetCoverageController{runner: runner, interval: interval}
}

// Name returns the controller name.
func (c *AssetCoverageController) Name() string { return "asset-coverage" }

// Interval returns how often the controller runs.
func (c *AssetCoverageController) Interval() time.Duration { return c.interval }

// Exclusive: one replica runs the loop at a time.
func (c *AssetCoverageController) Exclusive() bool { return true }

// Reconcile runs one pass.
func (c *AssetCoverageController) Reconcile(ctx context.Context) (int, error) {
	return c.runner.Run(ctx)
}
