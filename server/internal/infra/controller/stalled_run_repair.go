package controller

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/logger"
)

// StalledRunRepairer advances workflow runs left waiting on nothing
// (scanrun.Service.RepairStalledRuns).
type StalledRunRepairer interface {
	RepairStalledRuns(ctx context.Context) (int, error)
}

// StalledRunRepairController runs the stall repair every interval (research/62
// SG-10: a chained step deferred for a report that then failed or expired,
// or a plan saved without its commands).
type StalledRunRepairController struct {
	repairer StalledRunRepairer
	interval time.Duration
	logger   *logger.Logger
}

// NewStalledRunRepairController builds the controller (default every 60 s).
func NewStalledRunRepairController(r StalledRunRepairer, interval time.Duration, log *logger.Logger) *StalledRunRepairController {
	if interval <= 0 {
		interval = time.Minute
	}
	if log == nil {
		log = logger.NewNop()
	}
	return &StalledRunRepairController{repairer: r, interval: interval, logger: log}
}

// Name returns the controller name.
func (c *StalledRunRepairController) Name() string { return "stalled-run-repair" }

// Interval returns the reconciliation interval.
func (c *StalledRunRepairController) Interval() time.Duration { return c.interval }

// Reconcile advances the stalled runs.
func (c *StalledRunRepairController) Reconcile(ctx context.Context) (int, error) {
	return c.repairer.RepairStalledRuns(ctx)
}

// Exclusive: one replica repairs at a time, so a run is not advanced twice
// in the same pass.
func (c *StalledRunRepairController) Exclusive() bool { return true }
