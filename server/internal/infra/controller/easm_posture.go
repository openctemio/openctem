package controller

// Attack surface posture refresher (docs/architecture/easm-posture.md):
// every minute, one replica recomputes the organizations whose scheduled
// posture refresh is due, within a time budget.

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/logger"
)

// PostureRefresher recomputes due organizations (*posture.Service).
type PostureRefresher interface {
	RefreshDue(ctx context.Context, limit int) (int, error)
}

const (
	easmPostureInterval = time.Minute
	easmPostureBudget   = 5 * time.Minute
	easmPostureBatch    = 10
)

// EASMPostureController runs the refresher.
type EASMPostureController struct {
	svc    PostureRefresher
	logger *logger.Logger
}

// NewEASMPostureController creates the refresher controller.
func NewEASMPostureController(svc PostureRefresher, log *logger.Logger) *EASMPostureController {
	if log == nil {
		log = logger.NewNop()
	}
	return &EASMPostureController{svc: svc, logger: log}
}

// Name returns the controller name.
func (c *EASMPostureController) Name() string { return "easm-posture" }

// Interval returns the reconciliation interval.
func (c *EASMPostureController) Interval() time.Duration { return easmPostureInterval }

// ReconcileTimeout lets one run take longer than the tick: a large
// organization's rebuild can take a while.
func (c *EASMPostureController) ReconcileTimeout() time.Duration { return easmPostureBudget }

// Exclusive: one replica refreshes at a time.
func (c *EASMPostureController) Exclusive() bool { return true }

// Reconcile refreshes due organizations in batches until none is due or the
// budget is spent.
func (c *EASMPostureController) Reconcile(ctx context.Context) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, easmPostureBudget)
	defer cancel()
	total := 0
	for ctx.Err() == nil {
		n, err := c.svc.RefreshDue(ctx, easmPostureBatch)
		total += n
		if err != nil {
			return total, err
		}
		if n < easmPostureBatch {
			break
		}
	}
	return total, nil
}
