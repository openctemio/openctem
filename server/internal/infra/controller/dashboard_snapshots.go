package controller

// Dashboard snapshot refresher (docs/architecture/dashboards.md, "Snapshots
// and refresh"): every minute, one replica recomputes the snapshots whose
// scheduled refresh is due, oldest first, within a time budget.

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/logger"
)

// DashboardSnapshotRefresher recomputes due snapshots (*widgets.Service).
type DashboardSnapshotRefresher interface {
	RefreshDue(ctx context.Context, limit int) (int, error)
}

const (
	dashboardSnapshotsInterval = time.Minute
	dashboardSnapshotsBudget   = 50 * time.Second
	dashboardSnapshotsBatch    = 50
)

// DashboardSnapshotsController runs the refresher.
type DashboardSnapshotsController struct {
	svc    DashboardSnapshotRefresher
	logger *logger.Logger
}

// NewDashboardSnapshotsController creates the refresher controller.
func NewDashboardSnapshotsController(svc DashboardSnapshotRefresher, log *logger.Logger) *DashboardSnapshotsController {
	if log == nil {
		log = logger.NewNop()
	}
	return &DashboardSnapshotsController{svc: svc, logger: log}
}

// Name returns the controller name.
func (c *DashboardSnapshotsController) Name() string { return "dashboard-snapshots" }

// Interval returns the reconciliation interval.
func (c *DashboardSnapshotsController) Interval() time.Duration { return dashboardSnapshotsInterval }

// Exclusive: one replica refreshes at a time.
func (c *DashboardSnapshotsController) Exclusive() bool { return true }

// Reconcile refreshes due snapshots in batches until none is due or the
// budget is spent, and returns how many were refreshed.
func (c *DashboardSnapshotsController) Reconcile(ctx context.Context) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, dashboardSnapshotsBudget)
	defer cancel()
	total := 0
	for ctx.Err() == nil {
		n, err := c.svc.RefreshDue(ctx, dashboardSnapshotsBatch)
		total += n
		if err != nil {
			return total, err
		}
		if n < dashboardSnapshotsBatch {
			break
		}
	}
	return total, nil
}
