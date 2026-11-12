package controller

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/webendpoint"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// WebSurfaceRetentionController keeps the web surface sub-inventory current
// (RFC-056 WS14): an endpoint not seen for 30 days is gone (with a gone event
// in the change feed), one gone for a year is deleted with its parameters and
// events, and change feed rows older than 90 days are deleted. Findings are
// never touched. A platform job: every tenant, each row keeps its tenant.
type WebSurfaceRetentionController struct {
	repo   webendpoint.RetentionStore
	logger *logger.Logger
	now    func() time.Time
}

// Batches of one run per step.
const (
	webSurfaceBatchSize  = 5000
	webSurfaceMaxBatches = 20
)

// NewWebSurfaceRetentionController builds the controller.
func NewWebSurfaceRetentionController(repo webendpoint.RetentionStore, log *logger.Logger) *WebSurfaceRetentionController {
	if log == nil {
		log = logger.NewNop()
	}
	return &WebSurfaceRetentionController{repo: repo, logger: log, now: time.Now}
}

// Name returns the controller name.
func (c *WebSurfaceRetentionController) Name() string { return "web-surface-retention" }

// Interval returns the reconciliation interval.
func (c *WebSurfaceRetentionController) Interval() time.Duration { return time.Hour }

// Exclusive: one API replica at a time (controller lease).
func (c *WebSurfaceRetentionController) Exclusive() bool { return true }

// Reconcile runs the three steps in batches; it stops at the first error.
func (c *WebSurfaceRetentionController) Reconcile(ctx context.Context) (int, error) {
	now := c.now()
	steps := []struct {
		name string
		run  func(context.Context, time.Time, int) (int64, error)
		at   time.Time
	}{
		{"gone", c.repo.MarkGone, now.Add(-webendpoint.GoneAfter)},
		{"purged", c.repo.PurgeGone, now.Add(-webendpoint.PurgeAfter)},
		{"events deleted", c.repo.DeleteEventsBefore, now.Add(-webendpoint.EventsKeep)},
	}
	var total int64
	for _, st := range steps {
		var n int64
		for i := 0; i < webSurfaceMaxBatches; i++ {
			got, err := st.run(ctx, st.at, webSurfaceBatchSize)
			if err != nil {
				c.logger.Error("web surface retention failed", "step", st.name, "error", err)
				return int(total + n), err
			}
			n += got
			if got < webSurfaceBatchSize {
				break
			}
		}
		if n > 0 {
			c.logger.Info("web surface retention", "step", st.name, "count", n)
		}
		total += n
	}
	return int(total), nil
}
