package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// control test cadence controller.
//
// Every compensating control has a test cadence (e.g. "test this
// WAF rule every 30 days"). This controller runs periodically to:
//
//   1. Mark controls whose last test is older than the cadence as
//      `overdue` so the UI can flag them.
//   2. After a grace period beyond overdue, invalidate the control
//      (status = expired) and trigger a priority reclassification
//      for the protected assets — because a stale WAF claim must
//      not artificially keep a finding at P2.
//
// The DB operations live in the repository layer; this file is the
// controller wrapper + the event wiring.
//
// NOT WIRED: this controller is not registered in cmd/server/workers.go
// because the ControlTestSink methods it depends on are not implemented
// on postgres.ControlTestRepository — the repo has a different
// MarkOverdue signature (ctx, tenantID, id) that is called by the UI
// per-row, and ExpireWithGrace doesn't exist at all. A future PR that
// turns on this controller needs to:
//   1. Add batch MarkOverdue(ctx, now) (int64, error) to the repo
//   2. Add ExpireWithGrace(ctx, now, grace) ([]ExpiredControl, error)
//   3. Register the controller in workers.go with the
//      ControlChangePublisher so expired-control reclassification fires.

// ControlTestSink is the narrow store surface the controller needs.
type ControlTestSink interface {
	// MarkOverdue flags controls whose last_tested_at + cadence <
	// now AND status = 'active'. Returns the count marked.
	MarkOverdue(ctx context.Context, now time.Time) (int64, error)
	// ExpireWithGrace flips controls that have been overdue past
	// the grace period to status='expired' and returns the tenant
	// + asset pairs that need reclassification.
	ExpireWithGrace(ctx context.Context, now time.Time, grace time.Duration) ([]ExpiredControl, error)
}

// ExpiredControl describes one control that just expired. Used to
// drive the downstream reclassify sweep.
type ExpiredControl struct {
	TenantID  shared.ID
	ControlID shared.ID
	AssetIDs  []shared.ID
}

// ControlTestCadenceConfig tunes the controller.
type ControlTestCadenceConfig struct {
	Interval   time.Duration // default 1h
	Grace      time.Duration // default 7 days
	Publisher  *ControlChangePublisher
	Logger     *logger.Logger
}

// ControlTestCadenceController implements Name/Interval/Reconcile.
type ControlTestCadenceController struct {
	store  ControlTestSink
	cfg    *ControlTestCadenceConfig
	logger *logger.Logger
}

// NewControlTestCadenceController wires deps with safe defaults.
func NewControlTestCadenceController(store ControlTestSink, cfg *ControlTestCadenceConfig) *ControlTestCadenceController {
	if cfg == nil {
		cfg = &ControlTestCadenceConfig{}
	}
	if cfg.Interval == 0 {
		cfg.Interval = time.Hour
	}
	if cfg.Grace == 0 {
		cfg.Grace = 7 * 24 * time.Hour
	}
	if cfg.Logger == nil {
		cfg.Logger = logger.NewNop()
	}
	return &ControlTestCadenceController{
		store:  store,
		cfg:    cfg,
		logger: cfg.Logger.With("controller", "control-test-cadence"),
	}
}

// Name returns the controller name.
func (c *ControlTestCadenceController) Name() string { return "control-test-cadence" }

// Interval returns the tick interval.
func (c *ControlTestCadenceController) Interval() time.Duration { return c.cfg.Interval }

// Reconcile marks overdue, expires with grace, and triggers
// reclassification for every expired control.
func (c *ControlTestCadenceController) Reconcile(ctx context.Context) (int, error) {
	now := time.Now().UTC()

	markedCount, err := c.store.MarkOverdue(ctx, now)
	if err != nil {
		return 0, fmt.Errorf("mark overdue: %w", err)
	}
	if markedCount > 0 {
		c.logger.Info("marked controls overdue", "count", markedCount)
	}

	expired, err := c.store.ExpireWithGrace(ctx, now, c.cfg.Grace)
	if err != nil {
		// Overdue-marking already happened — surface the error but
		// keep the count so the controller framework can log.
		return int(markedCount), fmt.Errorf("expire with grace: %w", err)
	}

	// For every expired control, reclassify the affected assets so
	// findings that were parked at P2 "protected by control" flip
	// back up to their true priority.
	if c.cfg.Publisher != nil {
		for _, e := range expired {
			c.cfg.Publisher.PublishChange(ctx, e.TenantID, e.AssetIDs, "control expired past cadence grace")
		}
	}
	if len(expired) > 0 {
		c.logger.Info("expired controls past grace",
			"count", len(expired),
			"grace_days", int(c.cfg.Grace/(24*time.Hour)),
		)
	}
	return int(markedCount) + len(expired), nil
}
