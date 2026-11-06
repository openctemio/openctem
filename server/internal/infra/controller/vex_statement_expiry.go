package controller

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/logger"
)

// VEXStatementExpirer withdraws expired VEX statements (internal/app/vex).
type VEXStatementExpirer interface {
	ExpireDue(ctx context.Context, limit int) (int, error)
}

// VEXStatementExpiryController withdraws VEX statements whose expiry
// passed: the findings they closed reopen (unless another statement covers
// them), with an activity entry and an audit event
// (docs/architecture/software-components.md, "VEX statements").
type VEXStatementExpiryController struct {
	expirer  VEXStatementExpirer
	interval time.Duration
	logger   *logger.Logger
}

// vexExpiryBatch is how many statements one run withdraws.
const vexExpiryBatch = 200

// NewVEXStatementExpiryController creates the controller (every 5 minutes).
func NewVEXStatementExpiryController(e VEXStatementExpirer, log *logger.Logger) *VEXStatementExpiryController {
	if log == nil {
		log = logger.NewNop()
	}
	return &VEXStatementExpiryController{expirer: e, interval: 5 * time.Minute, logger: log}
}

// Name returns the controller name.
func (c *VEXStatementExpiryController) Name() string { return "vex-statement-expiry" }

// Interval returns the reconciliation interval.
func (c *VEXStatementExpiryController) Interval() time.Duration { return c.interval }

// Reconcile withdraws expired statements.
func (c *VEXStatementExpiryController) Reconcile(ctx context.Context) (int, error) {
	if c.expirer == nil {
		return 0, nil
	}
	n, err := c.expirer.ExpireDue(ctx, vexExpiryBatch)
	if err != nil {
		c.logger.Error("vex statement expiry failed", "error", err)
		return n, err
	}
	if n > 0 {
		c.logger.Info("vex statements expired", "count", n)
	}
	return n, nil
}
