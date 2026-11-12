package controller

// The closing-window controller (docs/architecture/scan-windows.md,
// "Closing windows"): every minute, running probing jobs outside their scan
// windows get their grace, then go back to the queue for the next opening.

import (
	"context"
	"time"

	commandapp "github.com/openctemio/openctem/api/internal/app/command"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// ClosedWindowEnforcer is the command service's pass.
type ClosedWindowEnforcer interface {
	EnforceClosedWindows(ctx context.Context, tenants commandapp.WindowTenants) (int, error)
}

// ScanWindowClosingController runs EnforceClosedWindows periodically.
type ScanWindowClosingController struct {
	enforcer ClosedWindowEnforcer
	tenants  commandapp.WindowTenants
	interval time.Duration
	logger   *logger.Logger
}

// NewScanWindowClosingController creates the controller (interval 0: one
// minute).
func NewScanWindowClosingController(e ClosedWindowEnforcer, tenants commandapp.WindowTenants, interval time.Duration, log *logger.Logger) *ScanWindowClosingController {
	if interval <= 0 {
		interval = time.Minute
	}
	if log == nil {
		log = logger.NewNop()
	}
	return &ScanWindowClosingController{enforcer: e, tenants: tenants, interval: interval, logger: log}
}

// Name returns the controller name.
func (c *ScanWindowClosingController) Name() string { return "scan-window-closing" }

// Interval returns the reconciliation interval.
func (c *ScanWindowClosingController) Interval() time.Duration { return c.interval }

// Reconcile makes one pass.
func (c *ScanWindowClosingController) Reconcile(ctx context.Context) (int, error) {
	n, err := c.enforcer.EnforceClosedWindows(ctx, c.tenants)
	if err != nil {
		c.logger.Error("scan window closing pass failed", "error", err)
		return n, err
	}
	if n > 0 {
		c.logger.Info("running jobs returned to the queue: their scan window closed", "count", n)
	}
	return n, nil
}
