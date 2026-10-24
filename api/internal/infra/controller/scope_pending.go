package controller

import (
	"context"
	"time"
)

// ScopePendingSettler puts leftover pending scope rows into effect
// (*scope.Service).
type ScopePendingSettler interface {
	ActivateLeftoverPending(ctx context.Context) (int, error)
}

// ScopePendingController puts into effect the scope entries and exclusions
// still waiting for approval in organizations that no longer require
// approvals for scope changes (RFC-073 §6). Each row goes through the job
// signer's ledger and is audited; Strict organizations keep theirs.
type ScopePendingController struct {
	svc      ScopePendingSettler
	interval time.Duration
}

// NewScopePendingController creates the controller. interval 0 = 1 h.
func NewScopePendingController(svc ScopePendingSettler, interval time.Duration) *ScopePendingController {
	if interval <= 0 {
		interval = time.Hour
	}
	return &ScopePendingController{svc: svc, interval: interval}
}

// Name implements Controller.
func (c *ScopePendingController) Name() string { return "scope-pending-settle" }

// Exclusive: one API replica at a time (controller lease). It settles pending scope entries and audits each: two replicas would audit and notify twice.
func (c *ScopePendingController) Exclusive() bool { return true }

// Interval implements Controller.
func (c *ScopePendingController) Interval() time.Duration { return c.interval }

// Reconcile implements Controller: the rows put into effect.
func (c *ScopePendingController) Reconcile(ctx context.Context) (int, error) {
	if c.svc == nil {
		return 0, nil
	}
	return c.svc.ActivateLeftoverPending(ctx)
}
