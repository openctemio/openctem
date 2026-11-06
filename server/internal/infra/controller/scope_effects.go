package controller

// Scope effects (research/320): closes the open findings of assets out of
// scope for good and reopens the findings of assets back in scope, for every
// organization that may have one. Exclusion and "not ours" changes kick a
// pass at once (scope.Effects.Kick); this catches expiries, findings that
// arrived meanwhile and kicks lost to a restart.

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/logger"
)

// scopeEffectsReconciler is the slice of *scope.Effects this controller drives.
type scopeEffectsReconciler interface {
	ReconcileAll(ctx context.Context) (int, error)
}

// ScopeEffectsController runs the scope effects reconciler on a schedule.
type ScopeEffectsController struct {
	svc      scopeEffectsReconciler
	interval time.Duration
	logger   *logger.Logger
}

// NewScopeEffectsController creates the controller. A non-positive interval
// falls back to 5 minutes.
func NewScopeEffectsController(svc scopeEffectsReconciler, interval time.Duration, log *logger.Logger) *ScopeEffectsController {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	return &ScopeEffectsController{svc: svc, interval: interval, logger: log}
}

// Name returns the controller name.
func (c *ScopeEffectsController) Name() string { return "scope-effects" }

// Interval returns how often the reconcile runs.
func (c *ScopeEffectsController) Interval() time.Duration { return c.interval }

// Reconcile runs one pass over every organization.
func (c *ScopeEffectsController) Reconcile(ctx context.Context) (int, error) {
	n, err := c.svc.ReconcileAll(ctx)
	if err != nil {
		return 0, err
	}
	if n > 0 && c.logger != nil {
		c.logger.Info("findings moved by scope effects", "findings", n)
	}
	return n, nil
}
