package controller

import (
	"context"
	"time"
)

// ScopeJoinReevaluator re-evaluates every tenant's pending automatic
// attribution records against its permanent scope targets and seeds
// (*easm.ScopeJoin).
type ScopeJoinReevaluator interface {
	ReevaluateAll(ctx context.Context) (int, error)
}

// ScopeJoinController confirms discovered names a scope target or seed of the
// tenant now covers (RFC-054 §4.3). It runs once at start-up, which is the
// backfill of records written before the rule existed, and then on an
// interval as a safety net; scope-target changes trigger a tenant run of
// their own. Idempotent: a confirmed record is no longer pending.
type ScopeJoinController struct {
	join     ScopeJoinReevaluator
	interval time.Duration
}

// NewScopeJoinController creates the controller. interval 0 = 6 h.
func NewScopeJoinController(join ScopeJoinReevaluator, interval time.Duration) *ScopeJoinController {
	if interval <= 0 {
		interval = 6 * time.Hour
	}
	return &ScopeJoinController{join: join, interval: interval}
}

// Name implements Controller.
func (c *ScopeJoinController) Name() string { return "scope-join" }

// Interval implements Controller.
func (c *ScopeJoinController) Interval() time.Duration { return c.interval }

// Reconcile implements Controller: the number of names confirmed.
func (c *ScopeJoinController) Reconcile(ctx context.Context) (int, error) {
	if c.join == nil {
		return 0, nil
	}
	return c.join.ReevaluateAll(ctx)
}
