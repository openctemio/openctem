package controller

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/logger"
)

// SSOEnforcementSweeper turns SSO enforcement off for organizations that may
// no longer use it and whose grace ended.
type SSOEnforcementSweeper interface {
	SweepDeniedSSOEnforcement(ctx context.Context) (int, error)
}

// SSOEnforcementEntitlementController runs that sweep.
type SSOEnforcementEntitlementController struct {
	sweeper  SSOEnforcementSweeper
	interval time.Duration
	logger   *logger.Logger
}

// NewSSOEnforcementEntitlementController creates the controller (default
// interval 1h).
func NewSSOEnforcementEntitlementController(s SSOEnforcementSweeper, interval time.Duration, log *logger.Logger) *SSOEnforcementEntitlementController {
	if interval <= 0 {
		interval = time.Hour
	}
	if log == nil {
		log = logger.NewNop()
	}
	return &SSOEnforcementEntitlementController{sweeper: s, interval: interval, logger: log}
}

// Name returns the controller name.
func (c *SSOEnforcementEntitlementController) Name() string { return "sso-enforcement-entitlement" }

// Interval returns the reconciliation interval.
func (c *SSOEnforcementEntitlementController) Interval() time.Duration { return c.interval }

// Reconcile turns enforcement off where the organization lost it after the grace.
func (c *SSOEnforcementEntitlementController) Reconcile(ctx context.Context) (int, error) {
	if c.sweeper == nil {
		return 0, nil
	}
	n, err := c.sweeper.SweepDeniedSSOEnforcement(ctx)
	if err != nil {
		c.logger.Error("sso enforcement entitlement sweep failed", "error", err)
		return 0, err
	}
	if n > 0 {
		c.logger.Info("sso enforcement turned off after a limits change", "organizations", n)
	}
	return n, nil
}
