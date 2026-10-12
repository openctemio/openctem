package controller

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/logger"
)

// TeamMembershipExpiryController removes team (access group) memberships
// whose end date passed (RFC-050 W22). It reuses MemberAccessExpirer: the
// group service removes up to batch memberships per run.
type TeamMembershipExpiryController struct {
	service  MemberAccessExpirer
	interval time.Duration
	batch    int
	logger   *logger.Logger
}

// NewTeamMembershipExpiryController creates the controller.
func NewTeamMembershipExpiryController(service MemberAccessExpirer, interval time.Duration, batch int, log *logger.Logger) *TeamMembershipExpiryController {
	if interval <= 0 {
		interval = time.Minute
	}
	if batch <= 0 {
		batch = 200
	}
	if log == nil {
		log = logger.NewNop()
	}
	return &TeamMembershipExpiryController{service: service, interval: interval, batch: batch, logger: log}
}

// Name returns the controller name.
func (c *TeamMembershipExpiryController) Name() string { return "team-membership-expiry" }

// Interval returns the reconciliation interval.
func (c *TeamMembershipExpiryController) Interval() time.Duration { return c.interval }

// Reconcile removes the team memberships whose end date passed.
func (c *TeamMembershipExpiryController) Reconcile(ctx context.Context) (int, error) {
	if c.service == nil {
		return 0, nil
	}
	n, err := c.service.ExpireMemberships(ctx, time.Now().UTC(), c.batch)
	if err != nil {
		c.logger.Error("team membership expiry sweep failed", "error", err)
		return 0, err
	}
	if n > 0 {
		c.logger.Info("removed team memberships whose end date passed", "count", n)
	}
	return n, nil
}
