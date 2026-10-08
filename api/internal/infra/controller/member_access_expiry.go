package controller

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/logger"
)

// MemberAccessExpirer suspends memberships whose access end date passed
// (TenantService.ExpireMemberships).
type MemberAccessExpirer interface {
	ExpireMemberships(ctx context.Context, now time.Time, batch int) (int, error)
}

// MemberAccessExpiryController suspends external members whose access ended
// (RFC-058), each in its own organization only.
type MemberAccessExpiryController struct {
	service  MemberAccessExpirer
	interval time.Duration
	batch    int
	logger   *logger.Logger
}

// NewMemberAccessExpiryController creates the controller.
func NewMemberAccessExpiryController(service MemberAccessExpirer, interval time.Duration, batch int, log *logger.Logger) *MemberAccessExpiryController {
	if interval <= 0 {
		interval = time.Minute
	}
	if batch <= 0 {
		batch = 200
	}
	if log == nil {
		log = logger.NewNop()
	}
	return &MemberAccessExpiryController{service: service, interval: interval, batch: batch, logger: log}
}

// Name returns the controller name.
func (c *MemberAccessExpiryController) Name() string { return "member-access-expiry" }

// Interval returns the reconciliation interval.
func (c *MemberAccessExpiryController) Interval() time.Duration { return c.interval }

// Reconcile suspends the memberships whose access expired.
func (c *MemberAccessExpiryController) Reconcile(ctx context.Context) (int, error) {
	if c.service == nil {
		return 0, nil
	}
	n, err := c.service.ExpireMemberships(ctx, time.Now().UTC(), c.batch)
	if err != nil {
		c.logger.Error("member access expiry sweep failed", "error", err)
		return 0, err
	}
	if n > 0 {
		c.logger.Info("suspended members whose access expired", "count", n)
	}
	return n, nil
}
