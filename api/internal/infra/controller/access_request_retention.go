package controller

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/logger"
)

// AccessRequestPurger deletes expired access requests (accessrequest.Service).
type AccessRequestPurger interface {
	Purge(ctx context.Context) (int64, error)
}

// AccessRequestRetentionController applies the access-request retention:
// unconfirmed requests go after 24 hours, decided ones after 90 days (data
// minimisation; docs/architecture/user-onboarding.md, "Request access").
type AccessRequestRetentionController struct {
	purger   AccessRequestPurger
	interval time.Duration
	logger   *logger.Logger
}

// NewAccessRequestRetentionController creates the controller (hourly).
func NewAccessRequestRetentionController(p AccessRequestPurger, log *logger.Logger) *AccessRequestRetentionController {
	if log == nil {
		log = logger.NewNop()
	}
	return &AccessRequestRetentionController{purger: p, interval: time.Hour, logger: log}
}

// Name returns the controller name.
func (c *AccessRequestRetentionController) Name() string { return "access-request-retention" }

// Interval returns the reconciliation interval.
func (c *AccessRequestRetentionController) Interval() time.Duration { return c.interval }

// Reconcile deletes expired requests.
func (c *AccessRequestRetentionController) Reconcile(ctx context.Context) (int, error) {
	if c.purger == nil {
		return 0, nil
	}
	n, err := c.purger.Purge(ctx)
	if err != nil {
		c.logger.Error("access request retention failed", "error", err)
		return 0, err
	}
	if n > 0 {
		c.logger.Info("access requests purged", "count", n)
	}
	return int(n), nil
}
