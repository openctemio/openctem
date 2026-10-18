package controller

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/logger"
)

// SignupEventPurger deletes sign-up events past their retention
// (signupevent.Service).
type SignupEventPurger interface {
	Purge(ctx context.Context) (int64, error)
}

// SignupEventRetentionController deletes sign-up events older than 90 days
// (data minimisation; docs/architecture/signup-activity.md). It runs on one
// replica.
type SignupEventRetentionController struct {
	purger   SignupEventPurger
	interval time.Duration
	logger   *logger.Logger
}

// NewSignupEventRetentionController creates the controller (hourly).
func NewSignupEventRetentionController(p SignupEventPurger, log *logger.Logger) *SignupEventRetentionController {
	if log == nil {
		log = logger.NewNop()
	}
	return &SignupEventRetentionController{purger: p, interval: time.Hour, logger: log}
}

// Name returns the controller name.
func (c *SignupEventRetentionController) Name() string { return "signup-event-retention" }

// Interval returns the reconciliation interval.
func (c *SignupEventRetentionController) Interval() time.Duration { return c.interval }

// Exclusive runs the sweep on one replica only.
func (c *SignupEventRetentionController) Exclusive() bool { return true }

// Reconcile deletes expired events.
func (c *SignupEventRetentionController) Reconcile(ctx context.Context) (int, error) {
	if c.purger == nil {
		return 0, nil
	}
	n, err := c.purger.Purge(ctx)
	if err != nil {
		c.logger.Error("sign-up event retention failed", "error", err)
		return 0, err
	}
	if n > 0 {
		c.logger.Info("sign-up events purged", "count", n)
	}
	return int(n), nil
}
