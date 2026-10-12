package controller

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/logger"
)

// PurgeFunc deletes records that are past their end of life and returns how
// many it deleted. It must be safe to run again: a second run finds nothing.
type PurgeFunc func(ctx context.Context) (int64, error)

// PurgeController runs one time-based purge on an interval: expired
// invitations, expired platform-admin sessions, reviewed quarantined sensor
// results. Each purge is a single DELETE with a time cutoff, so the
// controller adds only scheduling, logging and the replica lease.
type PurgeController struct {
	name     string
	interval time.Duration
	purge    PurgeFunc
	logger   *logger.Logger
}

// NewPurgeController builds a purge controller; interval <= 0 means one hour.
func NewPurgeController(name string, interval time.Duration, purge PurgeFunc, log *logger.Logger) *PurgeController {
	if interval <= 0 {
		interval = time.Hour
	}
	if log == nil {
		log = logger.NewNop()
	}
	return &PurgeController{name: name, interval: interval, purge: purge, logger: log}
}

// Name returns the controller name.
func (c *PurgeController) Name() string { return c.name }

// Interval returns the reconciliation interval.
func (c *PurgeController) Interval() time.Duration { return c.interval }

// Reconcile runs the purge once.
func (c *PurgeController) Reconcile(ctx context.Context) (int, error) {
	if c.purge == nil {
		return 0, nil
	}
	n, err := c.purge(ctx)
	if err != nil {
		c.logger.Error("purge failed", "error", err)
		return 0, err
	}
	if n > 0 {
		c.logger.Info("purged expired records", "count", n)
	}
	return int(n), nil
}

// Exclusive: one API replica at a time (controller lease, RFC-046 P1.8).
func (c *PurgeController) Exclusive() bool { return true }
