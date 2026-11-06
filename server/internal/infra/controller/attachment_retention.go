package controller

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/logger"
)

// AttachmentRetentionSweeper purges evidence files the retention periods
// allow (api/docs/architecture/file-storage.md, "Retention").
type AttachmentRetentionSweeper interface {
	SweepRetention(ctx context.Context) (int, error)
}

// AttachmentRetentionController runs the attachment retention sweep: evidence
// whose finding or campaign was deleted is purged after the grace period,
// uploads never linked to one after their retention.
type AttachmentRetentionController struct {
	sweeper  AttachmentRetentionSweeper
	interval time.Duration
	logger   *logger.Logger
}

// NewAttachmentRetentionController builds the controller (interval 0 = 1 h).
func NewAttachmentRetentionController(s AttachmentRetentionSweeper, interval time.Duration, log *logger.Logger) *AttachmentRetentionController {
	if interval <= 0 {
		interval = time.Hour
	}
	if log == nil {
		log = logger.NewNop()
	}
	return &AttachmentRetentionController{sweeper: s, interval: interval, logger: log}
}

// Name returns the controller name.
func (c *AttachmentRetentionController) Name() string { return "attachment-retention" }

// Interval returns the reconciliation interval.
func (c *AttachmentRetentionController) Interval() time.Duration { return c.interval }

// Exclusive: one replica deletes files at a time.
func (c *AttachmentRetentionController) Exclusive() bool { return true }

// ReconcileTimeout gives a sweep (a database pass and up to one batch of
// storage deletes) more than the tick interval would.
func (c *AttachmentRetentionController) ReconcileTimeout() time.Duration { return 15 * time.Minute }

// Reconcile runs one sweep.
func (c *AttachmentRetentionController) Reconcile(ctx context.Context) (int, error) {
	n, err := c.sweeper.SweepRetention(ctx)
	if err != nil {
		c.logger.Error("attachment retention sweep failed", "error", logger.SanitizeError(err))
		return n, err
	}
	return n, nil
}
