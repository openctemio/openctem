package controller

import (
	"context"
	"time"
)

// OneOffScanArchiveInterval is how often never-run one-off scans are archived.
const OneOffScanArchiveInterval = 6 * time.Hour

// OneOffScanArchiver archives never-run one-off scans
// (scan.Service.ArchiveStaleOneOffScans).
type OneOffScanArchiver interface {
	ArchiveStaleOneOffScans(ctx context.Context, olderThan time.Duration) (int, error)
}

// OneOffScanArchiveController archives one-off (ad-hoc) scans that never ran
// once they are older than the threshold, on one replica at a time.
type OneOffScanArchiveController struct {
	archiver  OneOffScanArchiver
	interval  time.Duration
	olderThan time.Duration
}

// NewOneOffScanArchiveController creates the controller; interval <= 0 uses
// OneOffScanArchiveInterval, olderThan <= 0 the service default.
func NewOneOffScanArchiveController(a OneOffScanArchiver, interval, olderThan time.Duration) *OneOffScanArchiveController {
	if interval <= 0 {
		interval = OneOffScanArchiveInterval
	}
	return &OneOffScanArchiveController{archiver: a, interval: interval, olderThan: olderThan}
}

// Name implements Controller.
func (c *OneOffScanArchiveController) Name() string { return "one-off-scan-archive" }

// Interval implements Controller.
func (c *OneOffScanArchiveController) Interval() time.Duration { return c.interval }

// Exclusive implements Exclusive: one replica archives.
func (c *OneOffScanArchiveController) Exclusive() bool { return true }

// Reconcile implements Controller.
func (c *OneOffScanArchiveController) Reconcile(ctx context.Context) (int, error) {
	return c.archiver.ArchiveStaleOneOffScans(ctx, c.olderThan)
}
