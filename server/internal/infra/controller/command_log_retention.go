package controller

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/logger"
)

// CommandLogRetentionStore is the part of the command log repository the
// retention controller needs.
type CommandLogRetentionStore interface {
	DeleteOlderThan(ctx context.Context, before time.Time, limit int) (int64, error)
}

// CommandLogRetentionController deletes per-task sensor logs (command_logs,
// RFC-029 §4.4.1) older than the retention window: operational data, kept
// 14 days, not evidence.
type CommandLogRetentionController struct {
	repo      CommandLogRetentionStore
	retention time.Duration
	logger    *logger.Logger
	now       func() time.Time
}

// Batches of one run: at most commandLogMaxBatches deletes of
// commandLogBatchSize rows.
const (
	commandLogBatchSize  = 5000
	commandLogMaxBatches = 20
)

// NewCommandLogRetentionController builds the controller; retention <= 0
// means 14 days.
func NewCommandLogRetentionController(repo CommandLogRetentionStore, retention time.Duration, log *logger.Logger) *CommandLogRetentionController {
	if retention <= 0 {
		retention = 14 * 24 * time.Hour
	}
	if log == nil {
		log = logger.NewNop()
	}
	return &CommandLogRetentionController{repo: repo, retention: retention, logger: log, now: time.Now}
}

// Name returns the controller name.
func (c *CommandLogRetentionController) Name() string { return "command-log-retention" }

// Interval returns the reconciliation interval.
func (c *CommandLogRetentionController) Interval() time.Duration { return time.Hour }

// Reconcile deletes log batches older than the retention window, in batches.
func (c *CommandLogRetentionController) Reconcile(ctx context.Context) (int, error) {
	cutoff := c.now().Add(-c.retention)
	var total int64
	for i := 0; i < commandLogMaxBatches; i++ {
		n, err := c.repo.DeleteOlderThan(ctx, cutoff, commandLogBatchSize)
		if err != nil {
			c.logger.Error("failed to delete old command logs", "error", err, "cutoff", cutoff)
			return int(total), err
		}
		total += n
		if n < commandLogBatchSize {
			break
		}
	}
	if total > 0 {
		c.logger.Info("deleted old command logs", "count", total, "cutoff", cutoff)
	}
	return int(total), nil
}

// Exclusive: one API replica at a time (controller lease, RFC-046 P1.8).
func (c *CommandLogRetentionController) Exclusive() bool { return true }
