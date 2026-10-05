package controller

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// HeartbeatHistoryRetentionStore is the part of the heartbeat history
// repository the retention controller needs.
type HeartbeatHistoryRetentionStore interface {
	DeleteHeartbeatHistoryBefore(ctx context.Context, before time.Time, limit int) (int64, error)
}

// HeartbeatHistoryRetentionController deletes heartbeat history buckets
// older than sensor.HeartbeatHistoryRetention, so the history stays at
// about 192 rows per sensor (RFC-035 §5.5).
type HeartbeatHistoryRetentionController struct {
	repo       HeartbeatHistoryRetentionStore
	interval   time.Duration
	batchSize  int
	maxBatches int
	logger     *logger.Logger
	now        func() time.Time
}

// NewHeartbeatHistoryRetentionController builds the controller: hourly,
// batches of 5000, at most 20 batches a run.
func NewHeartbeatHistoryRetentionController(repo HeartbeatHistoryRetentionStore, log *logger.Logger) *HeartbeatHistoryRetentionController {
	if log == nil {
		log = logger.NewNop()
	}
	return &HeartbeatHistoryRetentionController{repo: repo, interval: time.Hour, batchSize: 5000, maxBatches: 20, logger: log, now: time.Now}
}

// Name returns the controller name.
func (c *HeartbeatHistoryRetentionController) Name() string {
	return "sensor-heartbeat-history-retention"
}

// Interval returns the reconciliation interval.
func (c *HeartbeatHistoryRetentionController) Interval() time.Duration { return c.interval }

// Reconcile deletes buckets past the retention window, in batches.
func (c *HeartbeatHistoryRetentionController) Reconcile(ctx context.Context) (int, error) {
	cutoff := c.now().Add(-sensor.HeartbeatHistoryRetention)
	var total int64
	for range c.maxBatches {
		n, err := c.repo.DeleteHeartbeatHistoryBefore(ctx, cutoff, c.batchSize)
		if err != nil {
			c.logger.Error("failed to delete old heartbeat history", "error", err, "cutoff", cutoff)
			return int(total), err
		}
		total += n
		if n < int64(c.batchSize) {
			break
		}
	}
	if total > 0 {
		c.logger.Info("deleted old heartbeat history", "count", total, "cutoff", cutoff)
	}
	return int(total), nil
}

// Exclusive: it runs on one API replica at a time (controller lease, RFC-046
// P1.8); two replicas sweeping at once would delete or fetch twice.
func (c *HeartbeatHistoryRetentionController) Exclusive() bool { return true }
