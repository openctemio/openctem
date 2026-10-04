package controller

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/logger"
)

// SensorEventRetentionStore is the part of the sensor event repository the
// retention controller needs.
type SensorEventRetentionStore interface {
	DeleteOlderThan(ctx context.Context, before time.Time, limit int) (int64, error)
}

// SensorEventRetentionConfig configures SensorEventRetentionController.
type SensorEventRetentionConfig struct {
	// Interval between runs (default 6h).
	Interval time.Duration
	// RetentionDays: events older than this are deleted (default 90).
	RetentionDays int
	// BatchSize bounds one delete statement (default 5000); a run deletes
	// batches until none is full, at most MaxBatches (default 20).
	BatchSize  int
	MaxBatches int
	Logger     *logger.Logger
}

// SensorEventRetentionController deletes sensor activity events
// (sensor_events) past the retention window. They are operational history,
// not compliance evidence: the audit log keeps administrator actions under
// its own retention.
type SensorEventRetentionController struct {
	repo   SensorEventRetentionStore
	config *SensorEventRetentionConfig
	logger *logger.Logger
	now    func() time.Time
}

// NewSensorEventRetentionController builds the controller with defaults for
// zero-valued settings.
func NewSensorEventRetentionController(repo SensorEventRetentionStore, config *SensorEventRetentionConfig) *SensorEventRetentionController {
	if config == nil {
		config = &SensorEventRetentionConfig{}
	}
	if config.Interval <= 0 {
		config.Interval = 6 * time.Hour
	}
	if config.RetentionDays <= 0 {
		config.RetentionDays = 90
	}
	if config.BatchSize <= 0 {
		config.BatchSize = 5000
	}
	if config.MaxBatches <= 0 {
		config.MaxBatches = 20
	}
	if config.Logger == nil {
		config.Logger = logger.NewNop()
	}
	return &SensorEventRetentionController{repo: repo, config: config, logger: config.Logger, now: time.Now}
}

// Name returns the controller name.
func (c *SensorEventRetentionController) Name() string { return "sensor-event-retention" }

// Interval returns the reconciliation interval.
func (c *SensorEventRetentionController) Interval() time.Duration { return c.config.Interval }

// Reconcile deletes events older than the retention window, in batches.
func (c *SensorEventRetentionController) Reconcile(ctx context.Context) (int, error) {
	cutoff := c.now().AddDate(0, 0, -c.config.RetentionDays)
	var total int64
	for i := 0; i < c.config.MaxBatches; i++ {
		n, err := c.repo.DeleteOlderThan(ctx, cutoff, c.config.BatchSize)
		if err != nil {
			c.logger.Error("failed to delete old sensor events", "error", err, "cutoff", cutoff)
			return int(total), err
		}
		total += n
		if n < int64(c.config.BatchSize) {
			break
		}
	}
	if total > 0 {
		c.logger.Info("deleted old sensor events", "count", total, "cutoff", cutoff,
			"retention_days", c.config.RetentionDays)
	}
	return int(total), nil
}

// Exclusive: it runs on one API replica at a time (controller lease, RFC-046
// P1.8); two replicas sweeping at once would delete or fetch twice.
func (c *SensorEventRetentionController) Exclusive() bool { return true }
