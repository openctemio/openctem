package controller

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/logger"
)

// EventRetentionStore is what an event retention controller needs from its
// repository: delete up to limit rows older than before.
type EventRetentionStore interface {
	DeleteOlderThan(ctx context.Context, before time.Time, limit int) (int64, error)
}

// SensorEventRetentionStore is the part of the sensor event repository the
// retention controller needs.
type SensorEventRetentionStore = EventRetentionStore

// EventRetentionConfig configures an EventRetentionController.
type EventRetentionConfig struct {
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

// SensorEventRetentionConfig configures the sensor event retention.
type SensorEventRetentionConfig = EventRetentionConfig

// CommandEventRetentionConfig configures the command event retention.
type CommandEventRetentionConfig = EventRetentionConfig

// EventRetentionController deletes operational event history past its
// retention window, in batches. Such events are not compliance evidence:
// the audit log keeps administrator actions under its own retention.
type EventRetentionController struct {
	name   string
	what   string
	repo   EventRetentionStore
	config *EventRetentionConfig
	logger *logger.Logger
	now    func() time.Time
}

// NewSensorEventRetentionController deletes sensor activity events
// (sensor_events) past the window (default 90 days).
func NewSensorEventRetentionController(repo EventRetentionStore, config *EventRetentionConfig) *EventRetentionController {
	return newEventRetentionController("sensor-event-retention", "sensor events", 90, repo, config)
}

// NewCommandEventRetentionController deletes command lifecycle events
// (command_events, the run timelines) past the window (default 30 days,
// research/62 P0-4).
func NewCommandEventRetentionController(repo EventRetentionStore, config *EventRetentionConfig) *EventRetentionController {
	return newEventRetentionController("command-event-retention", "command events", 30, repo, config)
}

func newEventRetentionController(name, what string, defaultDays int, repo EventRetentionStore, config *EventRetentionConfig) *EventRetentionController {
	if config == nil {
		config = &EventRetentionConfig{}
	}
	if config.Interval <= 0 {
		config.Interval = 6 * time.Hour
	}
	if config.RetentionDays <= 0 {
		config.RetentionDays = defaultDays
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
	return &EventRetentionController{name: name, what: what, repo: repo, config: config, logger: config.Logger, now: time.Now}
}

// Name returns the controller name.
func (c *EventRetentionController) Name() string { return c.name }

// Interval returns the reconciliation interval.
func (c *EventRetentionController) Interval() time.Duration { return c.config.Interval }

// Reconcile deletes events older than the retention window, in batches.
func (c *EventRetentionController) Reconcile(ctx context.Context) (int, error) {
	cutoff := c.now().AddDate(0, 0, -c.config.RetentionDays)
	var total int64
	for i := 0; i < c.config.MaxBatches; i++ {
		n, err := c.repo.DeleteOlderThan(ctx, cutoff, c.config.BatchSize)
		if err != nil {
			c.logger.Error("failed to delete old "+c.what, "error", err, "cutoff", cutoff)
			return int(total), err
		}
		total += n
		if n < int64(c.config.BatchSize) {
			break
		}
	}
	if total > 0 {
		c.logger.Info("deleted old "+c.what, "count", total, "cutoff", cutoff,
			"retention_days", c.config.RetentionDays)
	}
	return int(total), nil
}

// Exclusive: it runs on one API replica at a time (controller lease, RFC-046
// P1.8); two replicas sweeping at once would delete or fetch twice.
func (c *EventRetentionController) Exclusive() bool { return true }
