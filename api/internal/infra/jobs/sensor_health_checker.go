package jobs

import (
	"context"
	"sync"
	"time"

	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/telemetry"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// SensorHealthChecker periodically checks for stale sensors and marks them as offline (health).
// Note: This updates Health (automatic), not Status (admin-controlled).
// Sensors can still authenticate if their Status is 'active', regardless of Health.
type SensorHealthChecker struct {
	sensorRepo sensor.Repository
	config     *config.SensorConfig
	logger     *logger.Logger
	stopCh     chan struct{}
	wg         sync.WaitGroup
	// lastLegacyKeys is the legacy rda_ key count logged last (-1 = none
	// yet), so the count is logged when it changes, not on every pass.
	lastLegacyKeys int64
}

// NewSensorHealthChecker creates a new SensorHealthChecker.
func NewSensorHealthChecker(sensorRepo sensor.Repository, cfg *config.SensorConfig, log *logger.Logger) *SensorHealthChecker {
	return &SensorHealthChecker{
		sensorRepo:     sensorRepo,
		config:         cfg,
		logger:         log.With("component", "sensor-health-checker"),
		stopCh:         make(chan struct{}),
		lastLegacyKeys: -1,
	}
}

// Start starts the health checker in a background goroutine.
func (c *SensorHealthChecker) Start() {
	if !c.config.Enabled {
		c.logger.Info("sensor health checker is disabled")
		return
	}

	c.logger.Info("starting sensor health checker",
		"heartbeat_timeout", c.config.HeartbeatTimeout,
		"check_interval", c.config.HealthCheckInterval,
	)

	c.wg.Add(1)
	go c.run()
}

// Stop stops the health checker gracefully.
func (c *SensorHealthChecker) Stop() {
	c.logger.Info("stopping sensor health checker")
	close(c.stopCh)
	c.wg.Wait()
	c.logger.Info("sensor health checker stopped")
}

func (c *SensorHealthChecker) run() {
	defer c.wg.Done()

	ticker := time.NewTicker(c.config.HealthCheckInterval)
	defer ticker.Stop()

	// Run immediately on start
	c.checkStaleSensors()
	c.countLegacyKeys()

	for {
		select {
		case <-ticker.C:
			c.checkStaleSensors()
			c.countLegacyKeys()
		case <-c.stopCh:
			return
		}
	}
}

func (c *SensorHealthChecker) checkStaleSensors() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	count, err := c.sensorRepo.MarkStaleAsOffline(ctx, c.config.HeartbeatTimeout)
	if err != nil {
		c.logger.Error("failed to mark stale sensors as offline", "error", err)
		return
	}

	if count > 0 {
		c.logger.Info("marked stale sensors as offline (health)",
			"count", count,
			"timeout", c.config.HeartbeatTimeout,
		)
	}
}

// countLegacyKeys publishes how many sensors are still on a legacy rda_ key
// (openctem_sensor_legacy_keys) and logs the count when it changes. A sensor
// moves to an octs_ key on its next renewal; the count has to reach zero
// before the rda_ sunset.
func (c *SensorHealthChecker) countLegacyKeys() {
	counter, ok := c.sensorRepo.(sensor.LegacyKeyCounter)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	n, err := counter.CountLegacyKeySensors(ctx)
	if err != nil {
		c.logger.Warn("failed to count sensors on legacy rda_ keys", "error", err)
		return
	}
	telemetry.SetSensorLegacyKeys(n)
	if n != c.lastLegacyKeys {
		c.logger.Info("sensors on legacy rda_ keys (they move to octs_ on renewal)", "count", n)
		c.lastLegacyKeys = n
	}
}
