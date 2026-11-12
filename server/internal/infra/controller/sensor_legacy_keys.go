package controller

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/internal/infra/telemetry"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// sensorLegacyKeysInterval is how often the legacy key count is refreshed.
const sensorLegacyKeysInterval = 5 * time.Minute

// SensorLegacyKeysController publishes how many sensors still use a legacy
// rda_ key (openctem_sensor_legacy_keys) and logs the count when it changes.
// A sensor moves to an octs_ key on its next renewal; the count has to reach
// zero before the rda_ sunset.
type SensorLegacyKeysController struct {
	counter sensor.LegacyKeyCounter
	logger  *logger.Logger
	last    int64
}

// NewSensorLegacyKeysController builds the controller. repo must implement
// sensor.LegacyKeyCounter; otherwise the controller does nothing.
func NewSensorLegacyKeysController(repo sensor.Repository, log *logger.Logger) *SensorLegacyKeysController {
	counter, _ := repo.(sensor.LegacyKeyCounter)
	if log == nil {
		log = logger.NewNop()
	}
	return &SensorLegacyKeysController{counter: counter, logger: log, last: -1}
}

// Name returns the controller name.
func (c *SensorLegacyKeysController) Name() string { return "sensor-legacy-keys" }

// Interval returns the reconciliation interval.
func (c *SensorLegacyKeysController) Interval() time.Duration { return sensorLegacyKeysInterval }

// Reconcile counts the sensors on a legacy key.
func (c *SensorLegacyKeysController) Reconcile(ctx context.Context) (int, error) {
	if c.counter == nil {
		return 0, nil
	}
	n, err := c.counter.CountLegacyKeySensors(ctx)
	if err != nil {
		c.logger.Warn("failed to count sensors on legacy rda_ keys", "error", err)
		return 0, err
	}
	telemetry.SetSensorLegacyKeys(n)
	if n != c.last {
		c.logger.Info("sensors on legacy rda_ keys (they move to octs_ on renewal)", "count", n)
		c.last = n
	}
	return 0, nil
}
