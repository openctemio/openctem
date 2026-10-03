package telemetry

// Sensor heartbeat gap metrics (docs/rfcs/RFC-035-sensor-control-plane-under-load.md
// §5.5, docs/architecture/sensors.md "Control plane under load"). One
// observation per heartbeat that had a previous one, with no labels: the
// fleet's distribution, at a fixed cardinality whatever the number of
// sensors. Per-sensor detail is the sensor's heartbeat history (the
// Control channel sparkline) and its health reasons.

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	sensorHeartbeatGap = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "sensor_heartbeat_gap_seconds",
		Help:    "Time between two heartbeats of a sensor, as the platform saw them.",
		Buckets: []float64{5, 10, 15, 20, 30, 45, 60, 90, 120, 180, 300, 600, 1800},
	})
	sensorHeartbeatGapRatio = promauto.NewHistogram(prometheus.HistogramOpts{
		Name: "sensor_heartbeat_gap_ratio",
		Help: "Time between two heartbeats of a sensor divided by the interval it was following " +
			"(1 = on time; above 1 + grace the sensor was late).",
		Buckets: []float64{0.5, 0.9, 1, 1.1, 1.25, 1.5, 2, 3, 5, 10},
	})
)

// SensorHeartbeatMetrics records heartbeat gaps; it implements the sensor
// service's HeartbeatGapObserver.
type SensorHeartbeatMetrics struct{}

// ObserveHeartbeatGap records one heartbeat's gap and, when the interval it
// followed is known, the gap relative to it.
func (SensorHeartbeatMetrics) ObserveHeartbeatGap(gap, interval time.Duration) {
	if gap <= 0 {
		return
	}
	sensorHeartbeatGap.Observe(gap.Seconds())
	if interval > 0 {
		sensorHeartbeatGapRatio.Observe(gap.Seconds() / interval.Seconds())
	}
}
