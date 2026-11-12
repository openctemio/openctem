package telemetry

// Shared sensor anomaly metrics (docs/rfcs/RFC-100-shared-sensors.md §9).
// Labeled by signal only: aggregate counts at a fixed cardinality, never an
// organization or a target. The organization of an alert is in the admin
// audit log.

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	sharedSensorSignals = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "shared_sensor_signal_events_total",
		Help: "Events counted by the shared sensor anomaly signals (signal: distinct_domains, failures, deny_list_hits).",
	}, []string{"signal"})
	sharedSensorAnomalies = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "shared_sensor_anomalies_total",
		Help: "Organizations that reached a shared sensor anomaly threshold for the day, by signal.",
	}, []string{"signal"})
)

// SharedSensorAnomalyMetrics implements scanpolicy.AnomalyMetrics.
type SharedSensorAnomalyMetrics struct{}

// ObserveSharedSensorSignal adds n events to a signal.
func (SharedSensorAnomalyMetrics) ObserveSharedSensorSignal(signal string, n int) {
	if n > 0 {
		sharedSensorSignals.WithLabelValues(signal).Add(float64(n))
	}
}

// ObserveSharedSensorAnomaly counts one alert of a signal.
func (SharedSensorAnomalyMetrics) ObserveSharedSensorAnomaly(signal string) {
	sharedSensorAnomalies.WithLabelValues(signal).Inc()
}
