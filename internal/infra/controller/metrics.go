package controller

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// PrometheusMetrics implements the Metrics interface using Prometheus.
type PrometheusMetrics struct {
	reconcileTotal    *prometheus.CounterVec
	reconcileErrors   *prometheus.CounterVec
	reconcileDuration *prometheus.HistogramVec
	itemsProcessed    *prometheus.CounterVec
	controllerRunning *prometheus.GaugeVec
	lastReconcileTime *prometheus.GaugeVec
}

// NewPrometheusMetrics creates a new PrometheusMetrics.
func NewPrometheusMetrics(namespace string) *PrometheusMetrics {
	if namespace == "" {
		namespace = "exploop"
	}

	return &PrometheusMetrics{
		reconcileTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: "controller",
				Name:      "reconcile_total",
				Help:      "Total number of reconciliations by controller",
			},
			[]string{"controller", "result"},
		),

		reconcileErrors: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: "controller",
				Name:      "reconcile_errors_total",
				Help:      "Total number of reconciliation errors by controller",
			},
			[]string{"controller"},
		),

		reconcileDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Subsystem: "controller",
				Name:      "reconcile_duration_seconds",
				Help:      "Duration of reconciliation in seconds",
				Buckets:   []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5, 10, 30, 60},
			},
			[]string{"controller"},
		),

		itemsProcessed: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: "controller",
				Name:      "items_processed_total",
				Help:      "Total number of items processed by controller",
			},
			[]string{"controller"},
		),

		controllerRunning: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Subsystem: "controller",
				Name:      "running",
				Help:      "Whether the controller is running (1) or not (0)",
			},
			[]string{"controller"},
		),

		lastReconcileTime: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Subsystem: "controller",
				Name:      "last_reconcile_timestamp_seconds",
				Help:      "Unix timestamp of the last reconciliation",
			},
			[]string{"controller"},
		),
	}
}

// RecordReconcile records a reconciliation run.
func (m *PrometheusMetrics) RecordReconcile(controller string, itemsProcessed int, duration time.Duration, err error) {
	result := "success"
	if err != nil {
		result = "error"
	}

	m.reconcileTotal.WithLabelValues(controller, result).Inc()
	m.reconcileDuration.WithLabelValues(controller).Observe(duration.Seconds())

	if itemsProcessed > 0 {
		m.itemsProcessed.WithLabelValues(controller).Add(float64(itemsProcessed))
	}
}

// SetControllerRunning sets whether a controller is running.
func (m *PrometheusMetrics) SetControllerRunning(controller string, running bool) {
	val := 0.0
	if running {
		val = 1.0
	}
	m.controllerRunning.WithLabelValues(controller).Set(val)
}

// IncrementReconcileErrors increments the error counter.
func (m *PrometheusMetrics) IncrementReconcileErrors(controller string) {
	m.reconcileErrors.WithLabelValues(controller).Inc()
}

// SetLastReconcileTime sets the last reconcile timestamp.
func (m *PrometheusMetrics) SetLastReconcileTime(controller string, t time.Time) {
	m.lastReconcileTime.WithLabelValues(controller).Set(float64(t.Unix()))
}

// Ensure PrometheusMetrics implements Metrics interface
var _ Metrics = (*PrometheusMetrics)(nil)

// NoopMetrics is a no-op implementation of Metrics for testing.
type NoopMetrics struct{}

// RecordReconcile does nothing.
func (m *NoopMetrics) RecordReconcile(controller string, itemsProcessed int, duration time.Duration, err error) {
}

// SetControllerRunning does nothing.
func (m *NoopMetrics) SetControllerRunning(controller string, running bool) {}

// IncrementReconcileErrors does nothing.
func (m *NoopMetrics) IncrementReconcileErrors(controller string) {}

// SetLastReconcileTime does nothing.
func (m *NoopMetrics) SetLastReconcileTime(controller string, t time.Time) {}

// Ensure NoopMetrics implements Metrics interface
var _ Metrics = (*NoopMetrics)(nil)
