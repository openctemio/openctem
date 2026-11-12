package logger

import (
	"context"
	"log/slog"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

var (
	// logsDroppedTotal counts logs dropped by sampling
	logsDroppedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "openctem",
			Subsystem: "logger",
			Name:      "logs_dropped_total",
			Help:      "Total number of logs dropped by sampling",
		},
		[]string{"level"},
	)

	// logsProcessedTotal counts all logs processed (before sampling)
	logsProcessedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "openctem",
			Subsystem: "logger",
			Name:      "logs_processed_total",
			Help:      "Total number of logs processed (before sampling)",
		},
		[]string{"level"},
	)

	// samplingCounterSize tracks the number of unique log keys in the sampling counter
	samplingCounterSize = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "openctem",
			Subsystem: "logger",
			Name:      "sampling_counter_size",
			Help:      "Number of unique log message keys in the sampling counter",
		},
	)

	// registerOnce ensures metrics are only registered once
	registerOnce sync.Once
)

// RegisterMetrics registers logger metrics with the given registry.
// If registry is nil, uses the default prometheus registry.
// This function is safe to call multiple times.
func RegisterMetrics(registry prometheus.Registerer) {
	registerOnce.Do(func() {
		if registry == nil {
			registry = prometheus.DefaultRegisterer
		}

		// Use MustRegister with a wrapper to handle already-registered errors gracefully
		collectors := []prometheus.Collector{
			logsDroppedTotal,
			logsProcessedTotal,
			samplingCounterSize,
		}

		for _, c := range collectors {
			// Try to register, ignore if already registered
			_ = registry.Register(c)
		}
	})
}

// MetricsOnDropped returns an OnDropped callback that increments Prometheus metrics.
// Use this with SamplingConfig.OnDropped to track dropped logs.
func MetricsOnDropped() func(context.Context, slog.Record) {
	return func(ctx context.Context, r slog.Record) {
		level := levelToString(r.Level)
		logsDroppedTotal.WithLabelValues(level).Inc()
	}
}

// MetricsOnProcessed returns a function to call when a log is processed.
// This should be called for every log, before sampling decision.
func MetricsOnProcessed(level slog.Level) {
	logsProcessedTotal.WithLabelValues(levelToString(level)).Inc()
}

// SetSamplingCounterSize sets the current size of the sampling counter.
// Call this periodically (e.g., in maybeResetCounters) to track memory usage.
func SetSamplingCounterSize(size int) {
	samplingCounterSize.Set(float64(size))
}

func levelToString(level slog.Level) string {
	switch {
	case level >= slog.LevelError:
		return "error"
	case level >= slog.LevelWarn:
		return "warn"
	case level >= slog.LevelInfo:
		return "info"
	default:
		return "debug"
	}
}

// GetDroppedTotal returns the current dropped logs count for a level.
// Useful for testing. In production, use the /metrics endpoint instead.
func GetDroppedTotal(level string) float64 {
	m, err := logsDroppedTotal.GetMetricWithLabelValues(level)
	if err != nil {
		return 0
	}

	var metric dto.Metric
	if err := m.Write(&metric); err != nil {
		return 0
	}

	if metric.Counter != nil {
		return metric.Counter.GetValue()
	}
	return 0
}
