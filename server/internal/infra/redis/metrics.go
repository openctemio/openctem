package redis

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics holds all Redis-related Prometheus metrics.
type Metrics struct {
	// Operations
	operationDuration *prometheus.HistogramVec
	operationTotal    *prometheus.CounterVec
	operationErrors   *prometheus.CounterVec

	// Connection pool
	poolHits       prometheus.Gauge
	poolMisses     prometheus.Gauge
	poolTimeouts   prometheus.Gauge
	poolTotalConns prometheus.Gauge
	poolIdleConns  prometheus.Gauge
	poolStaleConns prometheus.Gauge

	// Cache specific
	cacheHits   *prometheus.CounterVec
	cacheMisses *prometheus.CounterVec

	// Rate limiter specific
	rateLimitAllowed *prometheus.CounterVec
	rateLimitDenied  *prometheus.CounterVec
}

// DefaultMetrics is the default metrics instance.
var DefaultMetrics *Metrics

func init() {
	DefaultMetrics = NewMetrics("openctem")
}

// NewMetrics creates a new Metrics instance with the given namespace.
func NewMetrics(namespace string) *Metrics {
	m := &Metrics{}
	m.initOperationMetrics(namespace)
	m.initPoolMetrics(namespace)
	m.initCacheMetrics(namespace)
	m.initRateLimitMetrics(namespace)
	return m
}

func (m *Metrics) initOperationMetrics(namespace string) {
	m.operationDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: "redis",
			Name:      "operation_duration_seconds",
			Help:      "Duration of Redis operations in seconds",
			Buckets:   []float64{.0001, .0005, .001, .005, .01, .025, .05, .1, .25, .5, 1},
		},
		[]string{"operation"},
	)
	m.operationTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "redis",
			Name:      "operations_total",
			Help:      "Total number of Redis operations",
		},
		[]string{"operation"},
	)
	m.operationErrors = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "redis",
			Name:      "operation_errors_total",
			Help:      "Total number of Redis operation errors",
		},
		[]string{"operation"},
	)
}

func (m *Metrics) initPoolMetrics(namespace string) {
	m.poolHits = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: "redis",
		Name:      "pool_hits_total",
		Help:      "Number of times a free connection was found in the pool",
	})
	m.poolMisses = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: "redis",
		Name:      "pool_misses_total",
		Help:      "Number of times a free connection was NOT found in the pool",
	})
	m.poolTimeouts = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: "redis",
		Name:      "pool_timeouts_total",
		Help:      "Number of times a wait for a connection timed out",
	})
	m.poolTotalConns = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: "redis",
		Name:      "pool_total_connections",
		Help:      "Number of total connections in the pool",
	})
	m.poolIdleConns = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: "redis",
		Name:      "pool_idle_connections",
		Help:      "Number of idle connections in the pool",
	})
	m.poolStaleConns = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: "redis",
		Name:      "pool_stale_connections",
		Help:      "Number of stale connections removed from the pool",
	})
}

func (m *Metrics) initCacheMetrics(namespace string) {
	m.cacheHits = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "redis",
			Name:      "cache_hits_total",
			Help:      "Total number of cache hits",
		},
		[]string{"cache"},
	)
	m.cacheMisses = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "redis",
			Name:      "cache_misses_total",
			Help:      "Total number of cache misses",
		},
		[]string{"cache"},
	)
}

func (m *Metrics) initRateLimitMetrics(namespace string) {
	m.rateLimitAllowed = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "redis",
			Name:      "ratelimit_allowed_total",
			Help:      "Total number of requests allowed by rate limiter",
		},
		[]string{"limiter"},
	)
	m.rateLimitDenied = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "redis",
			Name:      "ratelimit_denied_total",
			Help:      "Total number of requests denied by rate limiter",
		},
		[]string{"limiter"},
	)
}

// ObserveOperation records the duration and result of a Redis operation.
func (m *Metrics) ObserveOperation(operation string, duration time.Duration, err error) {
	m.operationDuration.WithLabelValues(operation).Observe(duration.Seconds())
	m.operationTotal.WithLabelValues(operation).Inc()
	if err != nil {
		m.operationErrors.WithLabelValues(operation).Inc()
	}
}

// RecordCacheHit records a cache hit for the given cache name.
func (m *Metrics) RecordCacheHit(cacheName string) {
	m.cacheHits.WithLabelValues(cacheName).Inc()
}

// RecordCacheMiss records a cache miss for the given cache name.
func (m *Metrics) RecordCacheMiss(cacheName string) {
	m.cacheMisses.WithLabelValues(cacheName).Inc()
}

// RecordRateLimitResult records the result of a rate limit check.
func (m *Metrics) RecordRateLimitResult(limiterName string, allowed bool) {
	if allowed {
		m.rateLimitAllowed.WithLabelValues(limiterName).Inc()
	} else {
		m.rateLimitDenied.WithLabelValues(limiterName).Inc()
	}
}

// UpdatePoolStats updates the connection pool metrics from the client.
func (m *Metrics) UpdatePoolStats(client *Client) {
	if client == nil {
		return
	}

	stats := client.PoolStats()
	if stats == nil {
		return
	}

	m.poolHits.Set(float64(stats.Hits))
	m.poolMisses.Set(float64(stats.Misses))
	m.poolTimeouts.Set(float64(stats.Timeouts))
	m.poolTotalConns.Set(float64(stats.TotalConns))
	m.poolIdleConns.Set(float64(stats.IdleConns))
	m.poolStaleConns.Set(float64(stats.StaleConns))
}

// MetricsCollector implements prometheus.Collector for Redis pool stats.
type MetricsCollector struct {
	client  *Client
	metrics *Metrics
}

// NewMetricsCollector creates a new MetricsCollector.
func NewMetricsCollector(client *Client, metrics *Metrics) *MetricsCollector {
	if metrics == nil {
		metrics = DefaultMetrics
	}
	return &MetricsCollector{
		client:  client,
		metrics: metrics,
	}
}

// Describe implements prometheus.Collector.
func (c *MetricsCollector) Describe(_ chan<- *prometheus.Desc) {
	// Pool metrics are already registered via promauto
}

// Collect implements prometheus.Collector.
func (c *MetricsCollector) Collect(_ chan<- prometheus.Metric) {
	c.metrics.UpdatePoolStats(c.client)
}

// StartPoolStatsCollector starts a goroutine that periodically updates pool stats.
// Returns a cancel function to stop the collector.
func StartPoolStatsCollector(ctx context.Context, client *Client, interval time.Duration) func() {
	if interval <= 0 {
		interval = 15 * time.Second
	}

	ctx, cancel := context.WithCancel(ctx)

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				DefaultMetrics.UpdatePoolStats(client)
			}
		}
	}()

	return cancel
}

// Timed is a helper to time operations. Use with defer:
//
//	done := redis.Timed("get")
//	result, err := cache.Get(ctx, key)
//	done(err)
func Timed(operation string) func(error) {
	start := time.Now()
	return func(err error) {
		DefaultMetrics.ObserveOperation(operation, time.Since(start), err)
	}
}
