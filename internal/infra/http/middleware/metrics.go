package middleware

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	httpRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "path", "status"},
	)

	httpRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "HTTP request duration in seconds",
			Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
		},
		[]string{"method", "path"},
	)

	httpRequestsInFlight = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "http_requests_in_flight",
			Help: "Number of HTTP requests currently being processed",
		},
	)

	httpResponseSize = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_response_size_bytes",
			Help:    "HTTP response size in bytes",
			Buckets: []float64{100, 1000, 10000, 100000, 1000000},
		},
		[]string{"method", "path"},
	)

	// ==========================================================================
	// Security Metrics for Platform Agents
	// ==========================================================================

	// SecurityEventsTotal counts security events by type
	SecurityEventsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "security_events_total",
			Help: "Total number of security events",
		},
		[]string{"event_type"},
	)

	// AuthFailuresTotal counts authentication failures by type
	AuthFailuresTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "auth_failures_total",
			Help: "Total number of authentication failures",
		},
		[]string{"reason"},
	)

	// BannedIPsGauge tracks currently banned IPs
	BannedIPsGauge = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "banned_ips_current",
			Help: "Current number of banned IPs due to auth failures",
		},
	)

	// PlatformJobsSubmitted counts platform jobs submitted
	PlatformJobsSubmitted = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "platform_jobs_submitted_total",
			Help: "Total number of platform jobs submitted",
		},
		[]string{"type", "status"},
	)

	// PlatformAgentsActive tracks active platform agents
	PlatformAgentsActive = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "platform_agents_active",
			Help: "Current number of active platform agents",
		},
	)

	// JobValidationFailures counts job validation failures by reason
	JobValidationFailures = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "job_validation_failures_total",
			Help: "Total number of job validation failures",
		},
		[]string{"reason"},
	)
)

// RecordSecurityEvent increments the security event counter.
func RecordSecurityEvent(eventType string) {
	SecurityEventsTotal.WithLabelValues(eventType).Inc()
}

// RecordAuthFailure increments the auth failure counter.
func RecordAuthFailure(reason string) {
	AuthFailuresTotal.WithLabelValues(reason).Inc()
}

// RecordJobSubmitted increments the job submitted counter.
func RecordJobSubmitted(jobType, status string) {
	PlatformJobsSubmitted.WithLabelValues(jobType, status).Inc()
}

// RecordJobValidationFailure increments the validation failure counter.
func RecordJobValidationFailure(reason string) {
	JobValidationFailures.WithLabelValues(reason).Inc()
}

// metricsResponseWriter wraps http.ResponseWriter to capture metrics.
type metricsResponseWriter struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int
}

func (mrw *metricsResponseWriter) WriteHeader(code int) {
	mrw.statusCode = code
	mrw.ResponseWriter.WriteHeader(code)
}

func (mrw *metricsResponseWriter) Write(b []byte) (int, error) {
	n, err := mrw.ResponseWriter.Write(b)
	mrw.bytesWritten += n
	return n, err
}

// Hijack implements http.Hijacker interface to support WebSocket connections.
func (mrw *metricsResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hijacker, ok := mrw.ResponseWriter.(http.Hijacker); ok {
		return hijacker.Hijack()
	}
	return nil, nil, fmt.Errorf("metricsResponseWriter: underlying ResponseWriter does not implement http.Hijacker")
}

// Metrics returns the Prometheus metrics middleware.
func Metrics() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip metrics endpoint itself
			if r.URL.Path == "/metrics" {
				next.ServeHTTP(w, r)
				return
			}

			start := time.Now()
			httpRequestsInFlight.Inc()

			mrw := &metricsResponseWriter{
				ResponseWriter: w,
				statusCode:     http.StatusOK,
			}

			next.ServeHTTP(mrw, r)

			duration := time.Since(start).Seconds()
			httpRequestsInFlight.Dec()

			// Normalize path for metrics (replace IDs with placeholder)
			path := normalizePath(r.URL.Path)

			httpRequestsTotal.WithLabelValues(
				r.Method,
				path,
				strconv.Itoa(mrw.statusCode),
			).Inc()

			httpRequestDuration.WithLabelValues(
				r.Method,
				path,
			).Observe(duration)

			httpResponseSize.WithLabelValues(
				r.Method,
				path,
			).Observe(float64(mrw.bytesWritten))
		})
	}
}

// normalizePath replaces dynamic path segments with placeholders.
// This prevents high cardinality in metrics labels.
func normalizePath(path string) string {
	// Common patterns: UUIDs, numeric IDs
	// /api/v1/assets/123e4567-e89b-12d3-a456-426614174000 -> /api/v1/assets/{id}
	// /api/v1/users/123 -> /api/v1/users/{id}

	segments := make([]byte, 0, len(path))
	i := 0
	for i < len(path) {
		if path[i] == '/' {
			segments = append(segments, '/')
			i++
			// Check if next segment looks like an ID
			start := i
			for i < len(path) && path[i] != '/' {
				i++
			}
			segment := path[start:i]
			if isID(segment) {
				segments = append(segments, "{id}"...)
			} else {
				segments = append(segments, segment...)
			}
		} else {
			segments = append(segments, path[i])
			i++
		}
	}
	return string(segments)
}

// isID checks if a string looks like an ID (UUID or numeric).
func isID(s string) bool {
	if len(s) == 0 {
		return false
	}

	// Check for UUID pattern (36 chars with dashes)
	if len(s) == 36 {
		dashes := 0
		for _, c := range s {
			if c == '-' {
				dashes++
			} else if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return false
			}
		}
		if dashes == 4 {
			return true
		}
	}

	// Check for numeric ID
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0 && len(s) <= 20 // Reasonable numeric ID length
}
