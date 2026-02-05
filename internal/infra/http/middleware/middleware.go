package middleware

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/openctemio/api/internal/config"
	"github.com/openctemio/api/pkg/logger"
)

// Use context keys from logger package for consistency.
const (
	RequestIDKey = logger.ContextKeyRequestID
)

// RequestID adds a unique request ID to each request.
func RequestID() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestID := r.Header.Get("X-Request-ID")
			if requestID == "" {
				requestID = uuid.New().String()
			}

			ctx := context.WithValue(r.Context(), RequestIDKey, requestID)
			w.Header().Set("X-Request-ID", requestID)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetRequestID extracts the request ID from context.
func GetRequestID(ctx context.Context) string {
	if id, ok := ctx.Value(logger.ContextKeyRequestID).(string); ok {
		return id
	}
	return ""
}

// responseWriter wraps http.ResponseWriter to capture status code.
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// Hijack implements http.Hijacker interface to support WebSocket connections.
// This delegates to the underlying ResponseWriter if it supports hijacking.
func (rw *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hijacker, ok := rw.ResponseWriter.(http.Hijacker); ok {
		return hijacker.Hijack()
	}
	return nil, nil, fmt.Errorf("responseWriter: underlying ResponseWriter does not implement http.Hijacker")
}

// LoggerConfig configures HTTP request logging behavior.
type LoggerConfig struct {
	// SkipPaths are paths that should not be logged (e.g., health checks)
	SkipPaths []string

	// SkipSuccessful skips logging for successful requests (2xx status codes)
	// Useful for high-traffic endpoints where you only care about errors
	SkipSuccessful bool

	// SlowRequestThreshold logs requests slower than this as warnings
	// Set to 0 to disable slow request logging
	SlowRequestThreshold time.Duration
}

// DefaultLoggerConfig returns default logging configuration.
func DefaultLoggerConfig() LoggerConfig {
	return LoggerConfig{
		SkipPaths: []string{
			"/health",
			"/healthz",
			"/ready",
			"/readyz",
			"/live",
			"/livez",
			"/metrics",
			"/api/v1/health",
			"/api/v1/ws", // WebSocket - skip to preserve http.Hijacker support
		},
		SkipSuccessful:       false,
		SlowRequestThreshold: 5 * time.Second,
	}
}

// Logger logs HTTP requests.
// This is the simple version that logs all requests.
func Logger(log *logger.Logger) func(http.Handler) http.Handler {
	return LoggerWithConfig(log, DefaultLoggerConfig())
}

// LoggerWithConfig logs HTTP requests with configurable behavior.
// Use this for production to skip health checks and reduce log volume.
func LoggerWithConfig(log *logger.Logger, cfg LoggerConfig) func(http.Handler) http.Handler {
	// Build skip paths map for O(1) lookup
	skipPaths := make(map[string]bool, len(cfg.SkipPaths))
	for _, path := range cfg.SkipPaths {
		skipPaths[path] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if path should be skipped (before processing for performance)
			if skipPaths[r.URL.Path] {
				next.ServeHTTP(w, r)
				return
			}

			start := time.Now()
			wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

			next.ServeHTTP(wrapped, r)

			duration := time.Since(start)

			// Skip successful requests if configured
			if cfg.SkipSuccessful && wrapped.statusCode >= 200 && wrapped.statusCode < 300 {
				return
			}

			// Log with appropriate level based on status and duration
			attrs := []any{
				"method", r.Method,
				"path", r.URL.Path,
				"status", wrapped.statusCode,
				"duration", duration,
				"request_id", GetRequestID(r.Context()),
				"remote_addr", r.RemoteAddr,
			}

			switch {
			case wrapped.statusCode >= 500:
				log.Error("http request", attrs...)
			case wrapped.statusCode >= 400:
				log.Warn("http request", attrs...)
			case cfg.SlowRequestThreshold > 0 && duration > cfg.SlowRequestThreshold:
				log.Warn("slow http request", attrs...)
			default:
				log.Info("http request", attrs...)
			}
		})
	}
}

// Recovery recovers from panics and returns a 500 error.
// In production, stack traces are omitted from logs to prevent information leakage.
func Recovery(log *logger.Logger) func(http.Handler) http.Handler {
	return RecoveryWithConfig(log, false)
}

// RecoveryWithConfig is like Recovery but accepts a production mode flag.
// SECURITY: In production, stack traces are omitted to prevent sensitive
// path/code information from being exposed in logs.
func RecoveryWithConfig(log *logger.Logger, isProduction bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					if isProduction {
						// SECURITY: Don't log stack traces in production
						log.Error("panic recovered",
							"error", err,
							"request_id", GetRequestID(r.Context()),
						)
					} else {
						// Include full stack trace in development for debugging
						log.Error("panic recovered",
							"error", err,
							"stack", string(debug.Stack()),
							"request_id", GetRequestID(r.Context()),
						)
					}

					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				}
			}()

			next.ServeHTTP(w, r)
		})
	}
}

// CORS adds CORS headers based on configuration.
func CORS(cfg *config.CORSConfig) func(http.Handler) http.Handler {
	allowedOrigins := make(map[string]bool)
	allowAllOrigins := false
	for _, origin := range cfg.AllowedOrigins {
		if origin == "*" {
			allowAllOrigins = true
		}
		allowedOrigins[origin] = true
	}

	methods := strings.Join(cfg.AllowedMethods, ", ")
	headers := strings.Join(cfg.AllowedHeaders, ", ")
	maxAge := strconv.Itoa(cfg.MaxAge)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			// Check if origin is allowed
			if allowAllOrigins {
				// Wildcard origin - cannot use credentials
				w.Header().Set("Access-Control-Allow-Origin", "*")
				// Note: Access-Control-Allow-Credentials not set with wildcard
			} else if origin != "" && allowedOrigins[origin] {
				// Specific origin - can use credentials
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.Header().Set("Vary", "Origin")
			}

			w.Header().Set("Access-Control-Allow-Methods", methods)
			w.Header().Set("Access-Control-Allow-Headers", headers)
			w.Header().Set("Access-Control-Max-Age", maxAge)

			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
