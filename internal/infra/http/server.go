package http

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/openctemio/api/internal/config"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/logger"
)

// Server represents the HTTP server.
type Server struct {
	httpServer   *http.Server
	router       Router
	config       *config.Config
	logger       *logger.Logger
	cleanupFuncs []func() // cleanup functions to call on shutdown
}

// ServerOption is a function that configures the server.
type ServerOption func(*Server)

// WithRouter sets a custom router implementation.
func WithRouter(r Router) ServerOption {
	return func(s *Server) {
		s.router = r
	}
}

// NewServer creates a new HTTP server.
// By default, it uses Chi router. Use WithRouter option to change.
func NewServer(cfg *config.Config, log *logger.Logger, opts ...ServerOption) *Server {
	s := &Server{
		config: cfg,
		logger: log,
	}

	// Apply options
	for _, opt := range opts {
		opt(s)
	}

	// Default to Chi router if not set
	if s.router == nil {
		s.router = NewChiRouter()
	}

	// Create rate limiter with cleanup
	rateLimitMw, rateLimitStop := middleware.RateLimitWithStop(&cfg.RateLimit, log)
	s.cleanupFuncs = append(s.cleanupFuncs, rateLimitStop)

	// Configure security headers (enable HSTS in production)
	securityCfg := middleware.SecurityHeadersConfig{
		HSTSEnabled:           cfg.IsProduction(),
		HSTSMaxAge:            31536000, // 1 year
		HSTSIncludeSubdomains: true,
	}

	// Apply global middleware (order matters!)
	s.router.Use(
		middleware.RecoveryWithConfig(log, cfg.IsProduction()), // Recover from panics (no stack trace in prod)
		middleware.RequestID(),                                 // Add request ID early
		middleware.SecurityHeadersWithConfig(securityCfg),      // Security headers with HSTS
		middleware.CORS(&cfg.CORS),                             // CORS with config
		middleware.BodyLimit(cfg.Server.MaxBodySize),           // Limit request body size
		rateLimitMw, // Rate limiting
		middleware.Timeout(cfg.Server.RequestTimeout), // Per-request timeout
		middleware.Metrics(),                          // Prometheus metrics
		middleware.LoggerWithConfig(log, middleware.LoggerConfig{
			SkipPaths:            middleware.DefaultLoggerConfig().SkipPaths,
			SkipSuccessful:       false, // Log all requests by default
			SlowRequestThreshold: time.Duration(cfg.Log.SlowRequestSeconds) * time.Second,
		}), // Request logging with configurable skip paths
	)

	s.httpServer = &http.Server{
		Addr:         cfg.Server.Addr(),
		Handler:      s.router.Handler(),
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  time.Minute,
	}

	return s
}

// Router returns the router for registering handlers.
func (s *Server) Router() Router {
	return s.router
}

// Config returns the server configuration.
func (s *Server) Config() *config.Config {
	return s.config
}

// Logger returns the server logger.
func (s *Server) Logger() *logger.Logger {
	return s.logger
}

// Start starts the HTTP server.
func (s *Server) Start() error {
	s.logger.Info("starting HTTP server", "addr", s.config.Server.Addr())

	if err := s.httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("failed to start server: %w", err)
	}

	return nil
}

// Shutdown gracefully shuts down the HTTP server.
func (s *Server) Shutdown(ctx context.Context) error {
	s.logger.Info("shutting down HTTP server")

	// Call cleanup functions (rate limiter stop, etc.)
	for _, cleanup := range s.cleanupFuncs {
		cleanup()
	}

	if err := s.httpServer.Shutdown(ctx); err != nil {
		return fmt.Errorf("failed to shutdown server: %w", err)
	}

	s.logger.Info("HTTP server stopped")
	return nil
}
