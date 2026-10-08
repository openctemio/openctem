package http

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/httpsec"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Server represents the HTTP server.
type Server struct {
	httpServer   *http.Server
	router       Router
	config       *config.Config
	logger       *logger.Logger
	cleanupFuncs []func() // cleanup functions to call on shutdown
	// prefixes are handlers served ahead of the router (MountPrefix).
	prefixes []prefixHandler
}

type prefixHandler struct {
	prefix  string
	handler http.Handler
}

// MountPrefix serves every request whose path starts with prefix+"/" with h,
// ahead of the router and its global middleware. It is for a surface that
// carries its own guards and cannot run behind the global request timeout
// and buffered writers: the sensor protocol v3 HTTPS binding, whose control
// stream lives for minutes (docs/rfcs/RFC-059-sensor-transport-v3.md). Call
// it before Start.
func (s *Server) MountPrefix(prefix string, h http.Handler) {
	s.prefixes = append(s.prefixes, prefixHandler{prefix: strings.TrimSuffix(prefix, "/") + "/", handler: h})
	router := s.router.Handler()
	prefixes := append([]prefixHandler(nil), s.prefixes...)
	s.httpServer.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, p := range prefixes {
			if strings.HasPrefix(r.URL.Path, p.prefix) {
				p.handler.ServeHTTP(w, r)
				return
			}
		}
		router.ServeHTTP(w, r)
	})
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

	// SECURITY (S-4): wire trusted-proxy CIDR allowlist into the IP-attribution
	// helpers used by rate-limit middleware and auth audit logs. When the
	// allowlist is empty the helpers honor only r.RemoteAddr — correct for
	// direct-Internet deployments. With a CIDR list (e.g. K8s pod range,
	// load-balancer subnet), X-Forwarded-For and X-Real-IP are honored only
	// from peers in that range.
	trustedProxies := httpsec.NewTrustedProxySet(cfg.Server.TrustedProxies)
	middleware.SetTrustedProxies(trustedProxies)
	handler.SetAuthTrustedProxies(trustedProxies)

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
		// Metrics sits right inside Recovery so every answer is counted:
		// the global rate limit (429), the concurrency limit (503), the body
		// limit and a panic (500) included. Operator alerts read these.
		middleware.Metrics(),
		middleware.ConcurrencyLimit(cfg.Server.MaxConcurrentRequests), // Limit concurrent requests
		middleware.RequestID(),                                 // Add request ID early
		middleware.ContextLogger(log),                          // Inject request-scoped logger into context
		middleware.SecurityHeadersWithConfig(securityCfg),      // Security headers with HSTS
		middleware.CORSWithEnvironment(&cfg.CORS, cfg.App.Env), // CORS with environment-aware config
		middleware.BodyLimit(cfg.Server.MaxBodySize),           // Limit request body size (10MB default)
		rateLimitMw, // Rate limiting
		middleware.TimeoutWithLogger(cfg.Server.RequestTimeout, log), // Per-request timeout (+ panic recovery inside its goroutine)
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
