package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/config"
	"github.com/openctemio/api/internal/infra/http"
	"github.com/openctemio/api/internal/infra/http/routes"
	"github.com/openctemio/api/internal/infra/jobs"
	"github.com/openctemio/api/internal/infra/postgres"
	"github.com/openctemio/api/internal/infra/redis"
	"github.com/openctemio/api/pkg/keycloak"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/validator"
)

// @title           Exploop API
// @version         1.0
// @description     Unified Continuous Threat Exposure Management (CTEM) Platform API
// @termsOfService  https://exploop.io/terms/

// @contact.name   Exploop Team
// @contact.url    https://github.com/exploopio/exploop
// @contact.email  support@exploop.io

// @license.name  MIT
// @license.url   https://opensource.org/licenses/MIT

// @host      localhost:8080
// @BasePath  /api/v1

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description JWT Bearer token. Format: "Bearer {token}"

// @externalDocs.description  OpenAPI
// @externalDocs.url          https://swagger.io/resources/open-api/

// Command line flags.
var (
	showRoutes  = flag.Bool("routes", false, "Print all registered routes and exit")
	routeFormat = flag.String("route-format", "table", "Route output format: table, json, csv, simple")
	routeMethod = flag.String("route-method", "", "Filter routes by HTTP method")
	routePath   = flag.String("route-path", "", "Filter routes containing this path")
	routeSort   = flag.String("route-sort", "path", "Sort routes by: path, method, handler")
)

func main() {
	flag.Parse()
	os.Exit(run())
}

func run() int {
	ctx := context.Background()

	// ==========================================================================
	// Configuration & Logger
	// ==========================================================================
	cfg, err := config.Load()
	if err != nil {
		log := logger.NewDefault()
		log.Error("failed to load configuration", "error", err)
		return 1
	}

	log := initLogger(cfg)
	log.Info("starting application", "app", cfg.App.Name, "env", cfg.App.Env)

	// ==========================================================================
	// Infrastructure
	// ==========================================================================
	db, err := postgres.New(&cfg.Database)
	if err != nil {
		log.Error("failed to connect to database", "error", err)
		return 1
	}
	defer closeWithLog(db, "database", log)
	log.Info("database connected")

	redisClient, err := redis.New(&cfg.Redis, log)
	if err != nil {
		log.Error("failed to connect to redis", "error", err)
		return 1
	}
	defer closeWithLog(redisClient, "redis", log)
	log.Info("redis connected")

	agentStateStore := redis.NewAgentStateStore(redisClient, log)
	log.Info("agent state store initialized")

	jobNotifier := redis.NewJobNotifier(redisClient, log)
	if err := jobNotifier.StartListener(ctx); err != nil {
		log.Error("failed to start job notifier", "error", err)
		return 1
	}
	log.Info("job notifier initialized")

	// ==========================================================================
	// Authentication
	// ==========================================================================
	var keycloakValidator *keycloak.Validator
	if cfg.Auth.Provider.SupportsOIDC() {
		keycloakValidator, err = initKeycloakValidator(cfg, log)
		if err != nil {
			return 1
		}
		defer closeWithLog(keycloakValidator, "keycloak validator", log)
	}

	// ==========================================================================
	// Repositories
	// ==========================================================================
	repos := NewRepositories(db)
	repos.InitIntegrationExtensions(db)
	log.Info("repositories initialized")

	// ==========================================================================
	// Services
	// ==========================================================================
	services, err := NewServices(&ServiceDeps{
		Config:          cfg,
		Log:             log,
		DB:              db.DB,
		Repos:           repos,
		RedisClient:     redisClient,
		AgentStateStore: agentStateStore,
	})
	if err != nil {
		log.Error("failed to initialize services", "error", err)
		return 1
	}
	log.Info("services initialized")

	// Initialize auth services if local auth is supported
	if cfg.Auth.Provider.SupportsLocal() {
		services.InitAuthServices(cfg, repos, log)
		log.Info("auth services initialized")
	}

	// Initialize email services
	if err := services.InitEmailServices(cfg, log); err != nil {
		log.Error("failed to initialize email services", "error", err)
		return 1
	}

	// ==========================================================================
	// Job Queue
	// ==========================================================================
	jobClient, err := NewJobClient(cfg, log)
	if err != nil {
		log.Error("failed to initialize job client", "error", err)
		return 1
	}
	defer closeWithLog(jobClient, "job client", log)

	emailEnqueuer := jobs.NewEmailEnqueuerAdapter(jobClient)
	services.Tenant = app.NewTenantService(repos.Tenant, log,
		app.WithTenantAuditService(services.Audit),
		app.WithEmailEnqueuer(emailEnqueuer),
	)
	services.Tenant.SetPermissionServices(services.PermCache, services.PermVersion)

	// Wire AI triage job enqueuer if service is enabled
	if services.AITriage != nil {
		aiTriageEnqueuer := jobs.NewAITriageEnqueuerAdapter(jobClient)
		services.AITriage.SetJobEnqueuer(aiTriageEnqueuer)
		log.Info("AI triage job enqueuer wired")
	}

	// ==========================================================================
	// Handlers
	// ==========================================================================
	v := validator.New()
	handlers := NewHandlers(&HandlerDeps{
		Config:       cfg,
		Log:          log,
		Validator:    v,
		DB:           db,
		RedisClient:  redisClient,
		WebSocketHub: services.WebSocketHub,
		Repos:        repos,
		Services:     services,
	})

	// Initialize local auth handler if supported
	if cfg.Auth.Provider.SupportsLocal() {
		InitLocalAuthHandler(&handlers, services, cfg, log)
	}

	// ==========================================================================
	// WebSocket Hub
	// ==========================================================================
	// Create cancellable context for graceful shutdown
	wsCtx, wsCancel := context.WithCancel(ctx)
	defer wsCancel()

	// Start WebSocket hub in background
	go services.WebSocketHub.Run(wsCtx)
	log.Info("websocket hub started")

	// ==========================================================================
	// HTTP Server
	// ==========================================================================
	authCfg := routes.AuthConfig{
		Provider:       cfg.Auth.Provider,
		LocalValidator: services.JWTGenerator,
		OIDCValidator:  keycloakValidator,
	}

	server := http.NewServer(cfg, log)
	routes.Register(server.Router(), handlers, cfg, log, authCfg, repos.Tenant, services.User, services.Module)

	// Handle --routes flag
	if *showRoutes {
		stats := http.CollectRoutes(server.Router())
		filters := http.RouteFilters{
			Method: *routeMethod,
			Path:   *routePath,
			SortBy: *routeSort,
		}
		http.PrintRoutes(os.Stdout, stats, *routeFormat, filters)
		return 0
	}

	// ==========================================================================
	// Workers
	// ==========================================================================
	workers, err := NewWorkers(&WorkerDeps{
		Config:   cfg,
		Log:      log,
		Repos:    repos,
		Services: services,
	})
	if err != nil {
		log.Error("failed to initialize workers", "error", err)
		return 1
	}

	if err := workers.Start(ctx, log); err != nil {
		log.Error("failed to start workers", "error", err)
		return 1
	}

	// ==========================================================================
	// Start Server
	// ==========================================================================
	go func() {
		if err := server.Start(); err != nil {
			log.Error("server error", "error", err)
		}
	}()
	log.Info("application started", "http_addr", cfg.Server.Addr())

	// ==========================================================================
	// Graceful Shutdown
	// ==========================================================================
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("shutting down...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
	defer cancel()

	// Stop WebSocket hub first (closes all connections)
	wsCancel()
	log.Info("websocket hub stopped")

	// Stop workers
	workers.Stop(log)

	// Then stop server
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Error("shutdown error", "error", err)
		return 1
	}

	log.Info("application stopped")
	return 0
}

// =============================================================================
// Helper Functions
// =============================================================================

func initLogger(cfg *config.Config) *logger.Logger {
	var log *logger.Logger
	if cfg.App.Env == "production" {
		// SamplingThreshold is validated to be non-negative in config validation
		//nolint:gosec // G115: safe conversion, value validated non-negative in config.Validate()
		threshold := uint64(cfg.Log.SamplingThreshold)
		log = logger.NewProductionWithConfig(logger.SamplingConfig{
			Enabled:   cfg.Log.SamplingEnabled,
			Tick:      time.Second,
			Threshold: threshold,
			Rate:      cfg.Log.SamplingRate,
			ErrorRate: cfg.Log.ErrorSamplingRate,
		})
	} else {
		log = logger.NewDevelopment()
	}
	log.SetDefault()
	return log
}

type closer interface {
	Close() error
}

func closeWithLog(c closer, name string, log *logger.Logger) {
	if err := c.Close(); err != nil {
		log.Error("failed to close "+name, "error", err)
	}
}

// =============================================================================
// Keycloak Validator
// =============================================================================

func initKeycloakValidator(cfg *config.Config, log *logger.Logger) (*keycloak.Validator, error) {
	keycloakValidator, err := keycloak.NewValidator(context.Background(), keycloak.ValidatorConfig{
		JWKSURL:             cfg.Keycloak.JWKSURL(),
		IssuerURL:           cfg.Keycloak.IssuerURL(),
		Audience:            cfg.Keycloak.ClientID,
		RefreshInterval:     cfg.Keycloak.JWKSRefreshInterval,
		HTTPTimeout:         cfg.Keycloak.HTTPTimeout,
		RequireInitialFetch: false,
		OnRefreshError: func(err error, consecutiveFailures int) {
			log.Error("JWKS refresh failed",
				"error", err,
				"consecutive_failures", consecutiveFailures,
				"jwks_url", cfg.Keycloak.JWKSURL(),
			)
			if consecutiveFailures >= 3 {
				log.Error("CRITICAL: JWKS refresh failing repeatedly, authentication may fail",
					"consecutive_failures", consecutiveFailures,
				)
			}
		},
	})
	if err != nil {
		log.Error("failed to initialize keycloak validator", "error", err)
		return nil, err
	}

	if keycloakValidator.HasKeys() {
		log.Info("keycloak validator initialized",
			"jwks_url", cfg.Keycloak.JWKSURL(),
			"issuer", cfg.Keycloak.IssuerURL(),
		)
	} else {
		log.Warn("keycloak validator initialized without keys, will retry in background",
			"jwks_url", cfg.Keycloak.JWKSURL(),
			"issuer", cfg.Keycloak.IssuerURL(),
		)
	}
	return keycloakValidator, nil
}
