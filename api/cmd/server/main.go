package main

import (
	"context"
	"errors"
	"flag"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/openctemio/openctem/api/internal/app"
	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/routes"
	"github.com/openctemio/openctem/api/internal/infra/jobs"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/infra/redis"
	"github.com/openctemio/openctem/api/internal/infra/websocket"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/keycloak"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// @title           OpenCTEM API
// @version         1.0
// @description     Unified Continuous Threat Exposure Management (CTEM) Platform API
// @termsOfService  https://openctem.io/terms/

// @contact.name   OpenCTEM Team
// @contact.url    https://github.com/openctemio/openctem
// @contact.email  support@openctem.io

// @license.name  MIT
// @license.url   https://opensource.org/licenses/MIT

// @host      localhost:8080
// @BasePath  /api/v1

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description JWT access token, or a tenant oct_ API key (read-only: GET/HEAD on tenant routes, within the key's scopes). Format: "Bearer {token}". An oct_ key may instead be sent as X-API-Key.

// @securityDefinitions.apikey CIRunToken
// @in header
// @name Authorization
// @description CI run upload token from POST /ci/oidc/exchange (RFC-051): "Bearer octci_...", 15 minutes, one run on one repository.

// @externalDocs.description  OpenAPI
// @externalDocs.url          https://swagger.io/resources/open-api/

// Command line flags.
var (
	showRoutes  = flag.Bool("routes", false, "Print all registered routes and exit")
	routeFormat = flag.String("route-format", "table", "Route output format: table, json, csv, simple")
	routeMethod = flag.String("route-method", "", "Filter routes by HTTP method")
	routePath   = flag.String("route-path", "", "Filter routes containing this path")
	routeSort   = flag.String("route-sort", "path", "Sort routes by: path, method, handler")

	sensorUpgradeCheck = flag.Bool("sensor-upgrade-check", false,
		"Report data and schema still carrying the pre-sensor 'agent' vocabulary after migration 000230, then exit (0 = clean, 1 = leftovers)")
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

	// Fail fast if the DB schema is behind the migrations shipped with this
	// binary — otherwise every request touching a not-yet-migrated column 500s
	// (a silent, total outage). Refuse to start with an actionable message
	// instead. Best-effort / bypassable via SKIP_SCHEMA_CHECK=true.
	if err := verifySchemaUpToDate(ctx, db.DB, migrationsDirPath(), log); err != nil {
		log.Error("database schema check failed — refusing to start", "error", err)
		return 1
	}

	if *sensorUpgradeCheck {
		return runSensorUpgradeCheck(ctx, db.DB, os.Stdout)
	}
	logSensorUpgradeLeftovers(ctx, db.DB, log)

	redisClient, err := redis.New(&cfg.Redis, log)
	if err != nil {
		log.Error("failed to connect to redis", "error", err)
		return 1
	}
	defer closeWithLog(redisClient, "redis", log)
	log.Info("redis connected")

	sensorStateStore := redis.NewSensorStateStore(redisClient, log)
	log.Info("sensor state store initialized")

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
		Config:           cfg,
		Log:              log,
		DB:               db.DB,
		Repos:            repos,
		RedisClient:      redisClient,
		SensorStateStore: sensorStateStore,
	})
	if err != nil {
		log.Error("failed to initialize services", "error", err)
		return 1
	}
	log.Info("services initialized")

	// P0-2: Jira webhook preflight. In production, refuse to start when
	// any tenant has a connected Jira integration but the HMAC secret is
	// missing — otherwise inbound webhooks would start silently 401'ing.
	if err := checkJiraWebhookPreflight(ctx, cfg, db.DB, log); err != nil {
		log.Error("jira webhook preflight failed", "error", err)
		return 1
	}

	// Initialize auth services if local auth is supported
	if cfg.Auth.Provider.SupportsLocal() {
		services.InitAuthServices(cfg, repos, log, redisClient)
		log.Info("auth services initialized")
	}

	// Initialize email services
	if err := services.InitEmailServices(cfg, log); err != nil {
		log.Error("failed to initialize email services", "error", err)
		return 1
	}

	// Account security e-mails (2FA turned off, recovery code used, password
	// changed) go to the user through the system SMTP server.
	if services.Auth != nil && services.Email != nil {
		services.Auth.SetSecurityNotifier(services.Email)
	}

	// Owners are emailed about an SSO change that waits for their approval.
	if services.SSOChange != nil && services.Email != nil {
		services.SSOChange.SetMailer(services.Email)
	}

	// Wire SMTP availability checker into auth service for smart email verification.
	// When no SMTP is configured (system or tenant), email verification is auto-disabled
	// so first-time deployments can register users without setting up SMTP first.
	if services.Auth != nil && services.Email != nil {
		services.Auth.SetSMTPChecker(services.Email)
	}

	// Wire the per-tenant SMTP resolver so a tenant that configured an email
	// notification integration sends from its own SMTP server instead of the
	// system default. The SetTenantSMTPResolver seam was never called, so
	// per-tenant SMTP was silently dead and every tenant fell back to system SMTP.
	if services.Email != nil {
		services.Email.SetTenantSMTPResolver(app.NewIntegrationSMTPResolver(repos.Integration, log))
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

	// Outbound Jira status sync (RFC-006 Phase 3c): when a finding's status
	// changes via the API, enqueue a background push to its linked Jira issue.
	// The worker no-ops unless the tenant opted in (config.ticketing.sync_enabled).
	if services.Vulnerability != nil {
		services.Vulnerability.SetJiraStatusSyncHook(func(ctx context.Context, tenantID, findingID shared.ID) {
			if err := jobClient.EnqueueJiraSyncFindingStatus(ctx, jobs.JiraSyncFindingStatusPayload{
				TenantID:  tenantID.String(),
				FindingID: findingID.String(),
			}); err != nil {
				log.Warn("failed to enqueue jira status sync", "error", err)
			}
			// The same status-change trigger drives outbound GitHub Issues sync;
			// the worker no-ops when the finding isn't linked to a GitHub issue.
			// A finding links to at most one provider, so only the matching push acts.
			if err := jobClient.EnqueueGitHubSyncFindingStatus(ctx, jobs.GitHubSyncFindingStatusPayload{
				TenantID:  tenantID.String(),
				FindingID: findingID.String(),
			}); err != nil {
				log.Warn("failed to enqueue github status sync", "error", err)
			}
		})
	}

	// The tenant service is built once, in NewServices, with everything it can
	// get there. Only collaborators that do not exist until this point are
	// added here, on that same instance. It used to be rebuilt here instead,
	// which silently dropped every setter NewServices had applied (session,
	// membership cache, SSO checker, role service, data-scope store, ...).
	services.Tenant.SetEmailEnqueuer(jobs.NewEmailEnqueuerAdapter(jobClient))
	// Suspend/reactivate emails need the email service, built above.
	if services.Email != nil {
		services.Tenant.SetMemberStatusEmailNotifier(services.Email)
	}
	// Administrator-created accounts. The set-password link is emailed
	// when SMTP is configured, otherwise returned once to the administrator.
	var setupMailer app.AccountSetupMailer
	if services.Email != nil {
		setupMailer = services.Email
	}
	if services.Role != nil {
		services.UserProvisioning = app.NewUserProvisioningService(repos.Tenant, repos.User, services.Role, setupMailer, services.Audit, log)
	}

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
	// Handlers are constructed before workers because workers
	// subscribe to some service events that need handler-side
	// dependencies wired. The AssetLifecycleWorker dry-run endpoint
	// is back-wired after workers.Start below.
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
		InitLocalAuthHandler(&handlers, services, repos, cfg, log)
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

	// F-7: wire Redis pubsub bridge so broadcasts fan out across pods.
	// Silent dependency until now: without this, a BroadcastEvent on
	// Pod-A never reaches a client on Pod-B in a multi-replica
	// deployment. Enabled whenever Redis is available, which covers
	// every production configuration.
	if redisClient != nil {
		bridge := websocket.NewRedisBridge(redisClient.Client(), services.WebSocketHub, &websocket.BridgeConfig{
			Logger: log,
		})
		go func() {
			if err := bridge.Start(wsCtx); err != nil && !errors.Is(err, context.Canceled) {
				log.Error("websocket bridge stopped with error", "error", err)
			}
		}()
		log.Info("websocket redis bridge started")
	}

	// ==========================================================================
	// HTTP Server
	// ==========================================================================
	authCfg := routes.AuthConfig{
		Provider:       cfg.Auth.Provider,
		LocalValidator: services.JWTGenerator,
		OIDCValidator:  keycloakValidator,
	}
	if services.SessionRevocations != nil {
		authCfg.RevokedSessions = services.SessionRevocations
	}

	// Close a socket whose session was revoked while its upgrade was in flight.
	if handlers.WebSocket != nil && services.SessionRevocations != nil {
		handlers.WebSocket.SetSessionRevocationChecker(services.SessionRevocations)
	}

	server := http.NewServer(cfg, log)
	routes.Register(server.Router(), handlers, cfg, log, authCfg, repos.Tenant, services.User, services.MembershipCache, services.PermCache, services.PermVersion)

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
		DB:       db.DB,
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

	// Back-wire the lifecycle worker into the tenant handler so the
	// dry-run HTTP endpoint and the cron controller share one worker
	// instance. Handlers are built before workers (see note above);
	// this call closes that loop.
	if workers.AssetLifecycleWorker != nil {
		WireAssetLifecycleWorker(workers.AssetLifecycleWorker)
	}

	// Seal leaked-credential secrets still stored in plaintext (rows written
	// before secrets were encrypted, or without a key). Idempotent, batched,
	// SKIP LOCKED: safe on every start and across replicas.
	go func() {
		n, err := postgres.BackfillLeakedCredentialSecrets(ctx, db.DB, services.CredentialSecrets)
		if err != nil {
			log.Error("leaked credential secret backfill failed", "error", err, "sealed", n)
			return
		}
		if n > 0 {
			log.Info("leaked credential secrets sealed", "count", n, "aes_gcm", services.CredentialSecrets.Encrypts())
		}
	}()

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

	// Flush any buffered new-internet-facing-asset summary so a graceful
	// restart does not drop it (the DB is still open here).
	if services.AssetDiscoveryNotifier != nil {
		services.AssetDiscoveryNotifier.Stop()
	}

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
	log := logger.New(loggerConfig(cfg))
	log.SetDefault()
	return log
}

// loggerConfig turns LOG_LEVEL, LOG_FORMAT and LOG_SAMPLING_* into the logger
// settings, in every environment. (Outside APP_ENV=production they used to be
// ignored: always debug + text, so a non-production deployment such as the
// live demo could neither lower the volume nor switch to JSON.)
func loggerConfig(cfg *config.Config) logger.Config {
	// SamplingThreshold is validated to be non-negative in config validation
	//nolint:gosec // G115: safe conversion, value validated non-negative in config.Validate()
	threshold := uint64(cfg.Log.SamplingThreshold)
	return logger.Config{
		Level:  cfg.Log.Level,
		Format: cfg.Log.Format,
		Output: os.Stdout,
		Sampling: logger.SamplingConfig{
			Enabled:   cfg.Log.SamplingEnabled,
			Tick:      time.Second,
			Threshold: threshold,
			Rate:      cfg.Log.SamplingRate,
			ErrorRate: cfg.Log.ErrorSamplingRate,
		},
	}
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
