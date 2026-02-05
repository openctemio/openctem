package main

import (
	"github.com/openctemio/api/internal/config"
	"github.com/openctemio/api/internal/infra/http/handler"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/internal/infra/http/routes"
	"github.com/openctemio/api/internal/infra/postgres"
	"github.com/openctemio/api/internal/infra/redis"
	"github.com/openctemio/api/internal/infra/websocket"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/validator"
)

// HandlerDeps contains dependencies needed to create handlers.
type HandlerDeps struct {
	Config       *config.Config
	Log          *logger.Logger
	Validator    *validator.Validator
	DB           *postgres.DB
	RedisClient  *redis.Client
	WebSocketHub *websocket.Hub // For real-time WebSocket communication
	Repos        *Repositories
	Services     *Services
}

// NewHandlers creates all HTTP handlers.
func NewHandlers(deps *HandlerDeps) routes.Handlers {
	cfg := deps.Config
	log := deps.Log
	v := deps.Validator
	repos := deps.Repos
	svc := deps.Services

	// Asset handler with integration service wired
	assetHandler := handler.NewAssetHandler(svc.Asset, v, log)
	assetHandler.SetIntegrationService(svc.Integration)

	// Command handler with pipeline service wired
	commandHandler := handler.NewCommandHandler(svc.Command, v, log)
	commandHandler.SetPipelineService(svc.Pipeline)

	// Tenant handler with role service wired
	tenantHandler := handler.NewTenantHandler(svc.Tenant, v, log)
	tenantHandler.SetRoleService(svc.Role)

	// Vulnerability handler with user and asset services for enrichment
	vulnHandler := handler.NewVulnerabilityHandler(svc.Vulnerability, v, log)
	vulnHandler.SetUserService(svc.User)
	vulnHandler.SetAssetService(svc.Asset)

	handlers := routes.Handlers{
		// Health
		Health: handler.NewHealthHandler(
			handler.WithDatabase(deps.DB),
			handler.WithRedis(deps.RedisClient),
		),

		// Auth
		Auth: handler.NewAuthHandler(&cfg.Keycloak, log),

		// Core
		Asset:  assetHandler,
		Tenant: tenantHandler,
		User:   handler.NewUserHandler(svc.User, svc.Tenant, v, log),
		Audit:  handler.NewAuditHandler(svc.Audit, v, log),

		// Assets & Components
		Component:     handler.NewComponentHandler(svc.Component, v, log),
		AssetGroup:    handler.NewAssetGroupHandler(svc.AssetGroup, v, log),
		AssetType:     handler.NewAssetTypeHandler(svc.AssetType, v, log),
		Scope:         handler.NewScopeHandler(svc.Scope, v, log),
		AttackSurface: handler.NewAttackSurfaceHandler(svc.AttackSurface, log),

		// Configuration (read-only system config)
		FindingSource: handler.NewFindingSourceHandler(svc.FindingSource, svc.FindingSourceCache, v, log),

		// CTEM Discovery - Network Services & State History
		AssetService:      handler.NewAssetServiceHandler(repos.AssetService, repos.Asset, v, log),
		AssetStateHistory: handler.NewAssetStateHistoryHandler(repos.AssetStateHistory, repos.Asset, v, log),

		// Vulnerabilities & Exposures
		Vulnerability:    vulnHandler,
		FindingActivity:  handler.NewFindingActivityHandler(svc.FindingActivity, svc.Vulnerability, log),
		Exposure:         handler.NewExposureHandler(svc.Exposure, svc.User, v, log),
		ThreatIntel:      handler.NewThreatIntelHandler(svc.ThreatIntel, v, log),
		CredentialImport: handler.NewCredentialImportHandler(svc.CredentialImport, v, log),

		// Dashboard & Branch
		Dashboard: handler.NewDashboardHandler(svc.Dashboard, log),
		Branch:    handler.NewBranchHandler(svc.Branch, v, log),

		// Integration
		Integration: handler.NewIntegrationHandler(svc.Integration, v, log),

		// Agents & Commands
		Command: commandHandler,
		Agent:   handler.NewAgentHandler(svc.Agent, v, log),
		Ingest:  handler.NewIngestHandler(svc.Ingest, svc.Agent, log),

		// Scanning & Pipelines
		ScanProfile:     handler.NewScanProfileHandler(svc.ScanProfile, v, log),
		ScanSession:     handler.NewScanSessionHandler(svc.ScanSession, v, log),
		ScannerTemplate: handler.NewScannerTemplateHandler(svc.ScannerTemplate, v, log),
		TemplateSource:  handler.NewTemplateSourceHandler(svc.TemplateSource, v, log),
		SecretStore:     handler.NewSecretStoreHandler(svc.SecretStore, v, log),
		Tool:            handler.NewToolHandler(svc.Tool, v, log),
		ToolCategory:    handler.NewToolCategoryHandler(svc.ToolCategory, v, log),
		Capability:      handler.NewCapabilityHandler(svc.Capability, v, log),
		Scan:            handler.NewScanHandler(svc.Scan, repos.User, v, log),
		Pipeline:        handler.NewPipelineHandler(svc.Pipeline, v, log),

		// Workflows
		Workflow: handler.NewWorkflowHandler(svc.Workflow, v, log),

		// Suppressions
		Suppression: handler.NewSuppressionHandler(svc.Suppression, log),

		// Access Control
		Group:         handler.NewGroupHandler(svc.Group, v, log),
		PermissionSet: handler.NewPermissionSetHandler(svc.Permission, v, log),
		Role:          handler.NewRoleHandler(svc.Role, v, log),
		Permission:    handler.NewPermissionHandler(svc.PermCache, svc.PermVersion, log),

		// Admin
		NotificationOutbox: handler.NewNotificationOutboxHandler(repos.NotificationOutbox, log),

		// Bootstrap (initial load endpoint)
		Bootstrap: handler.NewBootstrapHandler(
			svc.PermCache,
			svc.PermVersion,
			svc.Module,
			log,
		),

		// Docs
		Docs: handler.NewDocsHandler("api/openapi/swagger.yaml"),

		// Admin Auth (API Key authentication for Admin UI)
		AdminAuth:           handler.NewAdminAuthHandler(log),
		AdminAuthMiddleware: middleware.NewAdminAuthMiddleware(repos.Admin, log),

		// Admin Audit middleware (audit logging for admin operations)
		AdminAuditMiddleware: middleware.NewAuditMiddleware(repos.AdminAuditLog, log),

		// Admin Mapping rate limiter (10 req/min for write operations per RFC)
		AdminMappingRateLimiter: middleware.NewAdminMappingRateLimiter(middleware.DefaultAdminMappingRateLimitConfig(), log),

		// Admin Management (CRUD for admin users, audit logs, and target mappings)
		AdminUser:          handler.NewAdminUserHandler(repos.Admin, log),
		AdminAudit:         handler.NewAdminAuditHandler(repos.AdminAuditLog, log),
		AdminTargetMapping: handler.NewAdminTargetMappingHandler(repos.TargetMapping, log),

		// WebSocket for real-time communication
		WebSocket: websocket.NewHandler(deps.WebSocketHub, log),
	}

	return handlers
}

// InitLocalAuthHandler initializes the local auth handler.
// Should be called only if local auth is supported.
func InitLocalAuthHandler(
	handlers *routes.Handlers,
	svc *Services,
	cfg *config.Config,
	log *logger.Logger,
) {
	if svc.Auth != nil && svc.Session != nil {
		handlers.LocalAuth = handler.NewLocalAuthHandler(
			svc.Auth,
			svc.Session,
			svc.Email,
			cfg.Auth,
			log,
		)
		log.Info("local auth handler initialized")
	}
}
