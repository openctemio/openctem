package main

import (
	"database/sql"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/crypto"
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
	assetHandler.SetAccessControlRepo(repos.AccessControl)

	// Command handler with pipeline service wired
	commandHandler := handler.NewCommandHandler(svc.Command, v, log)
	commandHandler.SetPipelineService(svc.Pipeline)

	// Tenant handler with role service and asset service wired
	tenantHandler := handler.NewTenantHandler(svc.Tenant, v, log)
	tenantHandler.SetRoleService(svc.Role)
	tenantHandler.SetAssetService(svc.Asset)
	tenantHandler.SetModuleService(svc.Module)

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

		// CTEM Discovery - Network Services, State History & Relationships
		AssetService:      handler.NewAssetServiceHandler(repos.AssetService, repos.Asset, v, log),
		AssetStateHistory: handler.NewAssetStateHistoryHandler(repos.AssetStateHistory, repos.Asset, v, log),
		AssetRelationship: handler.NewAssetRelationshipHandler(svc.AssetRelationship, v, log),

		// Vulnerabilities & Exposures
		Vulnerability:      vulnHandler,
		FindingActivity:    handler.NewFindingActivityHandler(svc.FindingActivity, svc.Vulnerability, log),
		FindingActions:   handler.NewFindingActionsHandler(svc.FindingActions, log),
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
		Agent:   newAgentHandlerWithTemplates(svc.Agent, cfg, v, log),
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
		CI:              handler.NewCIHandler(svc.Scan, log),
		Pipeline:        handler.NewPipelineHandler(svc.Pipeline, v, log),

		// Workflows
		Workflow: handler.NewWorkflowHandler(svc.Workflow, v, log),

		// SLA Policies
		SLA: handler.NewSLAHandler(svc.SLA, v, log),

		// Pentest Campaign Management
		Pentest: func() *handler.PentestHandler {
			h := handler.NewPentestHandler(svc.Pentest, repos.User, log)
			h.SetImportService(app.NewFindingImportService(repos.Finding, log))
			return h
		}(),
		PentestCampaignRoleQry: repos.PentestCampaignMember,

		// File Attachments (shared across pentest/retest/campaign)
		Attachment: newAttachmentHandlerWithAccessCheck(svc.Attachment, svc.Pentest, deps.DB.DB, svc.Encryptor, log),

		// Compliance Framework Management
		Compliance: handler.NewComplianceHandler(svc.Compliance, log),

		// API Keys & Webhooks
		APIKey:  handler.NewAPIKeyHandler(svc.APIKey, v, log),
		Webhook: handler.NewWebhookHandler(svc.Webhook, v, log),

		// AI Triage (always initialized - handler returns 503 if service is nil)
		AITriage: handler.NewAITriageHandler(svc.AITriage, log),

		// Suppressions
		Suppression: handler.NewSuppressionHandler(svc.Suppression, log),

		// Access Control
		Group:          handler.NewGroupHandler(svc.Group, v, log),
		PermissionSet:  handler.NewPermissionSetHandler(svc.Permission, v, log),
		Role:           handler.NewRoleHandler(svc.Role, v, log),
		Permission:     handler.NewPermissionHandler(svc.PermCache, svc.PermVersion, log),
		AssignmentRule: handler.NewAssignmentRuleHandler(svc.AssignmentRule, v, log),
		ScopeRule:      handler.NewScopeRuleHandler(svc.ScopeRule, v, log),
		AssetOwner:     handler.NewAssetOwnerHandler(repos.AccessControl, repos.Asset, log),

		// Notification
		Outbox:       handler.NewOutboxHandler(repos.Outbox, log),
		Notification: handler.NewNotificationHandler(svc.Notification, log),

		// Bootstrap (initial load endpoint)
		Bootstrap: handler.NewBootstrapHandler(
			svc.PermCache,
			svc.PermVersion,
			svc.Module,
			svc.Tenant,
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

		// Platform Stats (tenant-scoped platform agent statistics)
		PlatformStats: handler.NewPlatformStatsHandler(svc.Agent, log),

		// WebSocket for real-time communication
		WebSocket: websocket.NewHandler(deps.WebSocketHub, log),
	}

	// SSO handler (always initialized - uses DB-stored provider configs)
	if svc.SSO != nil {
		handlers.SSO = handler.NewSSOHandler(svc.SSO, log)
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

// newAgentHandlerWithTemplates creates an AgentHandler wired with the
// optional config-template service. Templates live in
// $AGENT_CONFIG_TEMPLATES_DIR (default: configs/agent-templates) and can be
// edited without rebuilding the frontend.
func newAgentHandlerWithTemplates(
	agentSvc *app.AgentService,
	cfg *config.Config,
	v *validator.Validator,
	log *logger.Logger,
) *handler.AgentHandler {
	h := handler.NewAgentHandler(agentSvc, v, log)

	templatesDir := cfg.AgentConfig.TemplatesDir
	if templatesDir == "" {
		templatesDir = "configs/agent-templates"
	}
	tmplSvc := app.NewAgentConfigTemplateService(templatesDir, log)
	h.SetTemplateService(tmplSvc)

	publicAPIURL := cfg.AgentConfig.PublicAPIURL
	if publicAPIURL == "" {
		publicAPIURL = cfg.App.URL
	}
	h.SetPublicAPIURL(publicAPIURL)

	return h
}

// newAttachmentHandlerWithAccessCheck creates an AttachmentHandler with campaign
// membership verification for finding-scoped attachments.
func newAttachmentHandlerWithAccessCheck(attachSvc *app.AttachmentService, pentestSvc *app.PentestService, db *sql.DB, enc crypto.Encryptor, log *logger.Logger) *handler.AttachmentHandler {
	h := handler.NewAttachmentHandler(attachSvc, log)
	h.SetAccessChecker(pentestSvc)
	h.SetStorageResolver(app.NewSettingsStorageResolver(db, enc, log))
	return h
}
