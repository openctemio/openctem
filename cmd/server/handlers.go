package main

import (
	"database/sql"

	"github.com/openctemio/api/internal/app"
	assetapp "github.com/openctemio/api/internal/app/asset"
	"github.com/openctemio/api/internal/config"
	"github.com/openctemio/api/internal/infra/http/handler"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/internal/infra/http/routes"
	"github.com/openctemio/api/internal/infra/postgres"
	"github.com/openctemio/api/internal/infra/redis"
	"github.com/openctemio/api/internal/infra/websocket"
	"github.com/openctemio/api/pkg/crypto"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/validator"
)

// newCompensatingControlHandlerWithWiring constructs the handler and
// attaches the B2 reclassify publisher when the services graph has
// one wired. Kept as a helper so handlers.go stays declarative.
func newCompensatingControlHandlerWithWiring(db *sql.DB, log *logger.Logger, svc *Services) *handler.CompensatingControlHandler {
	h := handler.NewCompensatingControlHandler(db, log)
	if svc != nil && svc.ControlChangePub != nil {
		h.SetChangePublisher(svc.ControlChangePub)
	}
	return h
}

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

// lastTenantHandler retains a pointer to the TenantHandler built by
// the most recent NewHandlers call so main.go can back-wire the
// asset lifecycle worker after workers are constructed. Not exposed
// via the Handlers struct because the routes layer already has a
// reference — we just need one extra slot for the back-wiring step.
var lastTenantHandler *handler.TenantHandler

// WireAssetLifecycleWorker connects the worker instance that the
// cron controller drives to the dry-run HTTP endpoint. Must be
// called after both NewHandlers and NewWorkers have run; until
// then the dry-run endpoint returns 503.
func WireAssetLifecycleWorker(w *assetapp.AssetLifecycleWorker) {
	if lastTenantHandler != nil {
		lastTenantHandler.SetAssetLifecycleWorker(w)
	}
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
	assetHandler.SetAuditService(svc.Audit)

	// Command handler with pipeline service wired
	commandHandler := handler.NewCommandHandler(svc.Command, v, log)
	commandHandler.SetPipelineService(svc.Pipeline)

	// Tenant handler with role service and asset service wired.
	// Exposed as a package-level var so main.go can back-wire the
	// asset lifecycle worker after both handlers and workers are
	// constructed. The handler returns 503 from the dry-run
	// endpoint until back-wiring happens.
	tenantHandler := handler.NewTenantHandler(svc.Tenant, v, log)
	tenantHandler.SetRoleService(svc.Role)
	tenantHandler.SetAssetService(svc.Asset)
	tenantHandler.SetModuleService(svc.Module)
	lastTenantHandler = tenantHandler

	// Vulnerability handler with user and asset services for enrichment
	vulnHandler := handler.NewVulnerabilityHandler(svc.Vulnerability, v, log)
	vulnHandler.SetUserService(svc.User)
	vulnHandler.SetAssetService(svc.Asset)
	if svc.BulkGuard != nil {
		vulnHandler.SetBulkGuard(svc.BulkGuard)
	}

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
		Component:     handler.NewComponentHandler(svc.Component, svc.SBOMImport, v, log),
		AssetGroup:    handler.NewAssetGroupHandler(svc.AssetGroup, v, log),
		AssetType:     handler.NewAssetTypeHandler(svc.AssetType, v, log),
		Scope:         handler.NewScopeHandler(svc.Scope, v, log),
		AttackSurface: handler.NewAttackSurfaceHandler(svc.AttackSurface, log),

		// Configuration (read-only system config)
		FindingSource: handler.NewFindingSourceHandler(svc.FindingSource, svc.FindingSourceCache, v, log),

		// CTEM Discovery - Network Services, State History & Relationships
		AssetService:           handler.NewAssetServiceHandler(repos.AssetService, repos.Asset, v, log),
		AssetStateHistory:      handler.NewAssetStateHistoryHandler(repos.AssetStateHistory, repos.Asset, v, log),
		AssetRelationship:      handler.NewAssetRelationshipHandler(svc.AssetRelationship, v, log),
		RelationshipSuggestion: handler.NewRelationshipSuggestionHandler(svc.RelationshipSuggestion, log),
		AssetImport:            handler.NewAssetImportHandler(svc.AssetImport, log),
		ReportSchedule:         handler.NewReportScheduleHandler(svc.ReportSchedule, log),

		// Vulnerabilities & Exposures
		Vulnerability:    vulnHandler,
		FindingActivity:  handler.NewFindingActivityHandler(svc.FindingActivity, svc.Vulnerability, log),
		FindingActions:   handler.NewFindingActionsHandler(svc.FindingActions, log),
		JiraWebhook:      handler.NewJiraWebhookHandler(svc.JiraSync, log),
		Exposure:         handler.NewExposureHandler(svc.Exposure, svc.User, v, log),
		ThreatIntel:      handler.NewThreatIntelHandler(svc.ThreatIntel, v, log),
		CredentialImport: handler.NewCredentialImportHandler(svc.CredentialImport, v, log),

		// Dashboard & Branch
		Dashboard: handler.NewDashboardHandler(svc.Dashboard, log),
		Branch:    handler.NewBranchHandler(svc.Branch, v, log),

		// Integration
		Integration: handler.NewIntegrationHandler(svc.Integration, v, log),

		// Agents & Commands
		Command:          commandHandler,
		Agent:            newAgentHandlerWithTemplates(svc.Agent, cfg, v, log),
		Ingest:           handler.NewIngestHandler(svc.Ingest, svc.Agent, log),
		RuntimeTelemetry: newRuntimeTelemetryHandlerWithCorrelator(deps, svc, log),
		IOC:              newIOCHandlerWithFindingCheck(deps, log),

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

		// Attack Simulation & Control Testing
		Simulation: handler.NewSimulationHandler(svc.Simulation, log),

		// Threat Actor Intelligence
		ThreatActor: handler.NewThreatActorHandler(svc.ThreatActor, log),

		// Remediation Campaigns
		RemediationCampaign: handler.NewRemediationCampaignHandler(svc.RemediationCampaign, log),

		// Business Units
		BusinessUnit: handler.NewBusinessUnitHandler(svc.BusinessUnit, log),

		// Business Services (Phase 3)
		BusinessService: handler.NewBusinessServiceHandler(deps.DB.DB, log),

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

		// Asset Dedup Review (RFC-001)
		AdminDedup: handler.NewAdminDedupHandler(repos.AssetDedup, log),

		// CTEM RFC-005: Compensating Controls, Attacker Profiles, CTEM Cycles
		CompensatingControl:   newCompensatingControlHandlerWithWiring(deps.DB.DB, log, svc),
		AttackerProfile:       handler.NewAttackerProfileHandler(deps.DB.DB, log),
		CTEMCycle:             handler.NewCTEMCycleHandler(deps.DB.DB, log),
		VerificationChecklist: handler.NewVerificationChecklistHandler(deps.DB.DB, log),
		PriorityRule:          handler.NewPriorityRuleHandler(deps.DB.DB, log),

		// Platform Stats (tenant-scoped platform agent statistics)
		PlatformStats: handler.NewPlatformStatsHandler(svc.Agent, log),

		// WebSocket for real-time communication
		WebSocket: websocket.NewHandler(deps.WebSocketHub, log),

		// F-8: wire the single-use ticket redeemer when configured so the
		// /ws route uses ticket auth instead of the JWT chain.
		WSTicketRedeemer: svc.WSTicket,
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
		// F-8: wire the single-use ticket service (may be nil if Redis not configured).
		if svc.WSTicket != nil {
			handlers.LocalAuth.SetWSTicketService(svc.WSTicket)
		}
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

// newRuntimeTelemetryHandlerWithCorrelator wires the IOC correlator
// into the runtime-telemetry ingest path. The handler is nil-safe
// without a correlator, but leaving it nil kills invariant B6 —
// telemetry is stored but never matched.
func newRuntimeTelemetryHandlerWithCorrelator(deps *HandlerDeps, svc *Services, log *logger.Logger) *handler.RuntimeTelemetryHandler {
	h := handler.NewRuntimeTelemetryHandler(deps.DB.DB, log)
	if svc.IOCCorrelator != nil {
		h.SetCorrelator(svc.IOCCorrelator)
	}
	return h
}

// newIOCHandlerWithFindingCheck wires the tenant-scoped finding repo
// into the IOC handler so POST /iocs can verify source_finding_id
// belongs to the caller. Without this check a client in tenant A
// could submit an IOC pointing at a finding in tenant B and trick the
// B6 correlator into reopening tenant B's finding.
func newIOCHandlerWithFindingCheck(deps *HandlerDeps, log *logger.Logger) *handler.IOCHandler {
	h := handler.NewIOCHandler(deps.Repos.IOC, log)
	h.SetFindingChecker(deps.Repos.Finding)
	return h
}
