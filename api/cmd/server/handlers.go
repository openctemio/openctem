package main

import (
	"context"
	"database/sql"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/internal/app"
	apispecapp "github.com/openctemio/openctem/api/internal/app/apispec"
	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/internal/app/scanrun"
	webendpointapp "github.com/openctemio/openctem/api/internal/app/webendpoint"

	"github.com/openctemio/openctem/api/internal/app/adminconsole"
	auditsvc "github.com/openctemio/openctem/api/internal/app/audit"
	authapp "github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/internal/app/compliance"
	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/app/integration"
	"github.com/openctemio/openctem/api/internal/app/sensor"

	assetapp "github.com/openctemio/openctem/api/internal/app/asset"
	cirunapp "github.com/openctemio/openctem/api/internal/app/cirun"
	"github.com/openctemio/openctem/api/internal/app/commandlog"
	easmapp "github.com/openctemio/openctem/api/internal/app/easm"
	"github.com/openctemio/openctem/api/internal/app/findingimport"
	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/controller"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/http/routes"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/infra/redis"
	"github.com/openctemio/openctem/api/internal/infra/sensortransport"
	"github.com/openctemio/openctem/api/internal/infra/websocket"
	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/command"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/user"
	"github.com/openctemio/openctem/api/pkg/httpsec"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/oidc"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
	"github.com/openctemio/openctem/api/pkg/validator"
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

// newPriorityRuleHandlerWithWiring constructs the priority-rule handler and
// attaches the reclassify publisher when the services graph has one, so a rule
// create/update/delete drives a whole-tenant reclassify sweep. Mirrors
// newCompensatingControlHandlerWithWiring.
func newPriorityRuleHandlerWithWiring(db *sql.DB, log *logger.Logger, svc *Services) *handler.PriorityRuleHandler {
	h := handler.NewPriorityRuleHandler(db, log)
	if svc != nil && svc.ControlChangePub != nil {
		h.SetChangePublisher(svc.ControlChangePub)
	}
	// Wire the classifier so POST /priority-rules/dry-run can evaluate a draft
	// rule against live findings with the real engine (nil → endpoint 503s).
	if svc != nil && svc.PriorityClassification != nil {
		h.SetDryRunner(svc.PriorityClassification)
	}
	return h
}

// newThreatModelHandler wires the continuous-threat-modeling handler, or nil
// when the generation service was not initialized (e.g. no database).
func newThreatModelHandler(svc *Services, log *logger.Logger) *handler.ThreatModelHandler {
	if svc == nil || svc.ThreatModel == nil {
		return nil
	}
	return handler.NewThreatModelHandler(svc.ThreatModel, log)
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

// newScanWorkflowHandler builds the scan workflow handler with the run page's task
// logs (RFC-029 §4.4.1).
func newScanWorkflowHandler(svc *scanrun.Service, logs *commandlog.Service, events command.EventReader, scope *datascope.Enforcer, users user.Repository, v *validator.Validator, log *logger.Logger) *handler.ScanWorkflowHandler {
	h := handler.NewScanWorkflowHandler(svc, v, log)
	h.SetTaskLogs(logs)
	h.SetUserNames(users)
	h.SetRunEvents(events)
	if scope != nil {
		// Runs about a finding (retests) follow the finding's data scope.
		h.SetFindingScope(scope)
	}
	return h
}

// NewHandlers creates all HTTP handlers.
func NewHandlers(deps *HandlerDeps) routes.Handlers {
	cfg := deps.Config
	log := deps.Log
	v := deps.Validator
	repos := deps.Repos
	svc := deps.Services

	// Platform admin console (RFC-022): the administrator signs in on the normal
	// /login with their users-table account, then the console adds a TOTP step
	// and its own session, accepted by the admin auth middleware alongside API keys.
	adminConsoleSvc := adminconsole.NewService(repos.Admin, repos.AdminConsole, repos.AdminAuditLog, svc.Encryptor,
		adminAccountDirectory{auth: svc.Auth}, log)
	// Administrators' platform identity provider (RFC-022 revision 4): every
	// discovery, JWKS and token request goes through the SSRF-safe client.
	adminConsoleSvc.SetPlatformIdP(repos.PlatformIdP, newPlatformIdPClient())
	adminConsoleSvc.SetBreakGlassNotifier(breakGlassMailer{email: svc.Email, appName: cfg.App.Name, log: log})
	if svc.Signup != nil {
		svc.Signup.SetNotifier(signupPolicyMailer{email: svc.Email, appName: cfg.App.Name, log: log})
	}

	// CI runs (RFC-051): OIDC exchange, uploads, the gate, administration.
	ciAdmin, ciRunner := newCIHandlers(cfg, repos, svc, log)

	// Asset handler with integration service wired
	assetHandler := handler.NewAssetHandler(svc.Asset, v, log)
	assetHandler.SetIntegrationService(svc.Integration)
	assetHandler.SetAccessControlRepo(repos.AccessControl)
	assetHandler.SetAuditService(svc.Audit)

	// Command handler with scan run service wired
	commandHandler := handler.NewCommandHandler(svc.Command, v, log)
	sensorHandler := newSensorHandlerWithTemplates(svc.Sensor, cfg, v, log)
	sensorHandler.SetContentPolicySource(svc.SensorContent)
	sensorHandler.SetZoneLister(repos.ScanZone)
	sensorHandler.SetGrantService(svc.SensorGrant)
	commandHandler.SetScanRunService(svc.ScanRun)
	commandHandler.SetAuditService(svc.Audit)
	commandHandler.SetScanCommandGate(svc.Scan)
	// Map completed validation jobs into finding evidence.
	commandHandler.SetValidationIngest(svc.ValidationEvidence)
	commandHandler.SetSimulationFinalizer(svc.Simulation)
	// Continuous retest (RFC-039): a retest check's evidence is recorded
	// advisory-only and its retest settled when the sensor completes or fails it.
	commandHandler.SetRetestHooks(svc.ValidationEvidence, svc.Retest)
	if svc.ScanRun != nil {
		commandHandler.SetValidationRuns(svc.ScanRun)
	}
	// Per-task logs from sensors (RFC-029 §4.4.1), shown on the run page.
	commandLogs := commandlog.NewService(repos.CommandLog)
	commandHandler.SetCommandLogs(commandLogs)
	commandHandler.SetFindingScope(svc.DataScope)
	commandHandler.SetCoverageEvaluator(svc.Ingest)

	// Sensor authentication and the services the protocol v2 control handler
	// shares.
	ingestHandler := handler.NewIngestHandler(svc.Ingest, svc.Sensor, log)
	// Heartbeat doorbell (RFC-023 §9.2a): the heartbeat tells a sensor that
	// work is waiting and when to ring again. One cheap query per heartbeat.
	doorbell := sensor.NewDoorbell(repos.Command, heartbeatDoorbellConfig(cfg), log)
	// Gated actions (rotate_key) ring only when the sensor's grant lists
	// them (RFC-052 §5.3).
	doorbell.SetGrants(repos.SensorGrant)
	ingestHandler.SetDoorbell(doorbell)
	// Heartbeat latency feeds the health controller's platform-health guard
	// (RFC-035 D3): no offline conviction while heartbeats are slow.
	ingestHandler.SetHeartbeatObserver(svc.SensorPlatformHealth)
	// A CI sensor's key is refused when its organization requires OIDC for
	// CI (RFC-051).
	ciKeyPolicy := newCIRunnerKeyPolicy(repos, svc, log)
	if ciKeyPolicy != nil {
		ingestHandler.SetCIRunnerKeyPolicy(ciKeyPolicy)
	}

	// Tenant handler with role service and asset service wired.
	// Exposed as a package-level var so main.go can back-wire the
	// asset lifecycle worker after both handlers and workers are
	// constructed. The handler returns 503 from the dry-run
	// endpoint until back-wiring happens.
	tenantHandler := handler.NewTenantHandler(svc.Tenant, v, log)
	tenantHandler.SetSelfServiceTenantCreation(cfg.Auth.SelfServiceTenantCreation())
	if svc.Signup != nil {
		tenantHandler.SetSignupPolicy(svc.Signup)
	}
	if svc.UserProvisioning != nil {
		tenantHandler.SetUserProvisioning(svc.UserProvisioning)
	}
	tenantHandler.SetRoleService(svc.Role)
	tenantHandler.SetAssetService(svc.Asset)
	tenantHandler.SetModuleService(svc.Module)
	lastTenantHandler = tenantHandler

	// Vulnerability handler with user and asset services for enrichment
	vulnHandler := handler.NewVulnerabilityHandler(svc.Vulnerability, v, log)
	vulnHandler.SetUserService(svc.User)
	vulnHandler.SetAssetService(svc.Asset)
	vulnHandler.SetAuditService(svc.Audit)
	vulnHandler.SetComponentService(svc.Component)
	vulnHandler.SetSavedViews(svc.SavedView)
	if svc.BulkGuard != nil {
		vulnHandler.SetBulkGuard(svc.BulkGuard)
	}
	if svc.PriorityClassification != nil {
		vulnHandler.SetPriorityExplainer(svc.PriorityClassification)
	}

	// Jira/GitHub ticket sync handler. GitHub Issues is wired as an optional
	// secondary provider on the same create-ticket endpoint.
	jiraWebhookHandler := handler.NewJiraWebhookHandler(svc.JiraSync, v, log)
	jiraWebhookHandler.SetGitHubTicketService(svc.GitHubTicket)

	githubWebhookHandler := handler.NewGitHubWebhookHandler(svc.Integration, log)
	// Inbound GitHub issue closed/reopened → finding status (reverse of create-ticket).
	githubWebhookHandler.SetIssueSink(svc.GitHubTicket)

	// Finding actions handler with the CTEM Stage-4 validation runner wired.
	findingActionsHandler := handler.NewFindingActionsHandler(svc.FindingActions, log)
	findingActionsHandler.SetValidationRunner(svc.ValidationRun)
	findingActionsHandler.SetSavedViews(svc.SavedView)

	// Validation handler + coverage KPI reader.
	validationHandler := handler.NewValidationHandler(svc.ValidationEvidence, log)
	validationHandler.SetCoverageReader(repos.ValidationEvidence)
	// Direct evidence submissions change a finding only when they cite the
	// validate command assigned to the submitting sensor; otherwise advisory.
	validationHandler.SetCommandLookup(repos.Command)
	// Evidence without a command is refused unless the tenant's sensor result
	// policy allows advisory evidence (RFC-040 §5.3).
	validationHandler.SetEvidencePolicy(svc.Ingest)

	// Per-tenant module route gating (module-coupling plan Phase 1). Fail-open:
	// only an explicitly-disabled non-core module is blocked. Wired back into the
	// module service so a toggle invalidates the gate cache immediately.
	moduleGate := middleware.NewModuleGate(svc.Module, time.Minute)
	svc.Module.SetModuleCacheInvalidator(moduleGate)

	// Read-only MCP server: exposes this tenant's CTEM data to an AI client over
	// JSON-RPC, authenticated by a tenant-scoped `oct_` API key (not the browser
	// JWT). Built only when the read services and the API-key service exist.
	var mcpHandler *handler.MCPHandler
	var mcpAuth routes.Middleware
	// One `oct_` authenticator for MCP and the REST API, so a key has a single
	// rate-limit budget across both.
	var apiKeyAuth *middleware.APIKeyAuthMiddleware
	if svc.APIKey != nil {
		apiKeyAuth = middleware.NewAPIKeyAuth(svc.APIKey, log)
	}
	if apiKeyAuth != nil && svc.Vulnerability != nil && svc.PriorityClassification != nil &&
		svc.AttackSurface != nil && svc.RemediationGroup != nil && svc.Compliance != nil &&
		svc.Asset != nil && svc.Pentest != nil {
		mcpHandler = handler.NewMCPHandler(
			svc.Vulnerability, svc.PriorityClassification, svc.AttackSurface,
			svc.RemediationGroup, svc.Compliance, svc.Asset, svc.Pentest, log,
		)
		// Audit every MCP tools/call (which key, tenant, tool, sanitized args, outcome).
		mcpHandler.SetAuditService(svc.Audit)
		mcpAuth = apiKeyAuth.Handler
	}

	handlers := routes.Handlers{
		ModuleGate: moduleGate,
		DataScope:  svc.DataScope,
		MCP:        mcpHandler,
		MCPAuth:    mcpAuth,
		APIKeyAuth: apiKeyAuth,
		// Health
		Health: handler.NewHealthHandler(
			handler.WithDatabase(deps.DB),
			handler.WithRedis(deps.RedisClient),
		),
		ClientErrors: handler.NewClientErrorHandler(log),

		// Auth
		Auth: handler.NewAuthHandler(&cfg.Keycloak, log),

		// Core
		Asset:  assetHandler,
		Tenant: tenantHandler,
		User:   handler.NewUserHandler(svc.User, svc.Tenant, platformAdminChecker{admins: repos.Admin}, v, log),
		Audit:  handler.NewAuditHandler(svc.Audit, v, log),

		// Assets & Components
		Component:     handler.NewComponentHandler(svc.Component, svc.SBOMImport, v, log),
		AssetGroup:    handler.NewAssetGroupHandler(svc.AssetGroup, v, log),
		AssetType:     handler.NewAssetTypeHandler(svc.AssetType, v, log),
		Scope:         handler.NewScopeHandler(svc.Scope, v, log),
		AttackSurface: handler.NewAttackSurfaceHandler(svc.AttackSurface, log),
		EASM:          newEASMHandler(repos, svc, log),
		EASMSettings:  newEASMSettingsHandler(cfg, svc, deps, log),

		// Configuration (read-only system config)
		FindingSource: handler.NewFindingSourceHandler(svc.FindingSource, svc.FindingSourceCache, v, log),

		// CTEM Discovery - Network Services, State History & Relationships
		AssetService:           handler.NewAssetServiceHandler(repos.AssetService, repos.Asset, v, log).SetDataScope(svc.DataScope),
		WebEndpoint:            handler.NewWebEndpointHandler(webendpointapp.NewService(repos.WebEndpoint, svc.DataScope), svc.Audit, log),
		APISpec:                handler.NewAPISpecHandler(apispecapp.NewService(repos.APISpec, repos.Asset, svc.DataScope), svc.Audit, log),
		AssetStateHistory:      handler.NewAssetStateHistoryHandler(repos.AssetStateHistory, repos.Asset, v, log).SetDataScope(svc.DataScope),
		AssetIdentifier:        handler.NewAssetIdentifierHandler(repos.AssetIdentifier, repos.Asset, log),
		AssetAttribution:       newAssetAttributionHandler(repos, svc, log),
		AssetRelationship:      handler.NewAssetRelationshipHandler(svc.AssetRelationship, v, log),
		RelationshipSuggestion: handler.NewRelationshipSuggestionHandler(svc.RelationshipSuggestion, log),
		AssetImport:            newAssetImportHandler(svc, log),
		FindingImport:          newFindingImportHandler(cfg, repos, svc, log),
		ReportSchedule:         newReportScheduleHandler(svc, log),
		UserDashboard:          handler.NewUserDashboardHandler(svc.UserDashboard, log),
		SavedView:              handler.NewSavedViewHandler(svc.SavedView, log),

		// Vulnerabilities & Exposures
		Vulnerability:             vulnHandler,
		RemediationGroup:          handler.NewRemediationGroupHandler(svc.RemediationGroup),
		FindingActivity:           handler.NewFindingActivityHandler(svc.FindingActivity, svc.Vulnerability, log),
		FindingActions:            findingActionsHandler,
		FindingRetest:             handler.NewFindingRetestHandler(svc.Retest, log),
		FindingEvidenceItems:      handler.NewFindingEvidenceItemsHandler(svc.Evidence, log),
		JiraWebhook:               jiraWebhookHandler,
		JiraWebhookSecretResolver: svc.Integration,
		GitHubWebhook:             githubWebhookHandler,
		Exposure:                  handler.NewExposureHandler(svc.Exposure, svc.User, v, log),
		ThreatIntel:               handler.NewThreatIntelHandler(svc.ThreatIntel, v, log),
		CTEMID:                    handler.NewCTEMIDHandler(svc.CTEMID, log),
		CredentialImport:          handler.NewCredentialImportHandler(svc.CredentialImport, v, log),

		// Dashboard & Branch
		Dashboard: handler.NewDashboardHandler(svc.Dashboard, log),
		Branch: func() *handler.BranchHandler {
			h := handler.NewBranchHandler(svc.Branch, v, log)
			// S-2: wire AssetService so branch handler can verify repo ownership.
			h.SetAssetService(svc.Asset)
			return h
		}(),

		// Integration
		Integration: func() *handler.IntegrationHandler {
			h := handler.NewIntegrationHandler(svc.Integration, v, log)
			// A sync of a Tenable.sc connector queues connector_sync (RFC-047).
			h.SetTenableSCConnector(svc.TenableSC)
			return h
		}(),
		DefectDojo: handler.NewDefectDojoHandler(svc.DefectDojoSync, log),

		// Sensors & Commands
		Command:         commandHandler,
		Sensor:          sensorHandler,
		SensorContent:   handler.NewSensorContentHandler(svc.SensorContent, sensorHandler, log),
		SensorResults:   handler.NewSensorResultHandler(svc.Ingest, sensorHandler, log),
		ScanZone:        handler.NewScanZoneHandler(svc.ScanZone, svc.Scan, log),
		ScanFreeze:      handler.NewScanFreezeWindowHandler(svc.ScanFreeze, log),
		Ingest:          ingestHandler,
		SensorResultsV2: newSensorResultsV2Handler(cfg, repos, svc, ciKeyPolicy, log),
		SensorPairing:   newSensorPairingHandler(svc, log),
		IOC:             newIOCHandlerWithFindingCheck(deps, log),
		Validation:      validationHandler,
		SCIM: func() *handler.SCIMHandler {
			h := handler.NewSCIMHandler(svc.SCIMProvisioning, log)
			h.SetGroupService(svc.SCIMGroups)
			return h
		}(),
		SCIMToken: func() *handler.SCIMTokenHandler {
			h := handler.NewSCIMTokenHandler(svc.SCIMToken, log)
			h.SetGroupService(svc.SCIMGroups)
			h.SetAuditService(svc.Audit)
			return h
		}(),
		SCIMAuth: middleware.SCIMAuth(svc.SCIMToken),

		// Scanning & ScanRuns
		ScanProfile:     handler.NewScanProfileHandler(svc.ScanProfile, v, log),
		ScannerTemplate: handler.NewScannerTemplateHandler(svc.ScannerTemplate, v, log),
		TemplateSource:  handler.NewTemplateSourceHandler(svc.TemplateSource, v, log),
		SecretStore:     handler.NewSecretStoreHandler(svc.SecretStore, v, log),
		Tool:            handler.NewToolHandler(svc.Tool, v, log),
		ToolCategory:    handler.NewToolCategoryHandler(svc.ToolCategory, v, log),
		Capability:      handler.NewCapabilityHandler(svc.Capability, v, log),
		Scan:            handler.NewScanHandler(svc.Scan, repos.User, repos.ScanCoverage, v, log),
		CI:              handler.NewCIHandler(svc.Scan, log),
		CIAdmin:         ciAdmin,
		CIRunner:        ciRunner,
		ScanWorkflow:    newScanWorkflowHandler(svc.ScanRun, commandLogs, repos.CommandEvent, svc.DataScope, repos.User, v, log),

		// Workflows
		Workflow: handler.NewWorkflowHandler(svc.Workflow, v, log),

		// SLA Policies
		SLA: handler.NewSLAHandler(svc.SLA, v, log),

		// Pentest Campaign Management
		Pentest: func() *handler.PentestHandler {
			h := handler.NewPentestHandler(svc.Pentest, repos.User, v, log)
			h.SetImportService(finding.NewFindingImportService(repos.Finding, log))
			return h
		}(),
		PentestCampaignRoleQry: repos.PentestCampaignMember,

		// File Attachments (shared across pentest/retest/campaign)
		Attachment: newAttachmentHandlerWithAccessCheck(svc.Attachment, svc.Pentest, deps.DB.DB, svc.Encryptor, svc.Audit, log),

		// Compliance Framework Management
		Compliance: handler.NewComplianceHandler(svc.Compliance, log),

		// Attack Simulation & Control Testing
		Simulation: handler.NewSimulationHandler(svc.Simulation, log),

		// Threat Actor Intelligence
		ThreatActor: handler.NewThreatActorHandler(svc.ThreatActor, v, log),

		// Remediation Campaigns
		RemediationCampaign: handler.NewRemediationCampaignHandler(svc.RemediationCampaign, log),

		// Business Units
		BusinessUnit: handler.NewBusinessUnitHandler(svc.BusinessUnit, log),

		// Business Services (Phase 3)
		BusinessService: handler.NewBusinessServiceHandler(deps.DB.DB, log).WithDataScope(svc.DataScope),

		// API Keys & Webhooks
		APIKey: handler.NewAPIKeyHandler(svc.APIKey, v, log),

		// AI Triage (always initialized - handler returns 503 if service is nil)
		AITriage: handler.NewAITriageHandler(svc.AITriage, log),

		// Suppressions
		Suppression: newSuppressionHandler(svc, log),

		// Access Control
		Group:          handler.NewGroupHandler(svc.Group, v, log),
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
		AdminOrganization:   handler.NewAdminOrganizationHandler(repos.AdminOrg, svc.Tenant, repos.User, v, log).WithUserProvisioning(svc.UserProvisioning),
		AdminConsole:        handler.NewAdminConsoleHandler(adminConsoleSvc, cfg.Auth.CookieSecure, cfg.Auth.RefreshTokenCookieName, log),
		AdminAuditChain:     handler.NewAdminAuditChainHandler(svc.Audit, adminConsoleSvc, repos.AdminAuditLog, repos.AdminOrg, log),
		AdminAuthMiddleware: middleware.NewAdminAuthMiddleware(adminConsoleSvc, log),

		// Admin Audit middleware (audit logging for admin operations)
		AdminAuditMiddleware: middleware.NewAuditMiddleware(repos.AdminAuditLog, log),

		// Admin Mapping rate limiter (10 req/min for write operations per RFC)
		AdminMappingRateLimiter: middleware.NewAdminMappingRateLimiter(middleware.DefaultAdminMappingRateLimitConfig(), log),

		// Admin Management (CRUD for admin users, audit logs, and target mappings)
		AdminUser:          handler.NewAdminUserHandler(repos.Admin, log),
		AdminAudit:         handler.NewAdminAuditHandler(repos.AdminAuditLog, log),
		AdminTargetMapping: handler.NewAdminTargetMappingHandler(repos.TargetMapping, log),

		// Asset Dedup Review (RFC-001)
		AdminDedup: handler.NewAdminDedupHandler(repos.AssetDedup, log).SetDataScope(svc.DataScope),

		// CTEM RFC-005: Compensating Controls, Attacker Profiles, CTEM Cycles
		CompensatingControl:   newCompensatingControlHandlerWithWiring(deps.DB.DB, log, svc),
		AttackerProfile:       handler.NewAttackerProfileHandler(deps.DB.DB, log),
		CTEMCycle:             handler.NewCTEMCycleHandler(deps.DB.DB, postgres.NewCTEMCycleMetricsRepository(deps.DB), log).WithDataScope(svc.DataScope),
		VerificationChecklist: handler.NewVerificationChecklistHandler(deps.DB.DB, log),
		PriorityRule:          newPriorityRuleHandlerWithWiring(deps.DB.DB, log, svc),
		ThreatModel:           newThreatModelHandler(svc, log),
		Scoping:               handler.NewScopingHandler(postgres.NewScopingSummaryRepository(deps.DB), log),

		// Platform scanning: the shared platform sensors as a service the
		// tenant may use, never the sensors themselves.
		PlatformScanning: handler.NewPlatformScanningHandler(
			sensor.NewPlatformScanningService(repos.Sensor, app.PlatformSensorsAllowed), log),

		// WebSocket for real-time communication
		WebSocket: websocket.NewHandler(deps.WebSocketHub, log, cfg.CORS.AllowedOrigins, cfg.App.Env),

		// Login, MFA, password, SSO and invitation limits count in Redis so
		// every replica spends one budget (in-memory fallback on a Redis error).
		AuthRateLimitBackend: middleware.NewRedisAuthRateLimitBackend(deps.RedisClient, log),
	}

	// SSO handler (always initialized - uses DB-stored provider configs)
	// Scan profile changes go to the tenant's audit log.
	handlers.ScanProfile.SetAuditService(svc.Audit)
	// Changes to what sensors scan and run (scope targets and exclusions,
	// tools and their tenant config, scanner templates) too (RFC-040 §5.11).
	handlers.Scope.SetAuditService(svc.Audit)
	handlers.Scope.SetSettingsStore(svc.Tenant)
	// People on scope responses are named from this tenant's members only.
	scopeActors := postgres.NewScopeActorRepository(deps.DB)
	handlers.Scope.SetActorNamer(scopeActors)
	if svc.EASMSweep != nil {
		handlers.Scope.SetSweeper(svc.EASMSweep)
	}
	handlers.Scope.SetActiveProof(cfg.Scope.ActiveProof)
	if svc.Scan != nil && svc.ActiveGate != nil {
		handlers.Scope.SetDryRun(svc.Scan, svc.ActiveGate)
	}
	handlers.Tool.SetAuditService(svc.Audit)
	// Configuration changes audited with a before/after diff.
	handlers.Integration.SetAuditService(svc.Audit)
	handlers.TemplateSource.SetAuditService(svc.Audit)
	handlers.SLA.SetAuditService(svc.Audit)
	handlers.AssignmentRule.SetAuditService(svc.Audit)
	handlers.ScopeRule.SetAuditService(svc.Audit)
	handlers.Outbox.SetAuditService(svc.Audit)
	handlers.PriorityRule.SetAuditService(svc.Audit)
	// Asset access grants change who sees an asset: audited.
	handlers.AssetOwner.SetAuditService(svc.Audit)
	handlers.ScannerTemplate.SetAuditService(svc.Audit)

	if svc.SSO != nil {
		handlers.SSO = handler.NewSSOHandler(svc.SSO, log)
		// Identity-provider changes go to the organization's audit log.
		handlers.SSO.SetAuditService(svc.Audit)
		// Admin-console identity-provider creates/updates wait for an owner.
		handlers.SSO.SetChangeApproval(svc.SSOChange)
	}
	if svc.SSOChange != nil {
		handlers.SSOChange = handler.NewSSOChangeHandler(svc.SSOChange, svc.Audit, log)
	}

	// Social OAuth handler (Google / GitHub / Microsoft). svc.OAuth is non-nil
	// only when a provider is configured, so /auth/oauth/* exists exactly when
	// /auth/providers advertises a social button for it.
	if svc.OAuth != nil {
		handlers.OAuth = handler.NewOAuthHandler(svc.OAuth, cfg.OAuth, cfg.Auth, log)
	}

	// Verified-domain handler (SSO P1 domain-ownership verification)
	if svc.DomainVerify != nil {
		handlers.VerifiedDomain = handler.NewVerifiedDomainHandler(svc.DomainVerify, log)
		if svc.OrgTrust != nil {
			handlers.OrgTrust = handler.NewOrgTrustHandler(svc.OrgTrust, log)
		}
		handlers.VerifiedDomain.SetAuditService(svc.Audit)
		// Tenant self-service verification for EASM (research/22 P0-10, E6).
		var audit handler.AttributionAuditor
		if svc.Audit != nil {
			audit = svc.Audit
		}
		handlers.EASMVerifiedDomain = handler.NewEASMVerifiedDomainHandler(svc.DomainVerify, audit, log)
	}

	// SAML SP handler (RFC-009 9d+9e): metadata, config CRUD, and the
	// SP-initiated browser login (login redirect + ACS session cookies).
	if svc.SAML != nil {
		handlers.SAML = handler.NewSAMLHandler(
			svc.SAML,
			handler.NewCookieConfig(cfg.Auth),
			frontendOrigin(cfg.OAuth.FrontendCallbackURL),
			log,
		)
		// SP entity ID / ACS URL come from APP_URL, never from client headers.
		handlers.SAML.SetPublicURL(cfg.App.URL)
		handlers.SAML.SetAuditService(svc.Audit)
		// Admin-console SAML changes wait for an owner of the organization.
		handlers.SAML.SetChangeApproval(svc.SSOChange)
		if cfg.App.URL == "" && cfg.IsProduction() {
			log.Warn("saml: APP_URL is not set; SP URLs fall back to the request Host (forwarded headers only from SERVER_TRUSTED_PROXIES). Set APP_URL to the public API origin.")
		}
	}

	// AUTHZ-07: record an audit event whenever plaintext leaked-secret values
	// are read (list / by-id / related / by-identity).
	if handlers.CredentialImport != nil {
		handlers.CredentialImport.SetAuditService(svc.Audit)
	}

	// The sign-up policy exists with local auth (InitAuthServices).
	if svc.Signup != nil {
		handlers.AdminSignup = handler.NewAdminSignupHandler(svc.Signup, adminConsoleSvc, log)
		handlers.SignupPolicy = svc.Signup
	}
	handlers.SensorV3 = newSensorV3Server(cfg, repos, svc, handlers.SensorResultsV2, log)
	return handlers
}

// newSensorV3Server builds the sensor protocol v3 server (RFC-059) when
// SENSOR_TRANSPORT_V3_ENABLED is on and protocol v2 is served (v3 runs every
// call through the v2 routes). Command writes wake its control streams.
func newSensorV3Server(cfg *config.Config, repos *Repositories, svc *Services, v2 *handler.SensorResultsV2Handler,
	log *logger.Logger,
) *sensortransport.Server {
	tc := cfg.SensorConfig.TransportV3
	if !tc.Enabled {
		return nil
	}
	if v2 == nil {
		log.Warn("SENSOR_TRANSPORT_V3_ENABLED is set but protocol v2 results are off; protocol v3 is not served")
		return nil
	}
	srv := sensortransport.NewServer(sensortransport.Config{MaxContentBytes: v2.Limits().MaxContentBytes}, nil, log)
	repos.Command.SetChangeNotifier(srv.Hub())
	svc.Sensor.SetStatusNotifier(srv.Hub().Wake)

	// The sensor CA: certificates for the gRPC binding. Without it the
	// HTTPS binding still serves (IssueCertificate answers Unimplemented).
	grpcEndpoint := ""
	ca, err := sensortransport.LoadCA(tc.CACertFile, tc.CAKeyFile, tc.CADir)
	if err != nil {
		log.Error("sensor CA not loaded: protocol v3 serves the HTTPS binding only", "error", err)
	} else {
		srv.SetCertificateIssuer(sensortransport.NewIssuer(ca, svc.Sensor, svc.Sensor, tc.CertTTL, tc.PublicHost, log))
		if tc.PublicHost != "" {
			if err := srv.EnableMTLS(sensortransport.MTLSConfig{Addr: tc.MTLSListenAddr, Host: tc.PublicHost}, ca, svc.Sensor); err != nil {
				log.Error("sensor protocol v3 gRPC binding not served", "error", err)
			} else {
				grpcEndpoint = tc.PublicHost
			}
		}
		log.Info("sensor CA loaded", "fingerprint", ca.Fingerprint())
	}
	srv.SetGRPCEndpoint(grpcEndpoint)
	v2.SetTransportV3(&protov2.TransportV3{HTTPSPath: sensortransport.PathPrefix, GRPCEndpoint: grpcEndpoint})
	log.Info("sensor protocol v3 enabled", "https_path", sensortransport.PathPrefix, "grpc_endpoint", grpcEndpoint)
	return srv
}

// frontendOrigin extracts scheme://host from the configured frontend callback
// URL so the SAML browser flow can redirect to the SPA root after login. Falls
// back to the raw value (or localhost) if it cannot be parsed.
func frontendOrigin(callbackURL string) string {
	if callbackURL == "" {
		return "http://localhost:3000"
	}
	u, err := url.Parse(callbackURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return callbackURL
	}
	return u.Scheme + "://" + u.Host
}

// InitLocalAuthHandler initializes the local auth handler.
// Should be called only if local auth is supported.
func InitLocalAuthHandler(
	handlers *routes.Handlers,
	svc *Services,
	repos *Repositories,
	cfg *config.Config,
	log *logger.Logger,
) {
	if svc.Auth != nil && svc.Session != nil {
		handlers.LocalAuth = handler.NewLocalAuthHandler(
			svc.Auth,
			svc.Session,
			svc.Email,
			platformAdminChecker{admins: repos.Admin},
			cfg.Auth,
			log,
		)
		log.Info("local auth handler initialized")
		// Widening a sensor's grant needs a recent sign-in or step-up.
		if svc.SensorGrant != nil {
			svc.SensorGrant.SetWideningApprover(handler.StepUpWideningApprover{
				Checker: handlers.LocalAuth.RecentAuthChecker(), Window: authapp.StepUpWindow,
			})
		}
	}
}

// wireStepUpGate gives the services that need step-up re-authentication for
// some of their actions (making someone an administrator or an owner,
// renaming the organization's slug) the same check the sensitive routes use
// (docs/architecture/step-up-reauth.md). Without local auth there is no
// session store: platform sessions then cannot step up (fail closed) and
// external provider tokens are judged by their auth_time.
func wireStepUpGate(handlers *routes.Handlers, svc *Services) {
	var checker middleware.RecentAuthChecker
	if handlers.LocalAuth != nil {
		checker = handlers.LocalAuth.RecentAuthChecker()
	}
	gate := middleware.RecentAuthGate{Checker: checker, Window: authapp.StepUpWindow}
	if svc.Role != nil {
		svc.Role.SetStepUpGate(gate)
	}
	if svc.Tenant != nil {
		svc.Tenant.SetStepUpGate(gate)
	}
	if svc.Scope != nil {
		svc.Scope.SetStepUpGate(gate)
	}
	if svc.Sensor != nil {
		svc.Sensor.SetStepUpGate(gate)
	}
}

// newSensorHandlerWithTemplates creates a SensorHandler wired with the
// optional config-template service. Templates live in
// $SENSOR_CONFIG_TEMPLATES_DIR (default: configs/sensor-templates) and can be
// edited without rebuilding the frontend.
func newSensorHandlerWithTemplates(
	sensorSvc *sensor.SensorService,
	cfg *config.Config,
	v *validator.Validator,
	log *logger.Logger,
) *handler.SensorHandler {
	h := handler.NewSensorHandler(sensorSvc, v, log)

	templatesDir := cfg.SensorConfig.TemplatesDir
	if templatesDir == "" {
		templatesDir = "configs/sensor-templates"
	}
	tmplSvc := sensor.NewSensorConfigTemplateService(templatesDir, log)
	h.SetTemplateService(tmplSvc)

	publicAPIURL := cfg.SensorConfig.PublicAPIURL
	if publicAPIURL == "" {
		publicAPIURL = cfg.App.URL
	}
	h.SetPublicAPIURL(publicAPIURL)
	h.SetHealthPolicy(sensorHealthPolicy(cfg, log))
	h.SetSensorImage(sensorInstallImage(cfg, log))
	h.SetCACertificateFile(cfg.SensorConfig.CACertFile)

	return h
}

// imageRepositoryRegexp is an image repository safe to put in a shell snippet.
var imageRepositoryRegexp = regexp.MustCompile(`^[a-z0-9][a-z0-9._/:-]{0,254}$`)

// sensorInstallImage is the image the install snippets run: SENSOR_IMAGE with
// the release-channel tag (never "latest"). An unusable SENSOR_IMAGE falls
// back to the published image.
func sensorInstallImage(cfg *config.Config, log *logger.Logger) string {
	repo := strings.TrimSpace(cfg.SensorConfig.Image)
	if !imageRepositoryRegexp.MatchString(repo) || strings.Contains(repo, "@") {
		if repo != "" {
			log.Warn("ignoring SENSOR_IMAGE that is not an image repository", "value", repo)
		}
		repo = config.DefaultSensorImageRepository
	}
	// A tag in SENSOR_IMAGE is dropped: the tag is the release channel's.
	if i := strings.LastIndex(repo, ":"); i > strings.LastIndex(repo, "/") {
		repo = repo[:i]
	}
	tag := sensordom.NormalizeVersion(cfg.SensorConfig.LatestVersion)
	if !sensordom.IsReleaseVersion(tag) {
		tag = config.DefaultSensorLatestVersion
	}
	return repo + ":" + tag
}

// sensorHealthPolicy maps the heartbeat settings and the sensor release
// channel onto the fleet-health thresholds. Each sensor is judged against
// its own heartbeat deadline (pkg/domain/sensor/liveness.go); the policy adds
// the online window of the idle interval (informational) and the
// WORKER_HEARTBEAT_TIMEOUT backstop.
func sensorHealthPolicy(cfg *config.Config, log *logger.Logger) sensordom.HealthPolicy {
	sc := cfg.SensorConfig
	for name, v := range map[string]string{
		"SENSOR_LATEST_VERSION": sc.LatestVersion, "SENSOR_MIN_VERSION": sc.MinVersion,
		"SENSOR_SDK_LATEST_VERSION": sc.SDKLatestVersion, "SENSOR_SDK_MIN_VERSION": sc.SDKMinVersion,
	} {
		if v != "" && !sensordom.IsReleaseVersion(v) {
			log.Warn("ignoring sensor release setting that is not a version (want e.g. v0.4.2, or none)",
				"setting", name, "value", v)
		}
	}
	offline := cfg.Worker.HeartbeatTimeout
	return sensordom.HealthPolicy{
		OnlineWindow:     sensordom.OnlineWindowFor(sc.HeartbeatInterval, offline),
		OfflineAfter:     offline,
		LatestVersion:    sc.LatestVersion,
		MinVersion:       sc.MinVersion,
		SDKLatestVersion: sc.SDKLatestVersion,
		SDKMinVersion:    sc.SDKMinVersion,
	}.Normalized()
}

// newAttachmentHandlerWithAccessCheck creates an AttachmentHandler with campaign
// membership verification for finding-scoped attachments.
func newAttachmentHandlerWithAccessCheck(attachSvc *integration.AttachmentService, pentestSvc *compliance.PentestService, db *sql.DB, enc crypto.Encryptor, auditSvc *auditsvc.AuditService, log *logger.Logger) *handler.AttachmentHandler {
	h := handler.NewAttachmentHandler(attachSvc, log)
	h.SetAccessChecker(pentestSvc)
	h.SetStorageResolver(authapp.NewSettingsStorageResolver(db, enc, log))
	h.SetAuditService(auditSvc)
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
	h.SetMatchLister(deps.Repos.IOC)
	return h
}

// heartbeatDoorbellConfig maps the SENSOR_HEARTBEAT_* settings onto the
// doorbell, bounded so no advised interval reaches half of the time after
// which a sensor is marked offline: the health controller's
// sensorStaleTimeout (90 s), or WORKER_HEARTBEAT_TIMEOUT when shorter. The
// bound used to be WORKER_HEARTBEAT_TIMEOUT alone (5 min), so the "loaded"
// advice (120 s) outlasted the controller's 90 s and every sensor that
// followed it was marked offline once per cycle (RFC-035 B1, decision D2).
func heartbeatDoorbellConfig(cfg *config.Config) sensor.DoorbellConfig {
	sc := cfg.SensorConfig
	c := sensor.DefaultDoorbellConfig()
	c.IdleInterval = sc.HeartbeatInterval
	c.BusyInterval = sc.HeartbeatBusyInterval
	c.LoadedInterval = sc.HeartbeatLoadedInterval
	c.MinInterval = sc.HeartbeatMinInterval
	c.MaxInterval = sc.HeartbeatMaxInterval
	c.SlowQuery = sc.HeartbeatSlowQuery
	switch {
	case sc.KeyRenewBefore > 0:
		c.KeyRenewBefore = sc.KeyRenewBefore
	case sc.KeyTTL > 0:
		// Renew at half-life.
		c.KeyRenewBefore = sc.KeyTTL / 2
	}
	return c.Normalized(offlineMark(cfg.Worker.HeartbeatTimeout))
}

// offlineMark is how long after its last heartbeat a sensor is marked
// offline: the health controller's sensorStaleTimeout, or the configured
// heartbeat timeout when that is shorter.
func offlineMark(heartbeatTimeout time.Duration) time.Duration {
	if heartbeatTimeout > 0 && heartbeatTimeout < sensorStaleTimeout {
		return heartbeatTimeout
	}
	return sensorStaleTimeout
}

// newSensorResultsV2Handler builds the protocol v2 results handler (RFC-026),
// or returns nil — /api/v2/sensor is then not mounted — while
// SENSOR_PROTOCOL_V2_RESULTS is off.
func newSensorResultsV2Handler(cfg *config.Config, repos *Repositories, svc *Services, ciKeys *cirunapp.RunnerKeyPolicy,
	log *logger.Logger) *handler.SensorResultsV2Handler {
	if !cfg.Ingest.V2Results || repos.IngestJob == nil || repos.IngestReport == nil || svc.Sensor == nil {
		return nil
	}
	receiver := ingest.NewV2Receiver(repos.IngestReport, repos.IngestJob, repos.IngestJob, repos.Command,
		protov2.DefaultLimits(), cfg.Ingest.MaxPendingPerTenant, log)
	log.Info("sensor protocol v2 results enabled", "path", protov2.PathPrefix)
	h := handler.NewSensorResultsV2Handler(receiver, svc.Sensor, log)
	if ciKeys != nil {
		h.SetCIRunnerKeyPolicy(ciKeys)
	}
	return h
}

// newCIRunnerKeyPolicy builds the "OIDC required for CI" policy over the
// tenants' setting (nil without the CI repository).
func newCIRunnerKeyPolicy(repos *Repositories, svc *Services, log *logger.Logger) *cirunapp.RunnerKeyPolicy {
	if repos.CIRun == nil {
		return nil
	}
	var audit cirunapp.Auditor
	if svc.Audit != nil {
		audit = svc.Audit
	}
	return cirunapp.NewRunnerKeyPolicy(repos.CIRun, audit, log)
}

// newEASMHandler builds the EASM overview and review queue handler; every
// review decision is audited (RFC-036).
func newEASMHandler(repos *Repositories, svc *Services, log *logger.Logger) *handler.EASMHandler {
	h := handler.NewEASMHandler(easmapp.NewService(repos.EASMSummary, svc.DataScope), log)
	var audit handler.AttributionAuditor
	if svc.Audit != nil {
		audit = svc.Audit
	}
	review := easmapp.NewReviewService(repos.Attribution, svc.DataScope)
	review.SetDecisionEffects(easmDecisionEffects(repos, svc, log))
	if svc.ActiveGate != nil {
		review.SetCoverage(svc.ActiveGate) // covered_by on queue items (RFC-054 §6.6)
	}
	// Address rows explain why they stay in review and offer the fix.
	review.SetAddressExplainer(repos.Attribution, func(ctx context.Context, tenantID shared.ID) (string, error) {
		t, err := repos.Tenant.GetByID(ctx, tenantID)
		if err != nil {
			return "", err
		}
		return t.Name(), nil
	})
	h.SetReview(review, audit)
	// Review by rule (RFC-054 §6.7): rules are scope entries and exclusions.
	if svc.ScopeJoin != nil && svc.ActiveGate != nil && svc.Scope != nil {
		h.SetRules(easmapp.NewRuleService(review, svc.ScopeJoin, svc.Scope, repos.Asset, svc.ActiveGate, svc.ScopeGuardrails))
	}
	return h
}

// easmDecisionEffects reclassifies the decided assets' findings now and, on a
// rejection, resolves the name's EASM exposures (research/22 P0-9).
func easmDecisionEffects(repos *Repositories, svc *Services, log *logger.Logger) *easmapp.DecisionEffects {
	var reclassify easmapp.AssetReclassifier
	if pub := svc.ControlChangePub; pub != nil {
		reclassify = func(ctx context.Context, tenantID shared.ID, ids []shared.ID) {
			pub.PublishAssetReclassify(ctx, tenantID, ids, controller.ReasonAssetChange, "attribution decided")
		}
	}
	return easmapp.NewDecisionEffects(repos.Exposure, reclassify, log)
}

// newEASMSettingsHandler builds the EASM settings and run-now handler
// (research/22 P0-11).
func newEASMSettingsHandler(cfg *config.Config, svc *Services, deps *HandlerDeps, log *logger.Logger) *handler.EASMSettingsHandler {
	var audit handler.AttributionAuditor
	if svc.Audit != nil {
		audit = svc.Audit
	}
	var sweeper handler.EASMSweeper
	if svc.EASMSweep != nil {
		sweeper = svc.EASMSweep
	}
	platform := handler.EASMPlatform{
		CTAvailable:   cfg.Worker.CertMonitorEnabled,
		DNSAvailable:  svc.EASMDNS != nil,
		CTDefaultHrs:  int(cfg.Worker.CertMonitorInterval.Hours()),
		DNSDefaultHrs: int(cfg.Worker.EASMDNSInterval.Hours()),
	}
	return handler.NewEASMSettingsHandler(svc.Tenant, postgres.NewEASMSweepRepository(deps.DB), sweeper, platform, audit, log)
}

// newAssetAttributionHandler builds the attribution handler with its audit
// trail (RFC-036: every human attribution decision is audited).
func newAssetAttributionHandler(repos *Repositories, svc *Services, log *logger.Logger) *handler.AssetAttributionHandler {
	h := handler.NewAssetAttributionHandler(repos.Attribution, svc.Asset, log)
	if svc.ActiveGate != nil {
		h.SetActiveGate(svc.ActiveGate)
		h.SetScopeReader(svc.ActiveGate) // scope_status, covered_by (RFC-054 §6.6)
	}
	if svc.Audit != nil {
		h.SetAuditService(svc.Audit)
	}
	h.SetDecisionEffects(easmDecisionEffects(repos, svc, log))
	return h
}

// newAssetImportHandler builds the asset import handler with its audit trail.
func newAssetImportHandler(svc *Services, log *logger.Logger) *handler.AssetImportHandler {
	h := handler.NewAssetImportHandler(svc.AssetImport, log)
	h.SetAuditService(svc.Audit)
	return h
}

// newFindingImportHandler builds the handler of POST /findings/import: the
// ctis importers, ingest with the uploader's rights, VEX documents applied
// under INGEST_VEX.
func newFindingImportHandler(cfg *config.Config, repos *Repositories, svc *Services, log *logger.Logger) *handler.FindingImportHandler {
	imp := findingimport.NewService(svc.Ingest, repos.Finding, ingest.ParseVEXMode(cfg.Ingest.VEX), log)
	return handler.NewFindingImportHandler(imp, svc.DataScope, svc.Audit, log)
}

// newReportScheduleHandler builds the report schedule handler with its audit
// trail.
func newReportScheduleHandler(svc *Services, log *logger.Logger) *handler.ReportScheduleHandler {
	h := handler.NewReportScheduleHandler(svc.ReportSchedule, log)
	h.SetAuditService(svc.Audit)
	return h
}

// newSuppressionHandler wires the suppression handler with the tenant audit log
// (approvals, and self-approvals at Critical severity, are recorded there).
func newSuppressionHandler(svc *Services, log *logger.Logger) *handler.SuppressionHandler {
	h := handler.NewSuppressionHandler(svc.Suppression, log)
	h.SetAuditService(svc.Audit)
	return h
}

// newCIHandlers builds the CI run service and its two handlers (RFC-051).
// The CI providers' discovery and JWKS documents are fetched through the
// SSRF-safe client: a self-managed GitLab issuer is configured by a tenant.
func newCIHandlers(cfg *config.Config, repos *Repositories, svc *Services, log *logger.Logger) (*handler.CIAdminHandler, *handler.CIRunnerHandler) {
	if repos.CIRun == nil || svc.Ingest == nil {
		return nil, nil
	}
	verifier := oidc.NewClient(httpsec.SafeHTTPClient(10*time.Second), func(raw string) error {
		_, err := httpsec.ValidateURL(raw)
		return err
	})
	var audit cirunapp.Auditor
	if svc.Audit != nil {
		audit = svc.Audit
	}
	// Break-glass reaches every administrator (in-app) and the tenant's
	// channels subscribed to ci.break_glass.
	var admins cirunapp.AdminLister
	if repos.MemberLifecycle != nil {
		admins = repos.MemberLifecycle
	}
	var inApp cirunapp.InAppNotifier
	if svc.Notification != nil {
		inApp = svc.Notification
	}
	var ob cirunapp.Notifier
	if svc.Outbox != nil {
		ob = svc.Outbox
	}
	ciSvc := cirunapp.NewService(cirunapp.Deps{
		Repo:     repos.CIRun,
		Verifier: verifier,
		Assets:   repos.Asset,
		Branches: repos.Branch,
		Baseline: repos.Finding,
		Ingester: svc.Ingest,
		Units:    repos.CIRun,
		Audit:    audit,
		Alerts:   cirunapp.NewAdminAlerts(admins, inApp, ob, log),
	}, cirunapp.Config{WebBaseURL: cfg.SMTP.BaseURL, Versions: cirun.StatusPolicy{
		LatestVersion: sensordom.NormalizeVersion(cfg.SensorConfig.LatestVersion),
		MinVersion:    sensordom.NormalizeVersion(cfg.SensorConfig.MinVersion),
	}}, log)
	var ds handler.DataScopeEnforcer
	if svc.DataScope != nil {
		ds = svc.DataScope
	}
	admin := handler.NewCIAdminHandler(ciSvc, ds, log)
	admin.SetPipelineService(ciSvc)
	admin.SetCoverageService(ciSvc)
	admin.SetSettingsService(ciSvc)
	runner := handler.NewCIRunnerHandler(ciSvc, log)
	// VEX documents a run uploads: stored on the run repository's findings,
	// never closing any (the run token is not a person with findings:approve).
	runner.SetVEXApplier(findingimport.NewService(svc.Ingest, repos.Finding, ingest.ParseVEXMode(cfg.Ingest.VEX), log))
	return admin, runner
}

// newSensorPairingHandler builds the pairing handler (RFC-052); nil when
// pairing is disabled.
func newSensorPairingHandler(svc *Services, log *logger.Logger) *handler.SensorPairingHandler {
	if svc.SensorPairing == nil || svc.Sensor == nil {
		return nil
	}
	return handler.NewSensorPairingHandler(svc.SensorPairing, svc.Sensor, log)
}
