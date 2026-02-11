// Package routes registers all HTTP routes for the API.
// Routes are organized by domain for maintainability.
package routes

import (
	"net/http"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/config"
	infrahttp "github.com/openctemio/api/internal/infra/http"
	"github.com/openctemio/api/internal/infra/http/handler"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/internal/infra/websocket"
	"github.com/openctemio/api/pkg/domain/tenant"
	"github.com/openctemio/api/pkg/jwt"
	"github.com/openctemio/api/pkg/keycloak"
	"github.com/openctemio/api/pkg/logger"
)

// Middleware is an alias to the http package's Middleware type.
type Middleware = infrahttp.Middleware

// Router is an alias to the http package's Router interface.
type Router = infrahttp.Router

// Handlers holds all HTTP handlers for route registration.
type Handlers struct {
	Health          *handler.HealthHandler
	Auth            *handler.AuthHandler            // OIDC auth info handler
	LocalAuth       *handler.LocalAuthHandler       // Local auth handler (nil if OIDC-only)
	OAuth           *handler.OAuthHandler           // OAuth handler for social login (nil if not configured)
	Asset           *handler.AssetHandler           // nil if not initialized (no database)
	Tenant          *handler.TenantHandler          // nil if not initialized (no database)
	User            *handler.UserHandler            // nil if not initialized (no database)
	Component       *handler.ComponentHandler       // nil if not initialized (no database)
	Vulnerability   *handler.VulnerabilityHandler   // nil if not initialized (no database)
	FindingActivity *handler.FindingActivityHandler // nil if not initialized (no database)
	// Note: Real-time updates moved to WebSocket (see WebSocket field below)
	AITriage        *handler.AITriageHandler        // Always initialized - handles nil service gracefully
	Dashboard       *handler.DashboardHandler       // nil if not initialized (no database)
	Audit           *handler.AuditHandler           // nil if not initialized (no database)
	Branch          *handler.BranchHandler          // nil if not initialized (no database)
	SLA             *handler.SLAHandler             // nil if not initialized (no database)
	Integration     *handler.IntegrationHandler     // nil if not initialized (no database)
	AssetGroup      *handler.AssetGroupHandler      // nil if not initialized (no database)
	Scope           *handler.ScopeHandler           // nil if not initialized (no database)
	AssetType       *handler.AssetTypeHandler       // nil if not initialized (no database)
	AttackSurface   *handler.AttackSurfaceHandler   // nil if not initialized (no database)
	Docs            *handler.DocsHandler            // API documentation handler
	Command         *handler.CommandHandler         // nil if not initialized (no database)
	Ingest          *handler.IngestHandler          // nil if not initialized (no database) - unified ingestion (CTIS, SARIF, Recon)
	Agent           *handler.AgentHandler           // nil if not initialized (no database)
	Pipeline        *handler.PipelineHandler        // nil if not initialized (no database)
	ScanProfile     *handler.ScanProfileHandler     // nil if not initialized (no database)
	Tool            *handler.ToolHandler            // nil if not initialized (no database)
	ToolCategory    *handler.ToolCategoryHandler    // nil if not initialized (no database)
	Capability      *handler.CapabilityHandler      // nil if not initialized (no database)
	Scan            *handler.ScanHandler            // nil if not initialized (no database)
	ScanSession     *handler.ScanSessionHandler     // nil if not initialized (no database)
	ScannerTemplate *handler.ScannerTemplateHandler // nil if not initialized (no database)
	TemplateSource  *handler.TemplateSourceHandler  // nil if not initialized (no database)
	SecretStore     *handler.SecretStoreHandler     // nil if not initialized (no database)

	Exposure         *handler.ExposureHandler         // nil if not initialized (no database)
	ThreatIntel      *handler.ThreatIntelHandler      // nil if not initialized (no database)
	CredentialImport *handler.CredentialImportHandler // nil if not initialized (no database)
	Workflow         *handler.WorkflowHandler         // nil if not initialized (no database)
	Suppression      *handler.SuppressionHandler      // nil if not initialized (no database)

	// CTEM Discovery handlers
	AssetService      *handler.AssetServiceHandler      // nil if not initialized (no database)
	AssetStateHistory *handler.AssetStateHistoryHandler // nil if not initialized (no database)
	AssetRelationship *handler.AssetRelationshipHandler // nil if not initialized (no database)

	// Access Control handlers
	Group         *handler.GroupHandler         // nil if not initialized (no database)
	PermissionSet *handler.PermissionSetHandler // nil if not initialized (no database)
	Role          *handler.RoleHandler          // nil if not initialized (no database)
	Permission    *handler.PermissionHandler    // nil if not initialized (permission sync handler)

	// Configuration handlers (read-only system config)
	FindingSource *handler.FindingSourceHandler // nil if not initialized (no database)

	// API Keys & Webhooks
	APIKey  *handler.APIKeyHandler  // nil if not initialized (no database)
	Webhook *handler.WebhookHandler // nil if not initialized (no database)

	// Notification handlers
	NotificationOutbox *handler.NotificationOutboxHandler // nil if not initialized (no database)

	// Bootstrap handler (combines multiple endpoints into one)
	Bootstrap *handler.BootstrapHandler // nil if not initialized (no database)

	// Admin Auth handler (API key authentication for Admin UI)
	AdminAuth           *handler.AdminAuthHandler
	AdminAuthMiddleware *middleware.AdminAuthMiddleware

	// Admin Audit middleware (audit logging for admin operations)
	AdminAuditMiddleware *middleware.AuditMiddleware

	// Admin Mapping rate limiter (10 req/min for write operations)
	AdminMappingRateLimiter *middleware.AdminMappingRateLimiter

	// Admin management handlers (CRUD for admin users, audit logs, target mappings)
	AdminUser          *handler.AdminUserHandler
	AdminAudit         *handler.AdminAuditHandler
	AdminTargetMapping *handler.AdminTargetMappingHandler

	// WebSocket handler for real-time communication
	WebSocket *websocket.Handler
}

// AuthConfig holds authentication configuration for route registration.
type AuthConfig struct {
	Provider       config.AuthProvider
	LocalValidator *jwt.Generator
	OIDCValidator  *keycloak.Validator
}

// Register registers all application routes.
// This keeps route definitions in the infrastructure layer, not in main.
//
// Routes are organized across multiple files by domain:
//   - auth.go: Authentication (login, register, OAuth)
//   - tenant.go: Tenant management
//   - assets.go: Assets, components, asset groups, scope
//   - scanning.go: Agents, commands, scans, pipelines, tools
//   - exposure.go: Exposures, threat intel, credentials
//   - access_control.go: Groups, roles, permissions
//   - platform.go: Platform agents and jobs
//   - misc.go: Health, docs, dashboard, audit, SLA, integrations
//
//nolint:cyclop,gocognit // Route registration naturally has many branches
func Register(
	router Router,
	h Handlers,
	cfg *config.Config,
	log *logger.Logger,
	authCfg AuthConfig,
	tenantRepo tenant.Repository,
	userService *app.UserService,
	moduleService *app.ModuleService,
) {
	// Create unified auth middleware based on provider
	unifiedAuthCfg := middleware.UnifiedAuthConfig{
		Provider:       authCfg.Provider,
		LocalValidator: authCfg.LocalValidator,
		OIDCValidator:  authCfg.OIDCValidator,
		Logger:         log,
	}
	authMiddleware := middleware.UnifiedAuth(unifiedAuthCfg)

	// Health routes (public)
	registerHealthRoutes(router, h.Health)

	// API Documentation routes (public)
	if h.Docs != nil {
		registerDocsRoutes(router, h.Docs)
	}

	// Auth routes - based on provider (some protected, some public)
	registerAuthRoutes(router, h, authCfg, authMiddleware)

	// UserSync middleware syncs authenticated users to local database
	// Supports both local auth and OIDC auth
	var userSync Middleware
	if userService != nil {
		userSync = middleware.UserSync(userService, log)
	}

	// User routes (protected with user sync for OIDC)
	if h.User != nil {
		registerUserRoutes(router, h.User, h.LocalAuth, authMiddleware, userSync, authCfg.Provider)
	}

	// Tenant routes (protected with user sync)
	if h.Tenant != nil {
		registerTenantRoutes(router, h.Tenant, authMiddleware, userSync, tenantRepo, h.LocalAuth)
	}

	// Asset routes (tenant from JWT token) - only if handler is initialized
	if h.Asset != nil {
		registerAssetRoutes(router, h.Asset, authMiddleware, userSync, moduleService)
	}

	// Component routes (tenant from JWT token)
	if h.Component != nil {
		registerComponentRoutes(router, h.Component, authMiddleware, userSync, moduleService)
	}

	// Asset Service routes (CTEM Discovery - network services on assets)
	if h.AssetService != nil {
		registerAssetServiceRoutes(router, h.AssetService, authMiddleware, userSync, moduleService)
	}

	// Asset State History routes (CTEM Discovery - shadow IT detection, audit)
	if h.AssetStateHistory != nil {
		registerAssetStateHistoryRoutes(router, h.AssetStateHistory, authMiddleware, userSync, moduleService)
	}

	// Asset Relationship routes (CTEM Discovery - attack surface topology graph)
	if h.AssetRelationship != nil {
		registerAssetRelationshipRoutes(router, h.AssetRelationship, authMiddleware, userSync, moduleService)
	}

	// Vulnerability routes (global) and Finding routes (tenant from JWT token)
	if h.Vulnerability != nil {
		registerVulnerabilityRoutes(router, h.Vulnerability, authMiddleware, userSync, moduleService)
	}

	// Initialize finding activity rate limiter to prevent enumeration and DoS
	var activityRateLimiter *middleware.FindingActivityRateLimiter
	if cfg.RateLimit.Enabled {
		activityRateLimiter = middleware.NewFindingActivityRateLimiter(middleware.DefaultFindingActivityRateLimitConfig(), log)
	}

	// Finding Activity routes (tenant from JWT token)
	// Note: Real-time updates are delivered via WebSocket (channel: finding:{id})
	if h.FindingActivity != nil {
		registerFindingActivityRoutes(router, h.FindingActivity, authMiddleware, userSync, activityRateLimiter)
	}

	// Initialize AI triage rate limiter to prevent abuse of expensive LLM calls
	var aiTriageRateLimiter *middleware.AITriageRateLimiter
	if cfg.RateLimit.Enabled {
		aiTriageRateLimiter = middleware.NewAITriageRateLimiter(middleware.DefaultAITriageRateLimitConfig(), log)
	}

	// AI Triage routes (tenant from JWT token)
	// Always registered - handler handles nil service gracefully
	// Feature gating is done via RequireModule middleware (checks is_active in database)
	if h.AITriage != nil {
		registerAITriageRoutes(router, h.AITriage, authMiddleware, userSync, aiTriageRateLimiter, moduleService)
	}

	// Dashboard routes (global and tenant from JWT token)
	if h.Dashboard != nil {
		registerDashboardRoutes(router, h.Dashboard, authMiddleware, userSync)
	}

	// Audit log routes (tenant from JWT token)
	if h.Audit != nil {
		registerAuditRoutes(router, h.Audit, authMiddleware, userSync, moduleService)
	}

	// Branch routes (asset-scoped, tenant from JWT token)
	if h.Branch != nil {
		registerBranchRoutes(router, h.Branch, authMiddleware, userSync)
	}

	// SLA Policy routes (tenant from JWT token)
	if h.SLA != nil {
		registerSLARoutes(router, h.SLA, authMiddleware, userSync)
	}

	// Integration routes (tenant from JWT token)
	if h.Integration != nil {
		registerIntegrationRoutes(router, h.Integration, authMiddleware, userSync, moduleService)
	}

	// Asset Group routes (tenant from JWT token)
	if h.AssetGroup != nil {
		registerAssetGroupRoutes(router, h.AssetGroup, authMiddleware, userSync, moduleService)
	}

	// Scope Configuration routes (tenant from JWT token)
	if h.Scope != nil {
		registerScopeRoutes(router, h.Scope, authMiddleware, userSync)
	}

	// Asset Type routes (tenant from JWT token)
	if h.AssetType != nil {
		registerAssetTypeRoutes(router, h.AssetType, authMiddleware, userSync)
	}

	// Finding Source routes (read-only system configuration)
	if h.FindingSource != nil {
		registerFindingSourceRoutes(router, h.FindingSource, authMiddleware, userSync)
	}

	// Attack Surface routes (tenant from JWT token)
	if h.AttackSurface != nil {
		registerAttackSurfaceRoutes(router, h.AttackSurface, authMiddleware, userSync)
	}

	// Command routes (tenant from JWT token)
	if h.Command != nil {
		registerCommandRoutes(router, h.Command, authMiddleware, userSync)
	}

	// Ingest/Agent routes (API key authenticated)
	if h.Ingest != nil && h.Command != nil {
		registerAgentRoutes(router, h.Ingest, h.Command, h.ScanSession, moduleService)
	}

	// Agent management routes (tenant from JWT token)
	if h.Agent != nil {
		registerAgentManagementRoutes(router, h.Agent, nil, authMiddleware, userSync, moduleService)
	}

	// Initialize trigger rate limiter for pipeline/scan trigger endpoints
	// This prevents abuse and ensures fair resource usage across tenants
	var triggerRateLimiter *middleware.TriggerRateLimiter
	if cfg.RateLimit.Enabled {
		triggerRateLimiter = middleware.NewTriggerRateLimiter(middleware.DefaultTriggerRateLimitConfig(), log)
	}

	// Pipeline routes (tenant from JWT token)
	if h.Pipeline != nil {
		registerPipelineRoutes(router, h.Pipeline, authMiddleware, userSync, triggerRateLimiter)
	}

	// Scan Profile routes (tenant from JWT token)
	if h.ScanProfile != nil {
		registerScanProfileRoutes(router, h.ScanProfile, authMiddleware, userSync, moduleService)
	}

	// Tool Registry routes (tenant from JWT token for tenant tools)
	if h.Tool != nil {
		registerToolRoutes(router, h.Tool, authMiddleware, userSync)
	}

	// Tool Category routes (tenant from JWT token)
	if h.ToolCategory != nil {
		registerToolCategoryRoutes(router, h.ToolCategory, authMiddleware, userSync)
	}

	// Capability routes (tenant from JWT token)
	if h.Capability != nil {
		registerCapabilityRoutes(router, h.Capability, authMiddleware, userSync)
	}

	// Scan routes (tenant from JWT token)
	if h.Scan != nil {
		registerScanRoutes(router, h.Scan, authMiddleware, userSync, moduleService, triggerRateLimiter)
	}

	// Scan Session routes (tenant from JWT token for admin, API key for agent)
	if h.ScanSession != nil {
		registerScanSessionRoutes(router, h.ScanSession, authMiddleware, userSync)
	}

	// Scanner Template routes (tenant from JWT token)
	if h.ScannerTemplate != nil {
		registerScannerTemplateRoutes(router, h.ScannerTemplate, authMiddleware, userSync, moduleService)
	}

	// Template Source routes (tenant from JWT token)
	if h.TemplateSource != nil {
		registerTemplateSourceRoutes(router, h.TemplateSource, authMiddleware, userSync, moduleService)
	}

	// Secret Store routes (tenant from JWT token)
	if h.SecretStore != nil {
		registerSecretStoreRoutes(router, h.SecretStore, authMiddleware, userSync, moduleService)
	}

	// Workflow routes (tenant from JWT token)
	if h.Workflow != nil {
		registerWorkflowRoutes(router, h.Workflow, authMiddleware, userSync)
	}

	// Suppression routes (tenant from JWT token)
	if h.Suppression != nil {
		registerSuppressionRoutes(router, h.Suppression, authMiddleware, userSync)
	}

	// Exposure routes (tenant from JWT token)
	if h.Exposure != nil {
		registerExposureRoutes(router, h.Exposure, authMiddleware, userSync)
	}

	// Threat Intelligence routes (global threat intel data)
	if h.ThreatIntel != nil {
		registerThreatIntelRoutes(router, h.ThreatIntel, authMiddleware, userSync)
	}

	// Credential Import routes (tenant from JWT token)
	if h.CredentialImport != nil {
		registerCredentialRoutes(router, h.CredentialImport, h.Ingest, authMiddleware, userSync, moduleService)
	}

	// Group routes (Access Control - tenant from JWT token)
	if h.Group != nil {
		registerGroupRoutes(router, h.Group, authMiddleware, userSync)
	}

	// Permission Set routes (Access Control - tenant from JWT token)
	if h.PermissionSet != nil {
		registerPermissionSetRoutes(router, h.PermissionSet, authMiddleware, userSync)
	}

	// Permission Sync routes (real-time permission sync with ETag support)
	if h.Permission != nil {
		registerPermissionSyncRoutes(router, h.Permission, authMiddleware, userSync)
	}

	// Role routes (Access Control - tenant from JWT token)
	if h.Role != nil {
		registerRoleRoutes(router, h.Role, authMiddleware, userSync)
	}

	// API Key routes (tenant from JWT token)
	if h.APIKey != nil {
		registerAPIKeyRoutes(router, h.APIKey, authMiddleware, userSync, moduleService)
	}

	// Webhook routes (tenant from JWT token)
	if h.Webhook != nil {
		registerWebhookRoutes(router, h.Webhook, authMiddleware, userSync, moduleService)
	}

	// Notification Outbox routes (tenant from JWT token)
	if h.NotificationOutbox != nil {
		registerNotificationOutboxRoutes(router, h.NotificationOutbox, authMiddleware, userSync)
	}

	// Bootstrap route (combines permissions, subscription, modules, dashboard)
	if h.Bootstrap != nil {
		registerBootstrapRoutes(router, h.Bootstrap, authMiddleware, userSync)
	}

	// ==========================================================================
	// Platform Admin Routes (separate from tenant routes)
	// ==========================================================================
	// These routes are for OpenCTEM platform administrators only.
	// They manage shared infrastructure that serves all tenants.
	registerAdminRoutes(router, h, authMiddleware, userSync)

	// ==========================================================================
	// WebSocket Routes (protected with auth)
	// ==========================================================================
	// WebSocket endpoint for real-time features (activities, scans, notifications)
	if h.WebSocket != nil {
		registerWebSocketRoutes(router, h.WebSocket, authMiddleware, userSync)
	}
}

// =============================================================================
// Middleware Helpers
// =============================================================================

// buildBaseMiddlewares builds a middleware chain with auth and optional user sync.
func buildBaseMiddlewares(authMiddleware, userSyncMiddleware Middleware) []Middleware {
	middlewares := []Middleware{authMiddleware}
	if userSyncMiddleware != nil {
		middlewares = append(middlewares, userSyncMiddleware)
	}
	return middlewares
}

// buildTokenTenantMiddlewares builds a middleware chain for token-based tenant routes.
// This uses tenant ID from JWT claims instead of URL path.
// Best practice: tenant-scoped access tokens eliminate IDOR by design.
func buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware Middleware) []Middleware {
	middlewares := buildBaseMiddlewares(authMiddleware, userSyncMiddleware)
	return append(middlewares, middleware.RequireTenant())
}

// ChainFunc wraps a handler function with middleware(s).
// Returns the final handler after applying all middleware in order.
func ChainFunc(handler http.HandlerFunc, middlewares ...Middleware) http.Handler {
	return infrahttp.ChainFunc(handler, middlewares...)
}
