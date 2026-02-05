package routes

import (
	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/infra/http/handler"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/domain/module"
	"github.com/openctemio/api/pkg/domain/permission"
)

// registerExposureRoutes registers exposure event management endpoints.
// Exposures are tenant-scoped attack surface changes.
func registerExposureRoutes(
	router Router,
	h *handler.ExposureHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
) {
	// Build tenant middleware chain from JWT token
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	// Exposure routes - tenant from JWT token
	router.Group("/api/v1/exposures", func(r Router) {
		// Stats endpoint (must be before /{id} to avoid matching)
		r.GET("/stats", h.GetStats, middleware.Require(permission.FindingsRead))

		// Bulk ingest (must be before /{id} to avoid matching)
		r.POST("/ingest", h.BulkIngest, middleware.Require(permission.FindingsWrite))

		// Read operations
		r.GET("/", h.List, middleware.Require(permission.FindingsRead))
		r.GET("/{id}", h.Get, middleware.Require(permission.FindingsRead))

		// Write operations
		r.POST("/", h.Create, middleware.Require(permission.FindingsWrite))

		// State transitions
		r.POST("/{id}/resolve", h.Resolve, middleware.Require(permission.FindingsWrite))
		r.POST("/{id}/accept", h.Accept, middleware.Require(permission.FindingsWrite))
		r.POST("/{id}/false-positive", h.MarkFalsePositive, middleware.Require(permission.FindingsWrite))
		r.POST("/{id}/reactivate", h.Reactivate, middleware.Require(permission.FindingsWrite))

		// History
		r.GET("/{id}/history", h.GetHistory, middleware.Require(permission.FindingsRead))

		// Delete operations
		r.DELETE("/{id}", h.Delete, middleware.Require(permission.FindingsDelete))
	}, tenantMiddlewares...)
}

// registerThreatIntelRoutes registers threat intelligence endpoints.
// Threat intel provides global EPSS scores and KEV catalog data.
// Permission model:
// - Read (GET): vulnerabilities:read permission
// - Write (POST, PATCH): admin only
func registerThreatIntelRoutes(
	router Router,
	h *handler.ThreatIntelHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
) {
	// Build base middleware chain (no tenant required - global data)
	baseMiddlewares := buildBaseMiddlewares(authMiddleware, userSyncMiddleware)

	// Threat Intel routes - global data accessible to authenticated users
	router.Group("/api/v1/threat-intel", func(r Router) {
		// Unified stats endpoint (combines EPSS, KEV, and sync status)
		r.GET("/stats", h.GetThreatIntelStats, middleware.Require(permission.VulnerabilitiesRead))

		// Sync status and management (admin operations)
		r.GET("/sync", h.GetSyncStatuses, middleware.Require(permission.VulnerabilitiesRead))
		r.GET("/sync/{source}", h.GetSyncStatus, middleware.Require(permission.VulnerabilitiesRead))
		r.POST("/sync", h.TriggerSync, middleware.Require(permission.VulnerabilitiesWrite))
		r.PATCH("/sync/{source}", h.SetSyncEnabled, middleware.Require(permission.VulnerabilitiesWrite))

		// CVE enrichment (combine EPSS + KEV data)
		r.GET("/enrich/{cve_id}", h.EnrichCVE, middleware.Require(permission.VulnerabilitiesRead))
		r.POST("/enrich", h.EnrichCVEs, middleware.Require(permission.VulnerabilitiesRead))

		// EPSS scores (must have stats before {cve_id} to avoid route conflicts)
		r.GET("/epss/stats", h.GetEPSSStats, middleware.Require(permission.VulnerabilitiesRead))
		r.GET("/epss/{cve_id}", h.GetEPSSScore, middleware.Require(permission.VulnerabilitiesRead))

		// KEV catalog (must have stats before {cve_id} to avoid route conflicts)
		r.GET("/kev/stats", h.GetKEVStats, middleware.Require(permission.VulnerabilitiesRead))
		r.GET("/kev/{cve_id}", h.GetKEVEntry, middleware.Require(permission.VulnerabilitiesRead))
	}, baseMiddlewares...)
}

// registerCredentialRoutes registers credential leak management endpoints.
// Credentials are tenant-scoped (tenant from JWT token).
// Two sets of routes:
// 1. Admin routes (JWT auth): /api/v1/credentials - import, stats, management
// 2. Agent routes (API key auth): /api/v1/agent/credentials - ingest from agents
//
// Module check: Requires "credentials" module to be enabled.
func registerCredentialRoutes(
	router Router,
	h *handler.CredentialImportHandler,
	ingestHandler *handler.IngestHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
	moduleService *app.ModuleService,
) {
	// Build tenant middleware chain from JWT token
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	// Credential routes - tenant from JWT token (admin interface)
	router.Group("/api/v1/credentials", func(r Router) {
		// List credentials (must be before /{id} to avoid conflicts)
		r.GET("/", h.List, middleware.Require(permission.CredentialsRead))

		// Stats endpoint (must be before other routes to avoid conflicts)
		r.GET("/stats", h.GetStats, middleware.Require(permission.CredentialsRead))

		// Enum values (for UI dropdowns)
		r.GET("/enums", h.GetEnums, middleware.Require(permission.CredentialsRead))

		// Identity-centric view (credentials grouped by username/email)
		r.GET("/identities", h.ListByIdentity, middleware.Require(permission.CredentialsRead))

		// Get exposures for a specific identity (lazy load)
		r.GET("/identities/{identity}/exposures", h.GetExposuresForIdentity, middleware.Require(permission.CredentialsRead))

		// Import endpoints
		r.POST("/import", h.Import, middleware.Require(permission.CredentialsWrite))
		r.POST("/import/csv", h.ImportCSV, middleware.Require(permission.CredentialsWrite))
		r.GET("/import/template", h.GetTemplate, middleware.Require(permission.CredentialsRead))

		// Get single credential by ID
		r.GET("/{id}", h.GetByID, middleware.Require(permission.CredentialsRead))

		// Get related credentials (same identity)
		r.GET("/{id}/related", h.GetRelatedCredentials, middleware.Require(permission.CredentialsRead))

		// State change endpoints
		r.POST("/{id}/resolve", h.Resolve, middleware.Require(permission.CredentialsWrite))
		r.POST("/{id}/accept", h.Accept, middleware.Require(permission.CredentialsWrite))
		r.POST("/{id}/false-positive", h.MarkFalsePositive, middleware.Require(permission.CredentialsWrite))
		r.POST("/{id}/reactivate", h.Reactivate, middleware.Require(permission.CredentialsWrite))
	}, tenantMiddlewares...)

	// Agent routes for credential ingest (API key auth) - only if ingest handler exists
	// Module check: Requires "credentials" module to be enabled.
	if ingestHandler != nil {
		agentProvider := middleware.AgentContextProviderFunc(handler.AgentFromContext)

		// Build middleware chain: API key auth + credentials module check
		agentMiddlewares := []Middleware{ingestHandler.AuthenticateSource}
		if moduleService != nil {
			agentMiddlewares = append(
				agentMiddlewares,
				middleware.RequireModuleForAgent(moduleService, agentProvider, module.ModuleCredentials),
			)
		}

		router.Group("/api/v1/agent/credentials", func(r Router) {
			// Ingest credentials from agents
			r.POST("/ingest", h.Import)
		}, agentMiddlewares...)
	}
}

// registerVulnerabilityRoutes registers vulnerability and finding management endpoints.
// Vulnerabilities are global (CVE database), Findings are tenant-scoped (tenant from JWT token).
//
// Module check: Findings routes require "findings" module to be enabled.
// Vulnerabilities are global CVE database and don't require module check.
func registerVulnerabilityRoutes(
	router Router,
	h *handler.VulnerabilityHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
	moduleService *app.ModuleService,
) {
	// Build base middleware chain
	baseMiddlewares := buildBaseMiddlewares(authMiddleware, userSyncMiddleware)

	// Vulnerability routes - global CVE database (no tenant required, no module check)
	router.Group("/api/v1/vulnerabilities", func(r Router) {
		// Read operations
		r.GET("/", h.ListVulnerabilities, middleware.Require(permission.VulnerabilitiesRead))
		r.GET("/{id}", h.GetVulnerability, middleware.Require(permission.VulnerabilitiesRead))
		r.GET("/cve/{cve_id}", h.GetVulnerabilityByCVE, middleware.Require(permission.VulnerabilitiesRead))

		// Write operations (admin only)
		r.POST("/", h.CreateVulnerability, middleware.Require(permission.VulnerabilitiesWrite))
		r.PUT("/{id}", h.UpdateVulnerability, middleware.Require(permission.VulnerabilitiesWrite))
		r.DELETE("/{id}", h.DeleteVulnerability, middleware.Require(permission.VulnerabilitiesDelete))
	}, baseMiddlewares...)

	// Build tenant middleware chain from JWT token
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	// Add module check middleware for findings routes
	if moduleService != nil {
		tenantMiddlewares = append(tenantMiddlewares, middleware.RequireModule(moduleService, module.ModuleFindings))
	}

	// Finding routes - tenant from JWT token
	router.Group("/api/v1/findings", func(r Router) {
		// Read operations
		r.GET("/", h.ListFindings, middleware.Require(permission.FindingsRead))

		// Stats endpoint (must be before /{id} to avoid route conflicts)
		r.GET("/stats", h.GetFindingStats, middleware.Require(permission.FindingsRead))

		// Bulk operations (must be before /{id} to avoid route conflicts)
		r.POST("/bulk/status", h.BulkUpdateFindingsStatus, middleware.Require(permission.FindingsWrite))
		r.POST("/bulk/assign", h.BulkAssignFindings, middleware.Require(permission.FindingsWrite))

		// Single finding operations
		r.GET("/{id}", h.GetFinding, middleware.Require(permission.FindingsRead))

		// Write operations
		r.POST("/", h.CreateFinding, middleware.Require(permission.FindingsWrite))
		r.PATCH("/{id}/status", h.UpdateFindingStatus, middleware.Require(permission.FindingsWrite))

		// Assignment operations
		r.POST("/{id}/assign", h.AssignFinding, middleware.Require(permission.FindingsWrite))
		r.POST("/{id}/unassign", h.UnassignFinding, middleware.Require(permission.FindingsWrite))

		// Classification and severity
		r.PATCH("/{id}/classify", h.ClassifyFinding, middleware.Require(permission.FindingsWrite))
		r.PATCH("/{id}/severity", h.UpdateFindingSeverity, middleware.Require(permission.FindingsWrite))

		// Triage and verification
		r.PATCH("/{id}/triage", h.TriageFinding, middleware.Require(permission.FindingsWrite))
		r.POST("/{id}/verify", h.VerifyFinding, middleware.Require(permission.FindingsWrite))

		// Tags
		r.PUT("/{id}/tags", h.SetFindingTags, middleware.Require(permission.FindingsWrite))

		// Data flows (attack paths / taint tracking)
		r.GET("/{id}/dataflows", h.GetFindingDataFlows, middleware.Require(permission.FindingsRead))

		// Delete operations
		r.DELETE("/{id}", h.DeleteFinding, middleware.Require(permission.FindingsDelete))
	}, tenantMiddlewares...)

	// Asset-scoped finding routes
	router.Group("/api/v1/assets/{id}/findings", func(r Router) {
		r.GET("/", h.ListAssetFindings, middleware.Require(permission.FindingsRead))
	}, tenantMiddlewares...)

	// Finding comment routes - tenant from JWT token
	router.Group("/api/v1/findings/{id}/comments", func(r Router) {
		r.GET("/", h.ListComments, middleware.Require(permission.FindingsRead))
		r.POST("/", h.AddComment, middleware.Require(permission.FindingsWrite))
		r.PUT("/{comment_id}", h.UpdateComment, middleware.Require(permission.FindingsWrite))
		r.DELETE("/{comment_id}", h.DeleteComment, middleware.Require(permission.FindingsWrite))
	}, tenantMiddlewares...)
}

// registerFindingActivityRoutes registers finding activity endpoints.
// Activities are tenant-scoped (tenant from JWT token) and APPEND-ONLY.
// Rate limiting is applied to prevent enumeration and DoS attacks.
// Real-time updates are delivered via WebSocket (see registerWebSocketRoutes in misc.go).
func registerFindingActivityRoutes(
	router Router,
	h *handler.FindingActivityHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
	rateLimiter *middleware.FindingActivityRateLimiter,
) {
	// Build tenant middleware chain from JWT token
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	// Add rate limiting middleware if enabled
	if rateLimiter != nil {
		tenantMiddlewares = append(tenantMiddlewares, rateLimiter.ListMiddleware())
	}

	// Finding activity routes - tenant from JWT token
	router.Group("/api/v1/findings/{id}/activities", func(r Router) {
		r.GET("/", h.ListActivities, middleware.Require(permission.FindingsRead))
		r.GET("/{activity_id}", h.GetActivity, middleware.Require(permission.FindingsRead))
		// Note: Activities are created automatically via service hooks, not via direct API
		// Real-time updates are delivered via WebSocket channel: finding:{id}
	}, tenantMiddlewares...)
}

// registerAITriageRoutes registers AI triage endpoints.
// AI triage is tenant-scoped (tenant from JWT token).
// Rate limiting is applied to POST endpoints to prevent abuse of expensive LLM calls.
// Module check middleware ensures feature is only accessible when ai_triage module is active.
//
// Endpoints:
// - POST /api/v1/findings/{id}/ai-triage - Request AI triage for a finding (rate-limited)
// - POST /api/v1/findings/ai-triage/bulk - Bulk triage multiple findings (rate-limited)
// - GET /api/v1/findings/{id}/ai-triage - Get latest triage result
// - GET /api/v1/findings/{id}/ai-triage/history - Get triage history
// - GET /api/v1/findings/{id}/ai-triage/{triage_id} - Get specific triage result
// - GET /api/v1/ai-triage/config - Get AI configuration info
func registerAITriageRoutes(
	router Router,
	h *handler.AITriageHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
	rateLimiter *middleware.AITriageRateLimiter,
	moduleService *app.ModuleService,
) {
	// Build tenant middleware chain from JWT token
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	// Add module check middleware - returns 403 if ai_triage module is not active
	// This checks the is_active field in the modules table
	if moduleService != nil {
		tenantMiddlewares = append(tenantMiddlewares, middleware.RequireModule(moduleService, module.ModuleAITriage))
	}

	// Add rate limiter to POST endpoints if available
	var postMiddlewares []Middleware
	postMiddlewares = append(postMiddlewares, tenantMiddlewares...)
	if rateLimiter != nil {
		postMiddlewares = append(postMiddlewares, rateLimiter.RequestMiddleware())
	}

	// AI triage routes - tenant from JWT token
	router.Group("/api/v1/findings/{id}/ai-triage", func(r Router) {
		// Get latest triage result (must be before /{triage_id} to avoid conflicts)
		r.GET("/", h.GetTriageResult, middleware.Require(permission.FindingsRead))

		// Get triage history (must be before /{triage_id} to avoid conflicts)
		r.GET("/history", h.ListTriageHistory, middleware.Require(permission.FindingsRead))

		// Get specific triage result by ID
		r.GET("/{triage_id}", h.GetTriageResultByID, middleware.Require(permission.FindingsRead))
	}, tenantMiddlewares...)

	// Trigger AI triage for a finding (rate-limited)
	router.POST("/api/v1/findings/{id}/ai-triage", h.RequestTriage,
		append(postMiddlewares, middleware.Require(permission.FindingsWrite))...)

	// Bulk triage multiple findings (rate-limited)
	// Note: Bulk endpoint uses same rate limiter - each finding in bulk counts toward limit
	router.POST("/api/v1/findings/ai-triage/bulk", h.RequestBulkTriage,
		append(postMiddlewares, middleware.Require(permission.FindingsWrite))...)

	// AI triage config endpoint - returns current AI mode, provider, model
	// Note: This endpoint also goes through module check - returns 403 if module not active
	// The handler returns is_enabled: false if service is not configured
	router.GET("/api/v1/ai-triage/config", h.GetConfig, tenantMiddlewares...)
}
