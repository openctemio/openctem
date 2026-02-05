package routes

import (
	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/infra/http/handler"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/domain/module"
	"github.com/openctemio/api/pkg/domain/permission"
)

// registerCommandRoutes registers command management endpoints.
// Commands are server-side instructions sent to agents.
func registerCommandRoutes(
	router Router,
	h *handler.CommandHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
) {
	// Build tenant middleware chain from JWT token
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	// Command routes - tenant from JWT token (admin interface)
	router.Group("/api/v1/commands", func(r Router) {
		// Read operations
		r.GET("/", h.List, middleware.Require(permission.CommandsRead))
		r.GET("/{id}", h.Get, middleware.Require(permission.CommandsRead))

		// Write operations
		r.POST("/", h.Create, middleware.Require(permission.CommandsWrite))
		r.POST("/{id}/cancel", h.Cancel, middleware.Require(permission.CommandsWrite))

		// Delete operations
		r.DELETE("/{id}", h.Delete, middleware.Require(permission.CommandsDelete))
	}, tenantMiddlewares...)
}

// registerAgentRoutes registers agent API endpoints.
// These endpoints are authenticated using source API keys (not JWT).
//
// Module check: Requires "scans" module to be enabled for ingest/command/scan operations.
// Heartbeat endpoint is always allowed for agent health monitoring.
func registerAgentRoutes(
	router Router,
	ingestHandler *handler.IngestHandler,
	commandHandler *handler.CommandHandler,
	scanSessionHandler *handler.ScanSessionHandler,
	moduleService *app.ModuleService,
) {
	// Create agent context provider for module middleware
	agentProvider := middleware.AgentContextProviderFunc(handler.AgentFromContext)

	// Build middleware chain: API key auth + module gating
	baseMiddleware := ingestHandler.AuthenticateSource

	// Middleware with scans module check
	var scansModuleMiddleware Middleware
	if moduleService != nil {
		scansModuleMiddleware = middleware.RequireModuleForAgent(
			moduleService,
			agentProvider,
			module.ModuleScans,
		)
	}

	// Decompression middleware for ingest endpoints (supports gzip and zstd)
	decompressMiddleware := middleware.DecompressForIngest()

	// Agent routes - authenticated via API key
	router.Group("/api/v1/agent", func(r Router) {
		// Heartbeat - NO module gating (essential for agent health monitoring)
		// Agents need to report status even if tenant loses access
		r.POST("/heartbeat", ingestHandler.Heartbeat)

		// Ingest findings/assets - requires "scans" module
		// Supported formats: EIS (native), SARIF (industry standard), Recon (discovery data), Chunk (for large reports)
		// All ingest endpoints support compressed request bodies (Content-Encoding: gzip or zstd)
		if scansModuleMiddleware != nil {
			r.POST("/ingest", ingestHandler.IngestEIS, decompressMiddleware, scansModuleMiddleware) // Default: EIS format
			r.POST("/ingest/check", ingestHandler.CheckFingerprints, decompressMiddleware, scansModuleMiddleware)
			r.POST("/ingest/sarif", ingestHandler.IngestSARIF, decompressMiddleware, scansModuleMiddleware)
			r.POST("/ingest/eis", ingestHandler.IngestEIS, decompressMiddleware, scansModuleMiddleware)
			r.POST("/ingest/recon", ingestHandler.IngestReconReport, decompressMiddleware, scansModuleMiddleware)
			r.POST("/ingest/chunk", ingestHandler.IngestChunk, decompressMiddleware, scansModuleMiddleware)
		} else {
			r.POST("/ingest", ingestHandler.IngestEIS, decompressMiddleware) // Default: EIS format
			r.POST("/ingest/check", ingestHandler.CheckFingerprints, decompressMiddleware)
			r.POST("/ingest/sarif", ingestHandler.IngestSARIF, decompressMiddleware)
			r.POST("/ingest/eis", ingestHandler.IngestEIS, decompressMiddleware)
			r.POST("/ingest/recon", ingestHandler.IngestReconReport, decompressMiddleware)
			r.POST("/ingest/chunk", ingestHandler.IngestChunk, decompressMiddleware)
		}

		// Command polling and status updates - requires "scans" module
		if scansModuleMiddleware != nil {
			r.GET("/commands", commandHandler.Poll, scansModuleMiddleware)
			r.POST("/commands/{id}/acknowledge", commandHandler.Acknowledge, scansModuleMiddleware)
			r.POST("/commands/{id}/start", commandHandler.Start, scansModuleMiddleware)
			r.POST("/commands/{id}/complete", commandHandler.Complete, scansModuleMiddleware)
			r.POST("/commands/{id}/fail", commandHandler.Fail, scansModuleMiddleware)
		} else {
			r.GET("/commands", commandHandler.Poll)
			r.POST("/commands/{id}/acknowledge", commandHandler.Acknowledge)
			r.POST("/commands/{id}/start", commandHandler.Start)
			r.POST("/commands/{id}/complete", commandHandler.Complete)
			r.POST("/commands/{id}/fail", commandHandler.Fail)
		}

		// Scan session management - requires "scans" module
		if scanSessionHandler != nil {
			if scansModuleMiddleware != nil {
				r.POST("/scans", scanSessionHandler.RegisterScan, scansModuleMiddleware)
				r.PATCH("/scans/{id}", scanSessionHandler.UpdateScan, scansModuleMiddleware)
				r.GET("/scans/{id}", scanSessionHandler.GetScan, scansModuleMiddleware)
			} else {
				r.POST("/scans", scanSessionHandler.RegisterScan)
				r.PATCH("/scans/{id}", scanSessionHandler.UpdateScan)
				r.GET("/scans/{id}", scanSessionHandler.GetScan)
			}
		}
	}, baseMiddleware)
}

// registerAgentManagementRoutes registers agent management endpoints.
// Agents are distributed runners, workers, collectors, sensors that execute tasks.
//
// Module check: Requires "scans" module to be enabled.
// Agents are bundled with scans module because scanning requires agents to execute.
// The number of agents is controlled by the plan's agent_limit field.
func registerAgentManagementRoutes(
	router Router,
	h *handler.AgentHandler,
	_ interface{}, // analyticsHandler removed in OSS
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
	moduleService *app.ModuleService,
) {
	// Build tenant middleware chain from JWT token
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	// Add module check middleware - agents are bundled with scans module
	if moduleService != nil {
		tenantMiddlewares = append(tenantMiddlewares, middleware.RequireModule(moduleService, module.ModuleScans))
	}

	// Agent management routes - tenant from JWT token
	router.Group("/api/v1/agents", func(r Router) {
		// Read operations
		r.GET("/", h.List, middleware.Require(permission.AgentsRead))
		r.GET("/{id}", h.Get, middleware.Require(permission.AgentsRead))

		// Available capabilities for tenant (aggregated from all accessible agents)
		r.GET("/available-capabilities", h.GetAvailableCapabilities, middleware.Require(permission.AgentsRead))

		// Write operations
		r.POST("/", h.Create, middleware.Require(permission.AgentsWrite))
		r.PUT("/{id}", h.Update, middleware.Require(permission.AgentsWrite))
		r.POST("/{id}/regenerate-key", h.RegenerateAPIKey, middleware.Require(permission.AgentsWrite))

		// Status operations (admin-controlled)
		r.POST("/{id}/activate", h.Activate, middleware.Require(permission.AgentsWrite))
		r.POST("/{id}/deactivate", h.Disable, middleware.Require(permission.AgentsWrite))
		r.POST("/{id}/revoke", h.Revoke, middleware.Require(permission.AgentsWrite))

		// Delete operations
		r.DELETE("/{id}", h.Delete, middleware.Require(permission.AgentsDelete))

	}, tenantMiddlewares...)
}

// registerPipelineRoutes registers pipeline management endpoints.
// Pipelines orchestrate multi-step scan workflows via templates, steps, and runs.
func registerPipelineRoutes(
	router Router,
	h *handler.PipelineHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
	triggerRateLimiter *middleware.TriggerRateLimiter,
) {
	// Build tenant middleware chain from JWT token
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	// Pipeline Template routes - tenant from JWT token
	router.Group("/api/v1/pipelines", func(r Router) {
		// Read operations
		r.GET("/", h.ListTemplates, middleware.Require(permission.PipelinesRead))
		r.GET("/{id}", h.GetTemplate, middleware.Require(permission.PipelinesRead))

		// Write operations
		r.POST("/", h.CreateTemplate, middleware.Require(permission.PipelinesWrite))
		r.PUT("/{id}", h.UpdateTemplate, middleware.Require(permission.PipelinesWrite))

		// Status operations
		r.POST("/{id}/activate", h.ActivateTemplate, middleware.Require(permission.PipelinesWrite))
		r.POST("/{id}/deactivate", h.DeactivateTemplate, middleware.Require(permission.PipelinesWrite))
		r.POST("/{id}/clone", h.CloneTemplate, middleware.Require(permission.PipelinesWrite))

		// Delete operations
		r.DELETE("/{id}", h.DeleteTemplate, middleware.Require(permission.PipelinesDelete))

		// Template steps management
		r.POST("/{id}/steps", h.AddStep, middleware.Require(permission.PipelinesWrite))
		r.PUT("/{id}/steps/{stepId}", h.UpdateStep, middleware.Require(permission.PipelinesWrite))
		r.DELETE("/{id}/steps/{stepId}", h.DeleteStep, middleware.Require(permission.PipelinesDelete))

		// Pipeline runs (executions)
		r.GET("/{id}/runs", h.ListRuns, middleware.Require(permission.PipelinesRead))
		// Apply rate limiting to pipeline triggers
		if triggerRateLimiter != nil {
			r.POST("/{id}/runs", h.TriggerRun, middleware.Require(permission.PipelinesWrite), triggerRateLimiter.PipelineMiddleware())
		} else {
			r.POST("/{id}/runs", h.TriggerRun, middleware.Require(permission.PipelinesWrite))
		}
	}, tenantMiddlewares...)

	// Pipeline Run routes - direct access
	router.Group("/api/v1/pipeline-runs", func(r Router) {
		// Read operations
		r.GET("/", h.ListRuns, middleware.Require(permission.PipelinesRead))
		r.GET("/{id}", h.GetRun, middleware.Require(permission.PipelinesRead))

		// Write operations
		r.POST("/{id}/cancel", h.CancelRun, middleware.Require(permission.PipelinesWrite))
	}, tenantMiddlewares...)
}

// registerScanProfileRoutes registers scan profile management endpoints.
// Scan profiles are reusable scan configurations with tool settings.
//
// Module check: Requires "scans" module to be enabled (scan profiles are part of scans).
func registerScanProfileRoutes(
	router Router,
	h *handler.ScanProfileHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
	moduleService *app.ModuleService,
) {
	// Build tenant middleware chain from JWT token
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	// Add module check middleware
	if moduleService != nil {
		tenantMiddlewares = append(tenantMiddlewares, middleware.RequireModule(moduleService, module.ModuleScans))
	}

	// Scan Profile routes - tenant from JWT token
	router.Group("/api/v1/scan-profiles", func(r Router) {
		// Default profile (must be before /{id} to avoid route conflicts)
		r.GET("/default", h.GetDefault, middleware.Require(permission.ScanProfilesRead))

		// Read operations
		r.GET("/", h.List, middleware.Require(permission.ScanProfilesRead))
		r.GET("/{id}", h.Get, middleware.Require(permission.ScanProfilesRead))

		// Write operations
		r.POST("/", h.Create, middleware.Require(permission.ScanProfilesWrite))
		r.PUT("/{id}", h.Update, middleware.Require(permission.ScanProfilesWrite))
		r.PUT("/{id}/quality-gate", h.UpdateQualityGate, middleware.Require(permission.ScanProfilesWrite))
		r.POST("/{id}/evaluate-quality-gate", h.EvaluateQualityGate, middleware.Require(permission.ScanProfilesRead))
		r.POST("/{id}/set-default", h.SetDefault, middleware.Require(permission.ScanProfilesWrite))
		r.POST("/{id}/clone", h.Clone, middleware.Require(permission.ScanProfilesWrite))

		// Delete operations
		r.DELETE("/{id}", h.Delete, middleware.Require(permission.ScanProfilesDelete))
	}, tenantMiddlewares...)
}

// registerToolRoutes registers tool registry routes.
func registerToolRoutes(
	router Router,
	h *handler.ToolHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
) {
	// Build tenant middleware chain from JWT token
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	// Platform Tools routes (system-wide tools, accessible to all tenants)
	router.Group("/api/v1/tools/platform", func(r Router) {
		// Read operations (accessible to all roles with ToolsRead)
		r.GET("/", h.ListPlatformTools, middleware.Require(permission.ToolsRead))
	}, tenantMiddlewares...)

	// Tool routes (system-wide, read accessible to all authenticated users)
	router.Group("/api/v1/tools", func(r Router) {
		// Read operations (accessible to all roles with ToolsRead)
		r.GET("/", h.List, middleware.Require(permission.ToolsRead))
		r.GET("/name/{name}", h.GetByName, middleware.Require(permission.ToolsRead))
		r.GET("/{id}", h.Get, middleware.Require(permission.ToolsRead))

		// Write operations (admin only)
		r.POST("/", h.Create, middleware.Require(permission.ToolsWrite))
		r.PUT("/{id}", h.Update, middleware.Require(permission.ToolsWrite))
		r.POST("/{id}/activate", h.Activate, middleware.Require(permission.ToolsWrite))
		r.POST("/{id}/deactivate", h.Deactivate, middleware.Require(permission.ToolsWrite))

		// Delete operations (admin only)
		r.DELETE("/{id}", h.Delete, middleware.Require(permission.ToolsDelete))
	}, tenantMiddlewares...)

	// Tenant Custom Tools routes (tenant-specific tools)
	router.Group("/api/v1/custom-tools", func(r Router) {
		// Read operations
		r.GET("/", h.ListCustomTools, middleware.Require(permission.TenantToolsRead))
		r.GET("/{id}", h.GetCustomTool, middleware.Require(permission.TenantToolsRead))

		// Write operations
		r.POST("/", h.CreateCustomTool, middleware.Require(permission.TenantToolsWrite))
		r.PUT("/{id}", h.UpdateCustomTool, middleware.Require(permission.TenantToolsWrite))
		r.POST("/{id}/activate", h.ActivateCustomTool, middleware.Require(permission.TenantToolsWrite))
		r.POST("/{id}/deactivate", h.DeactivateCustomTool, middleware.Require(permission.TenantToolsWrite))

		// Delete operations
		r.DELETE("/{id}", h.DeleteCustomTool, middleware.Require(permission.TenantToolsDelete))
	}, tenantMiddlewares...)

	// Tenant Tool Config routes (tenant-scoped)
	router.Group("/api/v1/tenant-tools", func(r Router) {
		// Bulk operations (must be before /{tool_id} to avoid route conflicts)
		r.POST("/bulk-enable", h.BulkEnable, middleware.Require(permission.TenantToolsWrite))
		r.POST("/bulk-disable", h.BulkDisable, middleware.Require(permission.TenantToolsWrite))

		// List all tools with tenant-specific enabled status (must be before /{tool_id})
		r.GET("/all-tools", h.ListAllTools, middleware.Require(permission.TenantToolsRead))

		// Read operations
		r.GET("/", h.ListTenantConfigs, middleware.Require(permission.TenantToolsRead))
		r.GET("/{tool_id}", h.GetTenantConfig, middleware.Require(permission.TenantToolsRead))
		r.GET("/{tool_id}/effective-config", h.GetEffectiveConfig, middleware.Require(permission.TenantToolsRead))
		r.GET("/{tool_id}/with-config", h.GetToolWithConfig, middleware.Require(permission.TenantToolsRead))

		// Write operations
		r.PUT("/{tool_id}", h.UpdateTenantConfig, middleware.Require(permission.TenantToolsWrite))

		// Delete operations
		r.DELETE("/{tool_id}", h.DeleteTenantConfig, middleware.Require(permission.TenantToolsDelete))
	}, tenantMiddlewares...)

	// Tool Stats routes (tenant-scoped)
	router.Group("/api/v1/tool-stats", func(r Router) {
		r.GET("/", h.GetTenantStats, middleware.Require(permission.TenantToolsRead))
		r.GET("/{tool_id}", h.GetToolStats, middleware.Require(permission.TenantToolsRead))
	}, tenantMiddlewares...)
}

// registerToolCategoryRoutes registers tool category endpoints.
func registerToolCategoryRoutes(
	router Router,
	h *handler.ToolCategoryHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
) {
	// Build tenant middleware chain from JWT token
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	// Tool Categories routes (read - list all platform + tenant custom categories)
	router.Group("/api/v1/tool-categories", func(r Router) {
		// List all categories (no pagination, for dropdowns)
		r.GET("/all", h.ListAllCategories, middleware.Require(permission.ToolsRead))
		// List categories with pagination
		r.GET("/", h.ListCategories, middleware.Require(permission.ToolsRead))
		// Get category by ID
		r.GET("/{id}", h.GetCategory, middleware.Require(permission.ToolsRead))
	}, tenantMiddlewares...)

	// Custom Tool Categories routes (tenant-specific categories)
	router.Group("/api/v1/custom-tool-categories", func(r Router) {
		// Create custom category
		r.POST("/", h.CreateCustomCategory, middleware.Require(permission.TenantToolsWrite))
		// Update custom category
		r.PUT("/{id}", h.UpdateCustomCategory, middleware.Require(permission.TenantToolsWrite))
		// Delete custom category
		r.DELETE("/{id}", h.DeleteCustomCategory, middleware.Require(permission.TenantToolsDelete))
	}, tenantMiddlewares...)
}

// registerCapabilityRoutes registers capability endpoints.
func registerCapabilityRoutes(
	router Router,
	h *handler.CapabilityHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
) {
	// Build tenant middleware chain from JWT token
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	// Capabilities routes (read - list all platform + tenant custom capabilities)
	router.Group("/api/v1/capabilities", func(r Router) {
		// Get all capability categories (must be before /{id})
		r.GET("/categories", h.GetCategories, middleware.Require(permission.ToolsRead))
		// List by category (must be before /{id})
		r.GET("/by-category/{category}", h.ListCapabilitiesByCategory, middleware.Require(permission.ToolsRead))
		// List all capabilities (no pagination, for dropdowns)
		r.GET("/all", h.ListAllCapabilities, middleware.Require(permission.ToolsRead))
		// Batch get usage stats (must be before /{id})
		r.POST("/usage-stats", h.GetCapabilitiesUsageStatsBatch, middleware.Require(permission.ToolsRead))
		// List capabilities with pagination
		r.GET("/", h.ListCapabilities, middleware.Require(permission.ToolsRead))
		// Get capability by ID
		r.GET("/{id}", h.GetCapability, middleware.Require(permission.ToolsRead))
		// Get usage stats for a capability
		r.GET("/{id}/usage-stats", h.GetCapabilityUsageStats, middleware.Require(permission.ToolsRead))
	}, tenantMiddlewares...)

	// Custom Capabilities routes (tenant-specific capabilities)
	router.Group("/api/v1/custom-capabilities", func(r Router) {
		// Create custom capability
		r.POST("/", h.CreateCustomCapability, middleware.Require(permission.TenantToolsWrite))
		// Update custom capability
		r.PUT("/{id}", h.UpdateCustomCapability, middleware.Require(permission.TenantToolsWrite))
		// Delete custom capability
		r.DELETE("/{id}", h.DeleteCustomCapability, middleware.Require(permission.TenantToolsDelete))
	}, tenantMiddlewares...)
}

// registerScanRoutes registers scan management endpoints.
// Scans bind asset groups with scanners/workflows and schedules.
//
// Module check: Requires "scans" module to be enabled.
func registerScanRoutes(
	router Router,
	h *handler.ScanHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
	moduleService *app.ModuleService,
	triggerRateLimiter *middleware.TriggerRateLimiter,
) {
	// Build tenant middleware chain from JWT token
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	// Add module check middleware
	if moduleService != nil {
		tenantMiddlewares = append(tenantMiddlewares, middleware.RequireModule(moduleService, module.ModuleScans))
	}

	// Quick scan endpoint - separate from /scans to avoid conflict
	router.Group("/api/v1/quick-scan", func(r Router) {
		// Apply rate limiting to quick scans (stricter)
		if triggerRateLimiter != nil {
			r.POST("/", h.QuickScan, middleware.Require(permission.ScansWrite), triggerRateLimiter.QuickScanMiddleware())
		} else {
			r.POST("/", h.QuickScan, middleware.Require(permission.ScansWrite))
		}
	}, tenantMiddlewares...)

	// Scan management overview stats
	router.Group("/api/v1/scan-management", func(r Router) {
		r.GET("/stats", h.GetOverviewStats, middleware.Require(permission.ScansRead))
	}, tenantMiddlewares...)

	// Scan routes - tenant from JWT token
	router.Group("/api/v1/scans", func(r Router) {
		// Stats endpoint (must be before /{id} to avoid matching)
		r.GET("/stats", h.GetStats, middleware.Require(permission.ScansRead))

		// Bulk operations (must be before /{id} to avoid matching)
		r.POST("/bulk/activate", h.BulkActivate, middleware.Require(permission.ScansWrite))
		r.POST("/bulk/pause", h.BulkPause, middleware.Require(permission.ScansWrite))
		r.POST("/bulk/disable", h.BulkDisable, middleware.Require(permission.ScansWrite))
		r.POST("/bulk/delete", h.BulkDelete, middleware.Require(permission.ScansDelete))

		// Read operations
		r.GET("/", h.ListScans, middleware.Require(permission.ScansRead))
		r.GET("/{id}", h.GetScan, middleware.Require(permission.ScansRead))

		// Write operations
		r.POST("/", h.CreateScan, middleware.Require(permission.ScansWrite))
		r.PUT("/{id}", h.UpdateScan, middleware.Require(permission.ScansWrite))

		// Status operations
		r.POST("/{id}/activate", h.ActivateScan, middleware.Require(permission.ScansWrite))
		r.POST("/{id}/pause", h.PauseScan, middleware.Require(permission.ScansWrite))
		r.POST("/{id}/disable", h.DisableScan, middleware.Require(permission.ScansWrite))

		// Trigger scan execution - apply rate limiting
		if triggerRateLimiter != nil {
			r.POST("/{id}/trigger", h.TriggerScan, middleware.Require(permission.ScansWrite), triggerRateLimiter.ScanMiddleware())
		} else {
			r.POST("/{id}/trigger", h.TriggerScan, middleware.Require(permission.ScansWrite))
		}

		// Clone scan
		r.POST("/{id}/clone", h.CloneScan, middleware.Require(permission.ScansWrite))

		// Scan runs sub-resource
		r.GET("/{id}/runs", h.ListScanRuns, middleware.Require(permission.ScansRead))
		r.GET("/{id}/runs/latest", h.GetLatestScanRun, middleware.Require(permission.ScansRead))
		r.GET("/{id}/runs/{runId}", h.GetScanRun, middleware.Require(permission.ScansRead))

		// Delete operations
		r.DELETE("/{id}", h.DeleteScan, middleware.Require(permission.ScansDelete))
	}, tenantMiddlewares...)
}

// registerScanSessionRoutes registers scan session endpoints.
// Scan sessions track individual scan executions from agents.
// Two sets of routes:
// 1. Agent routes (API key auth): /api/v1/agent/scans - register, update, get scans
// 2. Admin routes (JWT auth): /api/v1/scan-sessions - list, view, manage sessions
func registerScanSessionRoutes(
	router Router,
	h *handler.ScanSessionHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
) {
	// Build tenant middleware chain from JWT token for admin routes
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	// Admin routes - tenant from JWT token
	router.Group("/api/v1/scan-sessions", func(r Router) {
		// Stats endpoint (must be before /{id} to avoid matching)
		r.GET("/stats", h.GetStats, middleware.Require(permission.ScansRead))

		// Read operations
		r.GET("/", h.List, middleware.Require(permission.ScansRead))
		r.GET("/{id}", h.Get, middleware.Require(permission.ScansRead))

		// Delete operations
		r.DELETE("/{id}", h.Delete, middleware.Require(permission.ScansDelete))
	}, tenantMiddlewares...)
}

// registerScannerTemplateRoutes registers scanner template management endpoints.
// Scanner templates are custom templates for security tools (Nuclei, Semgrep, Gitleaks).
//
// Module check: Requires "scans" module to be enabled (templates are part of scans).
func registerScannerTemplateRoutes(
	router Router,
	h *handler.ScannerTemplateHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
	moduleService *app.ModuleService,
) {
	// Build tenant middleware chain from JWT token
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	// Add module check middleware
	if moduleService != nil {
		tenantMiddlewares = append(tenantMiddlewares, middleware.RequireModule(moduleService, module.ModuleScans))
	}

	// Scanner Template routes - tenant from JWT token
	router.Group("/api/v1/scanner-templates", func(r Router) {
		// Static endpoints (must be before /{id} to avoid route conflicts)
		r.POST("/validate", h.Validate, middleware.Require(permission.ScannerTemplatesRead))
		r.GET("/usage", h.GetUsage, middleware.Require(permission.ScannerTemplatesRead))

		// Read operations
		r.GET("/", h.List, middleware.Require(permission.ScannerTemplatesRead))
		r.GET("/{id}", h.Get, middleware.Require(permission.ScannerTemplatesRead))
		r.GET("/{id}/download", h.Download, middleware.Require(permission.ScannerTemplatesRead))

		// Write operations
		r.POST("/", h.Create, middleware.Require(permission.ScannerTemplatesWrite))
		r.PUT("/{id}", h.Update, middleware.Require(permission.ScannerTemplatesWrite))
		r.POST("/{id}/deprecate", h.Deprecate, middleware.Require(permission.ScannerTemplatesWrite))

		// Delete operations
		r.DELETE("/{id}", h.Delete, middleware.Require(permission.ScannerTemplatesDelete))
	}, tenantMiddlewares...)
}

// registerTemplateSourceRoutes registers template source management endpoints.
// Template sources are external sources (Git, S3, HTTP) for scanner templates.
//
// Module check: Requires "scans" module to be enabled (template sources are part of scans).
func registerTemplateSourceRoutes(
	router Router,
	h *handler.TemplateSourceHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
	moduleService *app.ModuleService,
) {
	// Build tenant middleware chain from JWT token
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	// Add module check middleware
	if moduleService != nil {
		tenantMiddlewares = append(tenantMiddlewares, middleware.RequireModule(moduleService, module.ModuleScans))
	}

	// Template Source routes - tenant from JWT token
	router.Group("/api/v1/template-sources", func(r Router) {
		// Read operations
		r.GET("/", h.List, middleware.Require(permission.TemplateSourcesRead))
		r.GET("/{id}", h.Get, middleware.Require(permission.TemplateSourcesRead))

		// Write operations
		r.POST("/", h.Create, middleware.Require(permission.TemplateSourcesWrite))
		r.PUT("/{id}", h.Update, middleware.Require(permission.TemplateSourcesWrite))
		r.POST("/{id}/enable", h.Enable, middleware.Require(permission.TemplateSourcesWrite))
		r.POST("/{id}/disable", h.Disable, middleware.Require(permission.TemplateSourcesWrite))
		r.POST("/{id}/sync", h.Sync, middleware.Require(permission.TemplateSourcesWrite))

		// Delete operations
		r.DELETE("/{id}", h.Delete, middleware.Require(permission.TemplateSourcesDelete))
	}, tenantMiddlewares...)
}

// registerSecretStoreRoutes registers secret store endpoints for template source authentication.
// These secrets are used for authenticating to external template sources (Git, S3, HTTP).
//
// IMPORTANT: This is different from /api/v1/credentials which handles credential LEAKS (exposed passwords).
// - /api/v1/secret-store: Authentication secrets for template sources (Git tokens, AWS keys, etc.)
// - /api/v1/credentials: Leaked credentials found during scans (credential exposure management)
//
// Module check: Requires "scans" module to be enabled (secrets are part of template scanning).
func registerSecretStoreRoutes(
	router Router,
	h *handler.SecretStoreHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
	moduleService *app.ModuleService,
) {
	// Build tenant middleware chain from JWT token
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	// Add module check middleware
	if moduleService != nil {
		tenantMiddlewares = append(tenantMiddlewares, middleware.RequireModule(moduleService, module.ModuleScans))
	}

	// Secret store routes - tenant from JWT token
	// Path: /api/v1/secret-store (NOT /api/v1/credentials which is for credential leaks)
	router.Group("/api/v1/secret-store", func(r Router) {
		// Read operations
		r.GET("/", h.List, middleware.Require(permission.SecretStoreRead))
		r.GET("/{id}", h.Get, middleware.Require(permission.SecretStoreRead))

		// Write operations
		r.POST("/", h.Create, middleware.Require(permission.SecretStoreWrite))
		r.PUT("/{id}", h.Update, middleware.Require(permission.SecretStoreWrite))

		// Delete operations
		r.DELETE("/{id}", h.Delete, middleware.Require(permission.SecretStoreDelete))
	}, tenantMiddlewares...)
}

// registerSuppressionRoutes registers suppression rule management endpoints.
// Suppression rules are platform-controlled rules to suppress false positives.
// Unlike in-code ignore files (.semgrepignore, .gitleaksignore), these rules:
// - Are managed centrally from the platform
// - Require approval workflow (pending -> approved/rejected)
// - Have audit trail for compliance
// - Can be time-limited with expiration
func registerSuppressionRoutes(
	router Router,
	h *handler.SuppressionHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
) {
	// Build tenant middleware chain from JWT token
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	// Suppression rules routes - tenant from JWT token
	router.Group("/api/v1/suppressions", func(r Router) {
		// Active rules for agents (must be before /{id} to avoid route conflicts)
		r.GET("/active", h.ListActiveRules, middleware.Require(permission.SuppressionsRead))

		// Read operations
		r.GET("/", h.ListRules, middleware.Require(permission.SuppressionsRead))
		r.GET("/{id}", h.GetRule, middleware.Require(permission.SuppressionsRead))

		// Write operations
		r.POST("/", h.CreateRule, middleware.Require(permission.SuppressionsWrite))
		r.PUT("/{id}", h.UpdateRule, middleware.Require(permission.SuppressionsWrite))

		// Approval workflow (requires separate approve permission)
		r.POST("/{id}/approve", h.ApproveRule, middleware.Require(permission.SuppressionsApprove))
		r.POST("/{id}/reject", h.RejectRule, middleware.Require(permission.SuppressionsApprove))

		// Delete operations
		r.DELETE("/{id}", h.DeleteRule, middleware.Require(permission.SuppressionsDelete))
	}, tenantMiddlewares...)
}

// registerWorkflowRoutes registers workflow automation endpoints.
// Workflows orchestrate security automation actions like notifications, ticket creation, and assignments.
func registerWorkflowRoutes(
	router Router,
	h *handler.WorkflowHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
) {
	// Build tenant middleware chain from JWT token
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	// Workflow routes - tenant from JWT token
	router.Group("/api/v1/workflows", func(r Router) {
		// Read operations
		r.GET("/", h.ListWorkflows, middleware.Require(permission.WorkflowsRead))
		r.GET("/{id}", h.GetWorkflow, middleware.Require(permission.WorkflowsRead))

		// Write operations
		r.POST("/", h.CreateWorkflow, middleware.Require(permission.WorkflowsWrite))
		r.PUT("/{id}", h.UpdateWorkflow, middleware.Require(permission.WorkflowsWrite))

		// Delete operations
		r.DELETE("/{id}", h.DeleteWorkflow, middleware.Require(permission.WorkflowsWrite))

		// Graph update (atomic replacement of all nodes and edges)
		r.PUT("/{id}/graph", h.UpdateWorkflowGraph, middleware.Require(permission.WorkflowsWrite))

		// Workflow nodes management
		r.POST("/{id}/nodes", h.AddNode, middleware.Require(permission.WorkflowsWrite))
		r.PUT("/{id}/nodes/{nodeId}", h.UpdateNode, middleware.Require(permission.WorkflowsWrite))
		r.DELETE("/{id}/nodes/{nodeId}", h.DeleteNode, middleware.Require(permission.WorkflowsWrite))

		// Workflow edges management
		r.POST("/{id}/edges", h.AddEdge, middleware.Require(permission.WorkflowsWrite))
		r.DELETE("/{id}/edges/{edgeId}", h.DeleteEdge, middleware.Require(permission.WorkflowsWrite))

		// Workflow runs (executions)
		r.POST("/{id}/runs", h.TriggerWorkflow, middleware.Require(permission.WorkflowsWrite))
	}, tenantMiddlewares...)

	// Workflow Run routes - direct access
	router.Group("/api/v1/workflow-runs", func(r Router) {
		// Read operations
		r.GET("/", h.ListRuns, middleware.Require(permission.WorkflowsRead))
		r.GET("/{id}", h.GetRun, middleware.Require(permission.WorkflowsRead))

		// Write operations
		r.POST("/{id}/cancel", h.CancelRun, middleware.Require(permission.WorkflowsWrite))
	}, tenantMiddlewares...)
}
