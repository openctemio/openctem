package routes

import (
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
)

// IngestMaxConcurrentPerTenant caps in-flight report-ingest requests per
// tenant (see middleware.TenantConcurrencyLimiter).
const IngestMaxConcurrentPerTenant = 8

// ingestMiddlewareChain orders the ingest middlewares so the cheap rejections
// (per-tenant rate limit, per-tenant concurrency cap) run BEFORE the body is
// decompressed. Decompression buffers up to 100MB per request; when the limiter
// ran after it, a throttled tenant still made the server inflate every rejected
// body. nil limiters are skipped. Used by the CI run upload (routes/ci.go).
func ingestMiddlewareChain(
	rateLimiter *middleware.TelemetryRateLimiter,
	concurrency *middleware.TenantConcurrencyLimiter,
	bodyLimit, decompress Middleware,
) []Middleware {
	chain := make([]Middleware, 0, 4)
	if rateLimiter != nil {
		chain = append(chain, rateLimiter.Middleware())
	}
	if concurrency != nil {
		chain = append(chain, concurrency.Middleware())
	}
	return append(chain, bodyLimit, decompress)
}

// registerCommandRoutes registers command management endpoints.
// Commands are server-side instructions sent to sensors.
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

// registerSensorManagementRoutes registers sensor management endpoints.
// Sensors are the scanners, agents and collectors that run on the customer
// side and authenticate to the platform with their own key (RFC-023 D18).
//
//sensorrename:keep ("agents" here is the endpoint role)
func registerSensorManagementRoutes(
	router Router,
	h *handler.SensorHandler,
	content *handler.SensorContentHandler,
	results *handler.SensorResultHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
) {
	// Build tenant middleware chain from JWT token
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	// Sensor management routes - tenant from JWT token
	router.Group("/api/v1/sensors", func(r Router) {
		// Read operations
		r.GET("/", h.List, middleware.Require(permission.SensorsRead))
		// Tenant-wide aggregated stats — must be registered BEFORE /{id} so
		// chi doesn't treat "stats" as a path param.
		r.GET("/stats", h.GetStats, middleware.Require(permission.SensorsRead))
		// Scanner content (RFC-031): the tenant policy and refresh requests.
		// Before /{id} for the same reason. Writes queue commands for the
		// fleet, so they need sensors:write (owners and administrators).
		if content != nil {
			r.GET("/content-policy", content.GetPolicy, middleware.Require(permission.SensorsRead))
			r.PUT("/content-policy", content.UpdatePolicy, middleware.Require(permission.SensorsWrite))
			r.POST("/content/refresh", content.RefreshFleet, middleware.Require(permission.SensorsWrite))
			r.POST("/{id}/content/refresh", content.RefreshSensor, middleware.Require(permission.SensorsWrite))
		}
		// Results without a command (RFC-040 §5.3): the tenant policy and
		// the quarantine review. Accepting applies sensor data to the
		// inventory and discarding drops it, so both, like the policy, need
		// sensors:write (owners and administrators). Before /{id}.
		if results != nil {
			r.GET("/result-policy", results.GetPolicy, middleware.Require(permission.SensorsRead))
			r.PUT("/result-policy", results.UpdatePolicy, middleware.Require(permission.SensorsWrite))
			r.GET("/quarantined-results", results.List, middleware.Require(permission.SensorsRead))
			r.GET("/quarantined-results/{qid}", results.Get, middleware.Require(permission.SensorsRead))
			r.POST("/quarantined-results/{qid}/approve", results.Accept, middleware.Require(permission.SensorsWrite))
			r.POST("/quarantined-results/{qid}/reject", results.Discard, middleware.Require(permission.SensorsWrite))
		}
		// Identity policy (RFC-052 D-4): bearer keys allowed or pairing
		// only. Requiring key-bound identity narrows, allowing bearer keys
		// widens (the handler checks which). Before /{id}.
		r.GET("/identity-policy", h.GetIdentityPolicy, middleware.Require(permission.SensorsRead))
		r.PUT("/identity-policy", h.SetIdentityPolicy, middleware.RequireAny(permission.SensorsGrantNarrow, permission.SensorsGrantWiden))
		// Per-sensor grants (RFC-052 §5). A change that widens needs
		// sensors:grant:widen (the service decides). Before /{id}.
		r.GET("/grant-profiles", h.ListGrantProfiles, middleware.Require(permission.SensorsRead))
		r.GET("/grant-summaries", h.ListGrantSummaries, middleware.Require(permission.SensorsRead))
		r.GET("/{id}", h.Get, middleware.Require(permission.SensorsRead))
		// Signing keys of key-bound sensors (RFC-052).
		r.GET("/{id}/keys", h.ListSigningKeys, middleware.Require(permission.SensorsRead))
		r.POST("/{id}/keys/{key_id}/revoke", h.RevokeSigningKey, middleware.RequireAny(permission.SensorsWrite, permission.SensorsRevoke))
		r.GET("/{id}/grant", h.GetGrant, middleware.Require(permission.SensorsRead))
		r.PUT("/{id}/grant", h.UpdateGrant, middleware.RequireAny(permission.SensorsGrantNarrow, permission.SensorsGrantWiden))
		r.GET("/{id}/config-templates", h.GetConfigTemplates, middleware.Require(permission.SensorsRead))
		// Activity timeline. Audit-log items are added only for callers that
		// also hold audit:read (the handler checks it).
		r.GET("/{id}/activity", h.Activity, middleware.Require(permission.SensorsRead))
		// Heartbeat history (RFC-035): the Control channel sparkline.
		r.GET("/{id}/heartbeat-history", h.HeartbeatHistory, middleware.Require(permission.SensorsRead))
		// Manifest (RFC-033): the current one and its history.
		r.GET("/{id}/manifest", h.Manifest, middleware.Require(permission.SensorsRead))
		r.GET("/{id}/manifests", h.Manifests, middleware.Require(permission.SensorsRead))
		// Setup checklist (research/26): the sensor's config report, explained
		// from the platform catalog.
		r.GET("/{id}/config-report", h.ConfigReport, middleware.Require(permission.SensorsRead))

		// Available capabilities for tenant (aggregated from all accessible sensors)
		r.GET("/available-capabilities", h.GetAvailableCapabilities, middleware.Require(permission.SensorsRead))

		// Write operations. Every one of these creates, rotates or invalidates
		// a sensor key (or the sensor that owns it), so sensors:write and
		// sensors:delete are held by owners and administrators only — the
		// member and viewer seeds do not grant them (owner decision 2026-10-02).
		// Members and viewers keep the reads above.
		// Creating a sensor and regenerating its key mint a persistent
		// credential, so they need a recent sign-in (step-up), as an API key
		// does. Revoking and deleting stay one click.
		r.POST("/", h.Create, middleware.Require(permission.SensorsWrite), requireStepUp())
		r.PUT("/{id}", h.Update, middleware.Require(permission.SensorsWrite))
		r.POST("/{id}/regenerate-key", h.RegenerateAPIKey, middleware.Require(permission.SensorsWrite), requireStepUp())

		// Status operations (admin-controlled)
		r.POST("/{id}/activate", h.Activate, middleware.Require(permission.SensorsWrite))
		r.POST("/{id}/deactivate", h.Disable, middleware.Require(permission.SensorsWrite))
		// Revoking only narrows: sensors:revoke suffices (RFC-052).
		r.POST("/{id}/revoke", h.Revoke, middleware.RequireAny(permission.SensorsWrite, permission.SensorsRevoke))

		// Delete operations
		r.DELETE("/{id}", h.Delete, middleware.Require(permission.SensorsDelete))
	}, tenantMiddlewares...)

}

// registerScanZoneRoutes registers the scan zone management API (RFC-023
// Phase 1). Reads need sensors:zones:read; creating, editing and sensor
// assignment need sensors:zones:write; deleting needs sensors:zones:delete.
func registerScanZoneRoutes(
	router Router,
	h *handler.ScanZoneHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
) {
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	router.Group("/api/v1/scan-zones", func(r Router) {
		r.GET("/", h.List, middleware.Require(permission.ScanZonesRead))
		// Before /{id} so chi does not read "coverage" as an id.
		r.GET("/coverage", h.Coverage, middleware.Require(permission.ScanZonesRead))
		// Read-only: computes routing for a scan about to be created.
		r.POST("/preview", h.Preview, middleware.Require(permission.ScanZonesRead))
		r.GET("/{id}", h.Get, middleware.Require(permission.ScanZonesRead))

		r.POST("/", h.Create, middleware.Require(permission.ScanZonesWrite))
		r.PATCH("/{id}", h.Update, middleware.Require(permission.ScanZonesWrite))
		r.PUT("/{id}/sensors/{sensorId}", h.AssignSensor, middleware.Require(permission.ScanZonesWrite))
		r.DELETE("/{id}/sensors/{sensorId}", h.UnassignSensor, middleware.Require(permission.ScanZonesWrite))

		r.DELETE("/{id}", h.Delete, middleware.Require(permission.ScanZonesDelete))
	}, tenantMiddlewares...)
}

// registerScanFreezeWindowRoutes registers the scan freeze window API.
// Everyone who reads scans reads the windows (the console shows a banner
// while one is active); creating and changing them needs
// sensors:zones:write and deleting sensors:zones:delete, the scan zone
// administration permissions (owner and admin).
func registerScanFreezeWindowRoutes(
	router Router,
	h *handler.ScanFreezeWindowHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
) {
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	router.Group("/api/v1/scan-freeze-windows", func(r Router) {
		r.GET("/", h.List, middleware.Require(permission.ScansRead))
		r.GET("/{id}", h.Get, middleware.Require(permission.ScansRead))
		r.POST("/", h.Create, middleware.Require(permission.ScanZonesWrite))
		r.PATCH("/{id}", h.Update, middleware.Require(permission.ScanZonesWrite))
		r.DELETE("/{id}", h.Delete, middleware.Require(permission.ScanZonesDelete))
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
	moduleGate Middleware,
) {
	// Build tenant middleware chain from JWT token; gate after tenant extraction.
	tenantMiddlewares := append(buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware), moduleGate)

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
			r.POST("/{id}/runs", h.TriggerRun, middleware.RequireAll(permission.PipelinesWrite, permission.PipelinesExecute), triggerRateLimiter.PipelineMiddleware())
		} else {
			r.POST("/{id}/runs", h.TriggerRun, middleware.RequireAll(permission.PipelinesWrite, permission.PipelinesExecute))
		}
	}, tenantMiddlewares...)

	// Pipeline Run routes - direct access
	router.Group("/api/v1/pipeline-runs", func(r Router) {
		// Read operations
		r.GET("/", h.ListRuns, middleware.Require(permission.PipelinesRead))
		r.GET("/{id}", h.GetRun, middleware.Require(permission.PipelinesRead))
		// A run's tasks, paged by cursor (the run read embeds the first page).
		r.GET("/{id}/tasks", h.ListRunTasks, middleware.Require(permission.PipelinesRead))
		// One task's log lines, as its sensor sent them (RFC-029 §4.4.1).
		r.GET("/{id}/tasks/{task_id}/logs", h.GetRunTaskLogs, middleware.Require(permission.PipelinesRead))
		// How each stage of the run was planned (counts by reason).
		r.GET("/{id}/stages", h.ListRunStages, middleware.Require(permission.PipelinesRead))

		// Write operations. Scan runs are pipeline runs, and this is how a
		// scan run is stopped, so it also needs scans:write (owner decision
		// D12, scans redesign 2026-10).
		r.POST("/{id}/cancel", h.CancelRun, middleware.RequireAll(permission.PipelinesWrite, permission.ScansWrite))
	}, tenantMiddlewares...)
}

// registerScanProfileRoutes registers scan profile management endpoints.
// Scan profiles are reusable scan configurations with tool settings.
func registerScanProfileRoutes(
	router Router,
	h *handler.ScanProfileHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
) {
	// Build tenant middleware chain from JWT token
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

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
		// Bulk operations (must be before /{toolId} to avoid route conflicts)
		r.POST("/bulk/enable", h.BulkEnable, middleware.Require(permission.TenantToolsWrite))
		r.POST("/bulk/disable", h.BulkDisable, middleware.Require(permission.TenantToolsWrite))

		// List all tools with tenant-specific enabled status (must be before /{toolId})
		r.GET("/all-tools", h.ListAllTools, middleware.Require(permission.TenantToolsRead))
		// Tool availability from the sensors' manifests (must be before /{toolId}).
		r.GET("/availability", h.ToolAvailability, middleware.Require(permission.TenantToolsRead))

		// Read operations
		r.GET("/", h.ListTenantConfigs, middleware.Require(permission.TenantToolsRead))
		r.GET("/{toolId}", h.GetTenantConfig, middleware.Require(permission.TenantToolsRead))
		r.GET("/{toolId}/effective-config", h.GetEffectiveConfig, middleware.Require(permission.TenantToolsRead))
		r.GET("/{toolId}/with-config", h.GetToolWithConfig, middleware.Require(permission.TenantToolsRead))

		// Write operations
		r.PUT("/{toolId}", h.UpdateTenantConfig, middleware.Require(permission.TenantToolsWrite))

		// Delete operations
		r.DELETE("/{toolId}", h.DeleteTenantConfig, middleware.Require(permission.TenantToolsDelete))

		// Stats (consolidated from /tool-stats)
		r.GET("/stats", h.GetTenantStats, middleware.Require(permission.TenantToolsRead))
		r.GET("/stats/{toolId}", h.GetToolStats, middleware.Require(permission.TenantToolsRead))
	}, tenantMiddlewares...)

	// /tool-stats removed — use /tenant-tools/stats
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
func registerScanRoutes(
	router Router,
	h *handler.ScanHandler,
	ciHandler *handler.CIHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
	triggerRateLimiter *middleware.TriggerRateLimiter,
) {
	// Build tenant middleware chain from JWT token
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	// /quick-scan and /scan-management removed — use /scans/quick and /scans/overview-stats

	// Scan routes - tenant from JWT token
	router.Group("/api/v1/scans", func(r Router) {
		// Stats endpoint (must be before /{id} to avoid matching)
		r.GET("/stats", h.GetStats, middleware.Require(permission.ScansRead))
		// Overview stats (consolidated from /scan-management/stats)
		r.GET("/overview-stats", h.GetOverviewStats, middleware.Require(permission.ScansRead))
		// License-aware rolling coverage status (RFC-007 Phase 4 observability)
		r.GET("/coverage", h.CoverageStatus, middleware.Require(permission.ScansRead))
		// Scans affected by the sensor opt-ins (research/25 D3 banner).
		r.GET("/sensor-opt-in-impact", h.SensorOptInImpact, middleware.Require(permission.ScansRead))
		// Next occurrences of a schedule (stateless; the wizard and the scan page)
		r.POST("/schedule-preview", h.PreviewSchedule, middleware.Require(permission.ScansRead))
		// Quick scan (consolidated from /quick-scan)
		if triggerRateLimiter != nil {
			r.POST("/quick", h.QuickScan, middleware.RequireAll(permission.ScansWrite, permission.ScansExecute), triggerRateLimiter.QuickScanMiddleware())
		} else {
			r.POST("/quick", h.QuickScan, middleware.RequireAll(permission.ScansWrite, permission.ScansExecute))
		}

		// Bulk operations (must be before /{id} to avoid matching)
		r.POST("/bulk/activate", h.BulkActivate, middleware.Require(permission.ScansWrite))
		r.POST("/bulk/pause", h.BulkPause, middleware.Require(permission.ScansWrite))
		r.POST("/bulk/disable", h.BulkDisable, middleware.Require(permission.ScansWrite))
		r.POST("/bulk/delete", h.BulkDelete, middleware.Require(permission.ScansDelete))

		// Import scan config (must be before /{id} to avoid matching)
		r.POST("/import", h.ImportConfig, middleware.Require(permission.ScansWrite))

		// Scan stage catalog: static platform data (must be before /{id})
		r.GET("/stages", h.ListStages, middleware.Require(permission.ScansRead))

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
			r.POST("/{id}/trigger", h.TriggerScan, middleware.RequireAll(permission.ScansWrite, permission.ScansExecute), triggerRateLimiter.ScanMiddleware())
		} else {
			r.POST("/{id}/trigger", h.TriggerScan, middleware.RequireAll(permission.ScansWrite, permission.ScansExecute))
		}

		// Clone scan
		r.POST("/{id}/clone", h.CloneScan, middleware.Require(permission.ScansWrite))
		// Save an unsaved quick scan as a configuration ("Save as scan", D10)
		r.POST("/{id}/save", h.SaveScan, middleware.Require(permission.ScansWrite))

		// Export scan config
		r.GET("/{id}/export", h.ExportConfig, middleware.Require(permission.ScansRead))

		// CI/CD snippet generation
		if ciHandler != nil {
			r.GET("/{id}/ci-snippet", ciHandler.GenerateSnippet, middleware.Require(permission.ScansRead))
		}

		// Scan runs sub-resource
		r.GET("/{id}/runs", h.ListScanRuns, middleware.Require(permission.ScansRead))
		r.GET("/{id}/runs/latest", h.GetLatestScanRun, middleware.Require(permission.ScansRead))
		r.GET("/{id}/runs/{runId}", h.GetScanRun, middleware.Require(permission.ScansRead))

		// Delete operations
		r.DELETE("/{id}", h.DeleteScan, middleware.Require(permission.ScansDelete))
	}, tenantMiddlewares...)
}

// registerScannerTemplateRoutes registers scanner template management endpoints.
// Scanner templates are custom templates for security tools (Nuclei, Semgrep, Betterleaks).
func registerScannerTemplateRoutes(
	router Router,
	h *handler.ScannerTemplateHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
	moduleGate Middleware,
) {
	// Build tenant middleware chain from JWT token, gated by the scanner_templates module.
	tenantMiddlewares := append(buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware), moduleGate)

	// Scanner Template routes - tenant from JWT token
	router.Group("/api/v1/scanner-templates", func(r Router) {
		// Static endpoints (must be before /{id} to avoid route conflicts)
		r.POST("/validate", h.Validate, middleware.Require(permission.ScannerTemplatesRead))
		r.GET("/usage", h.GetUsage, middleware.Require(permission.ScannerTemplatesRead))
		// The tenant's public key for its sensors (public, not a secret).
		r.GET("/signing-key", h.GetSigningKey, middleware.Require(permission.ScannerTemplatesRead))

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
func registerTemplateSourceRoutes(
	router Router,
	h *handler.TemplateSourceHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
	moduleGate Middleware,
) {
	// Build tenant middleware chain from JWT token, gated by the template_sources module.
	tenantMiddlewares := append(buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware), moduleGate)

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
func registerSecretStoreRoutes(
	router Router,
	h *handler.SecretStoreHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
) {
	// Build tenant middleware chain from JWT token
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	// Secret store routes - tenant from JWT token
	// Path: /api/v1/secret-store (NOT /api/v1/credentials which is for credential leaks)
	router.Group("/api/v1/secret-store", func(r Router) {
		// Read operations
		r.GET("/", h.List, middleware.Require(permission.SecretStoreRead))
		r.GET("/{id}", h.Get, middleware.Require(permission.SecretStoreRead))

		// Write operations
		r.POST("/", h.Create, middleware.Require(permission.SecretStoreWrite))
		r.PUT("/{id}", h.Update, middleware.Require(permission.SecretStoreWrite))
		r.POST("/{id}/rotate", h.Rotate, middleware.Require(permission.SecretStoreWrite))

		// Delete operations
		r.DELETE("/{id}", h.Delete, middleware.Require(permission.SecretStoreDelete))
	}, tenantMiddlewares...)
}

// registerSuppressionRoutes registers suppression rule management endpoints.
// Suppression rules are platform-controlled rules to suppress false positives.
// Unlike in-code ignore files (.semgrepignore, .betterleaksignore), these rules:
// - Are managed centrally from the platform
// - Require approval workflow (pending -> approved/rejected)
// - Have audit trail for compliance
// - Can be time-limited with expiration
func registerSuppressionRoutes(
	router Router,
	h *handler.SuppressionHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
	moduleGate Middleware,
) {
	// Build tenant middleware chain from JWT token.
	// Append the module gate after tenant extraction so it can read the tenant.
	tenantMiddlewares := append(buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware), moduleGate)

	// Suppression rules routes - tenant from JWT token
	router.Group("/api/v1/suppressions", func(r Router) {
		// Active rules for sensors (must be before /{id} to avoid route conflicts)
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
	moduleGate Middleware,
) {
	// Build tenant middleware chain from JWT token; gate after tenant extraction.
	tenantMiddlewares := append(buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware), moduleGate)

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
