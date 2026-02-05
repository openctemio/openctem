package routes

import (
	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/infra/http/handler"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/domain/module"
	"github.com/openctemio/api/pkg/domain/permission"
)

// registerAssetRoutes registers asset management endpoints.
// Assets are tenant-scoped resources (tenant from JWT token).
// Permission model:
// - Read (GET): assets:read permission
// - Write (POST, PUT): assets:write permission
// - Delete (DELETE): assets:delete permission
//
// Module check: Requires "assets" module to be enabled in tenant's subscription plan.
//
//nolint:dupl // Route registration functions naturally have similar structure
func registerAssetRoutes(
	router Router,
	h *handler.AssetHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
	moduleService *app.ModuleService,
) {
	// Build middleware chain with tenant validation from JWT
	middlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	// Add module check middleware if licensing service is available
	// This ensures tenant has "assets" module enabled in their subscription plan
	if moduleService != nil {
		middlewares = append(middlewares, middleware.RequireModule(moduleService, module.ModuleAssets))
	}

	// Asset routes - tenant from JWT token
	router.Group("/api/v1/assets", func(r Router) {
		// Stats endpoint (must be before /{id} to avoid matching)
		r.GET("/stats", h.GetStats, middleware.Require(permission.AssetsRead))

		// Bulk operations (must be before /{id} patterns to avoid route conflicts)
		r.POST("/bulk-sync", h.BulkSync, middleware.Require(permission.AssetsWrite))
		r.POST("/bulk/status", h.BulkUpdateStatus, middleware.Require(permission.AssetsWrite))

		// Read operations
		r.GET("/", h.List, middleware.Require(permission.AssetsRead))
		r.GET("/{id}", h.Get, middleware.Require(permission.AssetsRead))
		r.GET("/{id}/full", h.GetWithRepository, middleware.Require(permission.AssetsRead))
		r.GET("/{id}/repository", h.GetRepository, middleware.Require(permission.AssetsRead))

		// Write operations
		r.POST("/", h.Create, middleware.Require(permission.AssetsWrite))
		r.POST("/repository", h.CreateRepository, middleware.Require(permission.AssetsWrite))
		r.PUT("/{id}", h.Update, middleware.Require(permission.AssetsWrite))
		r.PUT("/{id}/repository", h.UpdateRepository, middleware.Require(permission.AssetsWrite))

		// Status operations
		r.POST("/{id}/activate", h.Activate, middleware.Require(permission.AssetsWrite))
		r.POST("/{id}/deactivate", h.Deactivate, middleware.Require(permission.AssetsWrite))
		r.POST("/{id}/archive", h.Archive, middleware.Require(permission.AssetsWrite))

		// Sync and scan operations (repository assets)
		r.POST("/{id}/sync", h.Sync, middleware.Require(permission.AssetsWrite))
		r.POST("/{id}/scan", h.TriggerScan, middleware.Require(permission.AssetsWrite))

		// Delete operations
		r.DELETE("/{id}", h.Delete, middleware.Require(permission.AssetsDelete))
	}, middlewares...)
}

// registerComponentRoutes registers component management endpoints.
// Components are tenant-scoped dependencies/packages (tenant from JWT token).
//
// Module check: Requires "assets" module to be enabled (components are sub-module of assets).
func registerComponentRoutes(
	router Router,
	h *handler.ComponentHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
	moduleService *app.ModuleService,
) {
	// Build middleware chain with tenant validation from JWT
	middlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	// Add module check middleware - components require assets module
	if moduleService != nil {
		middlewares = append(middlewares, middleware.RequireModule(moduleService, module.ModuleAssets))
	}

	// Component routes - tenant from JWT token
	router.Group("/api/v1/components", func(r Router) {
		// Stats endpoints (must be before /{id} to avoid matching)
		r.GET("/stats", h.GetStats, middleware.Require(permission.ComponentsRead))
		r.GET("/ecosystems", h.GetEcosystemStats, middleware.Require(permission.ComponentsRead))
		r.GET("/vulnerable", h.GetVulnerableComponents, middleware.Require(permission.ComponentsRead))
		r.GET("/licenses", h.GetLicenseStats, middleware.Require(permission.ComponentsRead))

		// Read operations
		r.GET("/", h.List, middleware.Require(permission.ComponentsRead))
		r.GET("/{id}", h.Get, middleware.Require(permission.ComponentsRead))

		// Write operations
		r.POST("/", h.Create, middleware.Require(permission.ComponentsWrite))
		r.PUT("/{id}", h.Update, middleware.Require(permission.ComponentsWrite))

		// Delete operations
		r.DELETE("/{id}", h.Delete, middleware.Require(permission.ComponentsDelete))
	}, middlewares...)

	// Asset-scoped component routes
	router.Group("/api/v1/assets/{id}/components", func(r Router) {
		r.GET("/", h.ListByAsset, middleware.Require(permission.ComponentsRead))
	}, middlewares...)
}

// registerAssetGroupRoutes registers asset group management endpoints.
// Asset groups are tenant-scoped (tenant from JWT token).
//
// Module check: Requires "assets" module to be enabled (asset-groups are part of assets).
func registerAssetGroupRoutes(
	router Router,
	h *handler.AssetGroupHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
	moduleService *app.ModuleService,
) {
	// Build tenant middleware chain from JWT token
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	// Add module check middleware - asset groups require assets module
	if moduleService != nil {
		tenantMiddlewares = append(tenantMiddlewares, middleware.RequireModule(moduleService, module.ModuleAssets))
	}

	// Asset Group routes - tenant from JWT token
	router.Group("/api/v1/asset-groups", func(r Router) {
		// Stats endpoint (must be before /{id} to avoid matching)
		r.GET("/stats", h.GetStats, middleware.Require(permission.AssetGroupsRead))

		// List and create
		r.GET("/", h.List, middleware.Require(permission.AssetGroupsRead))
		r.POST("/", h.Create, middleware.Require(permission.AssetGroupsWrite))

		// Bulk operations
		r.PATCH("/bulk", h.BulkUpdate, middleware.Require(permission.AssetGroupsWrite))
		r.DELETE("/bulk", h.BulkDelete, middleware.Require(permission.AssetGroupsDelete))

		// Single resource operations
		r.GET("/{id}", h.Get, middleware.Require(permission.AssetGroupsRead))
		r.PUT("/{id}", h.Update, middleware.Require(permission.AssetGroupsWrite))
		r.DELETE("/{id}", h.Delete, middleware.Require(permission.AssetGroupsDelete))

		// Asset membership
		r.GET("/{id}/assets", h.GetAssets, middleware.Require(permission.AssetGroupsRead))
		r.POST("/{id}/assets", h.AddAssets, middleware.Require(permission.AssetGroupsWrite))
		r.DELETE("/{id}/assets", h.RemoveAssets, middleware.Require(permission.AssetGroupsWrite))

		// Findings in group
		r.GET("/{id}/findings", h.GetFindings, middleware.Require(permission.AssetGroupsRead))
	}, tenantMiddlewares...)
}

// registerScopeRoutes registers scope configuration endpoints.
// Scope configuration includes targets, exclusions, and scan schedules.
func registerScopeRoutes(
	router Router,
	h *handler.ScopeHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
) {
	// Build tenant middleware chain from JWT token
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	// Scope routes - tenant from JWT token
	router.Group("/api/v1/scope", func(r Router) {
		// Stats endpoint
		r.GET("/stats", h.GetStats, middleware.Require(permission.ScopeRead))

		// Check scope endpoint
		r.POST("/check", h.CheckScope, middleware.Require(permission.ScopeRead))
	}, tenantMiddlewares...)

	// Scope Target routes
	router.Group("/api/v1/scope/targets", func(r Router) {
		// Read operations
		r.GET("/", h.ListTargets, middleware.Require(permission.ScopeRead))
		r.GET("/{id}", h.GetTarget, middleware.Require(permission.ScopeRead))

		// Write operations
		r.POST("/", h.CreateTarget, middleware.Require(permission.ScopeWrite))
		r.PUT("/{id}", h.UpdateTarget, middleware.Require(permission.ScopeWrite))
		r.POST("/{id}/activate", h.ActivateTarget, middleware.Require(permission.ScopeWrite))
		r.POST("/{id}/deactivate", h.DeactivateTarget, middleware.Require(permission.ScopeWrite))

		// Delete operations
		r.DELETE("/{id}", h.DeleteTarget, middleware.Require(permission.ScopeDelete))
	}, tenantMiddlewares...)

	// Scope Exclusion routes
	router.Group("/api/v1/scope/exclusions", func(r Router) {
		// Read operations
		r.GET("/", h.ListExclusions, middleware.Require(permission.ScopeRead))
		r.GET("/{id}", h.GetExclusion, middleware.Require(permission.ScopeRead))

		// Write operations
		r.POST("/", h.CreateExclusion, middleware.Require(permission.ScopeWrite))
		r.PUT("/{id}", h.UpdateExclusion, middleware.Require(permission.ScopeWrite))
		r.POST("/{id}/approve", h.ApproveExclusion, middleware.Require(permission.ScopeWrite))
		r.POST("/{id}/activate", h.ActivateExclusion, middleware.Require(permission.ScopeWrite))
		r.POST("/{id}/deactivate", h.DeactivateExclusion, middleware.Require(permission.ScopeWrite))

		// Delete operations
		r.DELETE("/{id}", h.DeleteExclusion, middleware.Require(permission.ScopeDelete))
	}, tenantMiddlewares...)

	// Scan Schedule routes
	router.Group("/api/v1/scope/schedules", func(r Router) {
		// Read operations
		r.GET("/", h.ListSchedules, middleware.Require(permission.ScopeRead))
		r.GET("/{id}", h.GetSchedule, middleware.Require(permission.ScopeRead))

		// Write operations
		r.POST("/", h.CreateSchedule, middleware.Require(permission.ScopeWrite))
		r.PUT("/{id}", h.UpdateSchedule, middleware.Require(permission.ScopeWrite))
		r.POST("/{id}/enable", h.EnableSchedule, middleware.Require(permission.ScopeWrite))
		r.POST("/{id}/disable", h.DisableSchedule, middleware.Require(permission.ScopeWrite))

		// Delete operations
		r.DELETE("/{id}", h.DeleteSchedule, middleware.Require(permission.ScopeDelete))
	}, tenantMiddlewares...)
}

// registerAssetTypeRoutes registers asset type management endpoints.
// Asset types are read-only system configuration created via DB seed.
func registerAssetTypeRoutes(
	router Router,
	h *handler.AssetTypeHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
) {
	// Build tenant middleware chain from JWT token
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	// Asset Type Category routes (read-only)
	router.Group("/api/v1/asset-types/categories", func(r Router) {
		r.GET("/", h.ListCategories, middleware.Require(permission.AssetsRead))
		r.GET("/{categoryId}", h.GetCategory, middleware.Require(permission.AssetsRead))
	}, tenantMiddlewares...)

	// Asset Type routes (read-only)
	router.Group("/api/v1/asset-types", func(r Router) {
		r.GET("/", h.ListAssetTypes, middleware.Require(permission.AssetsRead))
		r.GET("/{id}", h.GetAssetType, middleware.Require(permission.AssetsRead))
	}, tenantMiddlewares...)
}

// registerFindingSourceRoutes registers finding source configuration endpoints.
// Finding sources are read-only system configuration created via DB seed.
// These are used for categorizing vulnerability/finding sources (SAST, DAST, pentest, etc.)
func registerFindingSourceRoutes(
	router Router,
	h *handler.FindingSourceHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
) {
	// Build tenant middleware chain from JWT token
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	// Finding Source Category routes (read-only)
	router.Group("/api/v1/config/finding-sources/categories", func(r Router) {
		r.GET("/", h.ListCategories, middleware.Require(permission.FindingsRead))
		r.GET("/{categoryId}", h.GetCategory, middleware.Require(permission.FindingsRead))
	}, tenantMiddlewares...)

	// Finding Source routes (read-only)
	router.Group("/api/v1/config/finding-sources", func(r Router) {
		r.GET("/", h.ListFindingSources, middleware.Require(permission.FindingsRead))
		r.GET("/code/{code}", h.GetFindingSourceByCode, middleware.Require(permission.FindingsRead))
		r.GET("/{id}", h.GetFindingSource, middleware.Require(permission.FindingsRead))
	}, tenantMiddlewares...)
}

// registerAttackSurfaceRoutes registers attack surface endpoints.
// Attack surface provides aggregated statistics for external attack surface monitoring.
// Tenant stats use tenant from JWT token.
func registerAttackSurfaceRoutes(
	router Router,
	h *handler.AttackSurfaceHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
) {
	// Build tenant middleware chain from JWT token
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	// Attack Surface routes
	router.Group("/api/v1/attack-surface", func(r Router) {
		r.GET("/stats", h.GetStats, middleware.Require(permission.AssetsRead))
	}, tenantMiddlewares...)
}

// registerBranchRoutes registers branch management endpoints.
// Branches are repository-scoped, tenant from JWT token.
func registerBranchRoutes(
	router Router,
	h *handler.BranchHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
) {
	// Build tenant middleware chain from JWT token
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	// Branch routes - tenant from JWT token, scoped to repository
	router.Group("/api/v1/repositories/{repositoryId}/branches", func(r Router) {
		// List branches for a repository
		r.GET("/", h.List, middleware.Require(permission.AssetsRead))

		// Create a new branch
		r.POST("/", h.Create, middleware.Require(permission.AssetsWrite))

		// Get, update, delete specific branch
		r.GET("/{branchId}", h.Get, middleware.Require(permission.AssetsRead))
		r.PUT("/{branchId}", h.Update, middleware.Require(permission.AssetsWrite))
		r.DELETE("/{branchId}", h.Delete, middleware.Require(permission.AssetsDelete))

		// Default branch management
		r.GET("/default", h.GetDefault, middleware.Require(permission.AssetsRead))
		r.PUT("/{branchId}/default", h.SetDefault, middleware.Require(permission.AssetsWrite))
	}, tenantMiddlewares...)
}

// registerAssetServiceRoutes registers asset service endpoints.
// Services are network services discovered on assets (ports, protocols).
// Part of the CTEM Discovery phase.
func registerAssetServiceRoutes(
	router Router,
	h *handler.AssetServiceHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
	moduleService *app.ModuleService,
) {
	// Build tenant middleware chain from JWT token
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	// Add module check middleware - services require assets module
	if moduleService != nil {
		tenantMiddlewares = append(tenantMiddlewares, middleware.RequireModule(moduleService, module.ModuleAssets))
	}

	// Asset Service routes - standalone
	router.Group("/api/v1/services", func(r Router) {
		// Stats endpoint (must be before /{id})
		r.GET("/stats", h.Stats, middleware.Require(permission.AssetsRead))
		r.GET("/public", h.ListPublic, middleware.Require(permission.AssetsRead))

		// List all services
		r.GET("/", h.List, middleware.Require(permission.AssetsRead))

		// Single service operations
		r.GET("/{id}", h.Get, middleware.Require(permission.AssetsRead))
		r.PUT("/{id}", h.Update, middleware.Require(permission.AssetsWrite))
		r.DELETE("/{id}", h.Delete, middleware.Require(permission.AssetsDelete))
	}, tenantMiddlewares...)

	// Asset-scoped service routes
	router.Group("/api/v1/assets/{id}/services", func(r Router) {
		r.GET("/", h.ListByAsset, middleware.Require(permission.AssetsRead))
		r.POST("/", h.Create, middleware.Require(permission.AssetsWrite))
	}, tenantMiddlewares...)
}

// registerAssetStateHistoryRoutes registers asset state history endpoints.
// State history tracks changes for audit, compliance, and shadow IT detection.
// Part of the CTEM Discovery phase.
func registerAssetStateHistoryRoutes(
	router Router,
	h *handler.AssetStateHistoryHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
	moduleService *app.ModuleService,
) {
	// Build tenant middleware chain from JWT token
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	// Add module check middleware - state history requires assets module
	if moduleService != nil {
		tenantMiddlewares = append(tenantMiddlewares, middleware.RequireModule(moduleService, module.ModuleAssets))
	}

	// State History routes - standalone
	router.Group("/api/v1/state-history", func(r Router) {
		// Stats and analytics endpoints (must be before /{id})
		r.GET("/stats", h.Stats, middleware.Require(permission.AssetsRead))
		r.GET("/timeline", h.Timeline, middleware.Require(permission.AssetsRead))

		// Shadow IT detection
		r.GET("/shadow-it", h.ShadowITCandidates, middleware.Require(permission.AssetsRead))
		r.GET("/appearances", h.RecentAppearances, middleware.Require(permission.AssetsRead))
		r.GET("/disappearances", h.RecentDisappearances, middleware.Require(permission.AssetsRead))

		// Exposure tracking
		r.GET("/exposure-changes", h.ExposureChanges, middleware.Require(permission.AssetsRead))
		r.GET("/newly-exposed", h.NewlyExposed, middleware.Require(permission.AssetsRead))

		// Compliance
		r.GET("/compliance", h.ComplianceChanges, middleware.Require(permission.AssetsRead))

		// List and get
		r.GET("/", h.List, middleware.Require(permission.AssetsRead))
		r.GET("/{id}", h.Get, middleware.Require(permission.AssetsRead))
	}, tenantMiddlewares...)

	// Asset-scoped state history routes
	router.Group("/api/v1/assets/{id}/state-history", func(r Router) {
		r.GET("/", h.ListByAsset, middleware.Require(permission.AssetsRead))
	}, tenantMiddlewares...)
}
