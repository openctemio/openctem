package routes

import (
	"github.com/openctemio/api/internal/infra/http/handler"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/domain/permission"
)

// registerCompensatingControlRoutes registers compensating control CRUD routes.
func registerCompensatingControlRoutes(
	router Router,
	h *handler.CompensatingControlHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
	moduleGate Middleware,
) {
	// Append the module gate after tenant extraction so it can read the tenant.
	tenantMiddlewares := append(buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware), moduleGate)

	router.Group("/api/v1/compensating-controls", func(r Router) {
		r.GET("/", h.List, middleware.Require(permission.CompensatingControlsRead))
		r.POST("/", h.Create, middleware.Require(permission.CompensatingControlsWrite))
		r.GET("/{id}", h.Get, middleware.Require(permission.CompensatingControlsRead))
		r.PUT("/{id}", h.Update, middleware.Require(permission.CompensatingControlsWrite))
		r.DELETE("/{id}", h.Delete, middleware.Require(permission.CompensatingControlsWrite))
		r.POST("/{id}/test", h.RecordTest, middleware.Require(permission.CompensatingControlsWrite))
		r.POST("/{id}/assets", h.LinkAssets, middleware.Require(permission.CompensatingControlsWrite))
		r.POST("/{id}/findings", h.LinkFindings, middleware.Require(permission.CompensatingControlsWrite))
	}, tenantMiddlewares...)
}

// registerAttackerProfileRoutes registers attacker profile CRUD routes.
func registerAttackerProfileRoutes(
	router Router,
	h *handler.AttackerProfileHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
	moduleGate Middleware,
) {
	// Append the module gate after tenant extraction so it can read the tenant.
	tenantMiddlewares := append(buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware), moduleGate)

	router.Group("/api/v1/attacker-profiles", func(r Router) {
		r.GET("/", h.List, middleware.Require(permission.AttackerProfilesRead))
		r.POST("/", h.Create, middleware.Require(permission.AttackerProfilesWrite))
		r.GET("/{id}", h.Get, middleware.Require(permission.AttackerProfilesRead))
		r.PUT("/{id}", h.Update, middleware.Require(permission.AttackerProfilesWrite))
		r.DELETE("/{id}", h.Delete, middleware.Require(permission.AttackerProfilesWrite))
	}, tenantMiddlewares...)
}

// registerThreatModelRoutes registers continuous threat-modeling routes.
//
// Permission decision: a dedicated ThreatModelsRead/Write permission would need a
// new permissions + role_permissions seed migration (see 000153_ctem_permissions),
// which is disproportionate for this step. Threat models are read-derived from
// the asset graph + findings, so we gate reads with AssetsRead and generation
// (a compute/write over that data) with AssetsWrite. Swap to a dedicated
// ctem:threat_models:* permission when that seed migration lands.
func registerThreatModelRoutes(
	router Router,
	h *handler.ThreatModelHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
) {
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	router.Group("/api/v1/threat-models", func(r Router) {
		r.GET("/", h.List, middleware.Require(permission.AssetsRead))
		r.POST("/generate", h.Generate, middleware.Require(permission.AssetsWrite))
		r.GET("/{id}", h.Get, middleware.Require(permission.AssetsRead))
		r.GET("/{id}/coverage", h.Coverage, middleware.Require(permission.AssetsRead))
	}, tenantMiddlewares...)
}

// registerBusinessServiceRoutes registers business service CRUD routes.
func registerBusinessServiceRoutes(
	router Router,
	h *handler.BusinessServiceHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
	moduleGate Middleware,
) {
	// Append the module gate after tenant extraction so it can read the tenant.
	tenantMiddlewares := append(buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware), moduleGate)

	router.Group("/api/v1/business-services", func(r Router) {
		r.GET("/", h.List, middleware.Require(permission.BusinessServicesRead))
		r.POST("/", h.Create, middleware.Require(permission.BusinessServicesWrite))
		r.GET("/{id}", h.Get, middleware.Require(permission.BusinessServicesRead))
		r.PUT("/{id}", h.Update, middleware.Require(permission.BusinessServicesWrite))
		r.DELETE("/{id}", h.Delete, middleware.Require(permission.BusinessServicesWrite))
		r.POST("/{id}/assets", h.LinkAsset, middleware.Require(permission.BusinessServicesWrite))
		r.GET("/{id}/assets", h.ListAssets, middleware.Require(permission.BusinessServicesRead))
		r.DELETE("/{id}/assets/{assetId}", h.UnlinkAsset, middleware.Require(permission.BusinessServicesWrite))
	}, tenantMiddlewares...)
}

// registerPriorityRuleRoutes registers priority override rule CRUD routes.
func registerPriorityRuleRoutes(
	router Router,
	h *handler.PriorityRuleHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
	moduleGate Middleware,
) {
	// Append the module gate after tenant extraction so it can read the tenant.
	tenantMiddlewares := append(buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware), moduleGate)

	router.Group("/api/v1/priority-rules", func(r Router) {
		r.GET("/", h.List, middleware.Require(permission.PriorityRulesRead))
		r.POST("/", h.Create, middleware.Require(permission.PriorityRulesWrite))
		// Dry-run a DRAFT rule against live findings — read-only evaluation, so it
		// takes the READ permission. Registered before "/{id}" (distinct static
		// path, no capture conflict).
		r.POST("/dry-run", h.DryRun, middleware.Require(permission.PriorityRulesRead))
		r.GET("/{id}", h.Get, middleware.Require(permission.PriorityRulesRead))
		r.PUT("/{id}", h.Update, middleware.Require(permission.PriorityRulesWrite))
		r.DELETE("/{id}", h.Delete, middleware.Require(permission.PriorityRulesWrite))
	}, tenantMiddlewares...)
}

// registerCTEMCycleRoutes registers CTEM cycle management routes.
func registerCTEMCycleRoutes(
	router Router,
	h *handler.CTEMCycleHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
	moduleGate Middleware,
) {
	// Append the module gate after tenant extraction so it can read the tenant.
	tenantMiddlewares := append(buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware), moduleGate)

	router.Group("/api/v1/ctem-cycles", func(r Router) {
		r.GET("/", h.List, middleware.Require(permission.CTEMCyclesRead))
		r.POST("/", h.Create, middleware.Require(permission.CTEMCyclesWrite))
		// Static /metrics/trend is registered before /{id}/... so it is
		// never shadowed by the {id} param route.
		r.GET("/metrics/trend", h.MetricsTrend, middleware.Require(permission.CTEMCyclesRead))
		r.GET("/{id}/metrics", h.GetMetrics, middleware.Require(permission.CTEMCyclesRead))
		r.GET("/{id}", h.Get, middleware.Require(permission.CTEMCyclesRead))
		r.PUT("/{id}", h.Update, middleware.Require(permission.CTEMCyclesWrite))
		r.POST("/{id}/activate", h.Activate, middleware.Require(permission.CTEMCyclesWrite))
		r.POST("/{id}/start-review", h.StartReview, middleware.Require(permission.CTEMCyclesWrite))
		r.POST("/{id}/close", h.Close, middleware.Require(permission.CTEMCyclesWrite))
		// Feedback-to-scope: record scope-refinement notes at review/close.
		r.POST("/{id}/scope-refinement", h.UpdateScopeRefinement, middleware.Require(permission.CTEMCyclesWrite))
		r.GET("/{id}/scope", h.GetScope, middleware.Require(permission.CTEMCyclesRead))
		r.POST("/{id}/profiles", h.LinkProfile, middleware.Require(permission.CTEMCyclesWrite))
	}, tenantMiddlewares...)
}
