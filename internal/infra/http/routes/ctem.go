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
) {
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

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
) {
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	router.Group("/api/v1/attacker-profiles", func(r Router) {
		r.GET("/", h.List, middleware.Require(permission.AttackerProfilesRead))
		r.POST("/", h.Create, middleware.Require(permission.AttackerProfilesWrite))
		r.GET("/{id}", h.Get, middleware.Require(permission.AttackerProfilesRead))
		r.PUT("/{id}", h.Update, middleware.Require(permission.AttackerProfilesWrite))
		r.DELETE("/{id}", h.Delete, middleware.Require(permission.AttackerProfilesWrite))
	}, tenantMiddlewares...)
}

// registerBusinessServiceRoutes registers business service CRUD routes.
func registerBusinessServiceRoutes(
	router Router,
	h *handler.BusinessServiceHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
) {
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

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

// registerCTEMCycleRoutes registers CTEM cycle management routes.
func registerCTEMCycleRoutes(
	router Router,
	h *handler.CTEMCycleHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
) {
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	router.Group("/api/v1/ctem-cycles", func(r Router) {
		r.GET("/", h.List, middleware.Require(permission.CTEMCyclesRead))
		r.POST("/", h.Create, middleware.Require(permission.CTEMCyclesWrite))
		r.GET("/{id}", h.Get, middleware.Require(permission.CTEMCyclesRead))
		r.PUT("/{id}", h.Update, middleware.Require(permission.CTEMCyclesWrite))
		r.POST("/{id}/activate", h.Activate, middleware.Require(permission.CTEMCyclesWrite))
		r.POST("/{id}/start-review", h.StartReview, middleware.Require(permission.CTEMCyclesWrite))
		r.POST("/{id}/close", h.Close, middleware.Require(permission.CTEMCyclesWrite))
		r.GET("/{id}/scope", h.GetScope, middleware.Require(permission.CTEMCyclesRead))
		r.POST("/{id}/profiles", h.LinkProfile, middleware.Require(permission.CTEMCyclesWrite))
	}, tenantMiddlewares...)
}
