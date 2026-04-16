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
		r.GET("/", h.List, middleware.Require(permission.FindingsRead))
		r.POST("/", h.Create, middleware.Require(permission.FindingsWrite))
		r.GET("/{id}", h.Get, middleware.Require(permission.FindingsRead))
		r.PUT("/{id}", h.Update, middleware.Require(permission.FindingsWrite))
		r.DELETE("/{id}", h.Delete, middleware.Require(permission.FindingsWrite))
		r.POST("/{id}/test", h.RecordTest, middleware.Require(permission.FindingsWrite))
		r.POST("/{id}/assets", h.LinkAssets, middleware.Require(permission.FindingsWrite))
		r.POST("/{id}/findings", h.LinkFindings, middleware.Require(permission.FindingsWrite))
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
		r.GET("/", h.List, middleware.Require(permission.ScopeRead))
		r.POST("/", h.Create, middleware.Require(permission.ScopeWrite))
		r.GET("/{id}", h.Get, middleware.Require(permission.ScopeRead))
		r.PUT("/{id}", h.Update, middleware.Require(permission.ScopeWrite))
		r.DELETE("/{id}", h.Delete, middleware.Require(permission.ScopeDelete))
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
		r.GET("/", h.List, middleware.Require(permission.ScopeRead))
		r.POST("/", h.Create, middleware.Require(permission.ScopeWrite))
		r.GET("/{id}", h.Get, middleware.Require(permission.ScopeRead))
		r.PUT("/{id}", h.Update, middleware.Require(permission.ScopeWrite))
		r.DELETE("/{id}", h.Delete, middleware.Require(permission.ScopeWrite))
		r.POST("/{id}/assets", h.LinkAsset, middleware.Require(permission.ScopeWrite))
		r.GET("/{id}/assets", h.ListAssets, middleware.Require(permission.ScopeRead))
		r.DELETE("/{id}/assets/{assetId}", h.UnlinkAsset, middleware.Require(permission.ScopeWrite))
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
		r.GET("/", h.List, middleware.Require(permission.ScopeRead))
		r.POST("/", h.Create, middleware.Require(permission.ScopeWrite))
		r.GET("/{id}", h.Get, middleware.Require(permission.ScopeRead))
		r.PUT("/{id}", h.Update, middleware.Require(permission.ScopeWrite))
		r.POST("/{id}/activate", h.Activate, middleware.Require(permission.ScopeWrite))
		r.POST("/{id}/start-review", h.StartReview, middleware.Require(permission.ScopeWrite))
		r.POST("/{id}/close", h.Close, middleware.Require(permission.ScopeWrite))
		r.GET("/{id}/scope", h.GetScope, middleware.Require(permission.ScopeRead))
		r.POST("/{id}/profiles", h.LinkProfile, middleware.Require(permission.ScopeWrite))
	}, tenantMiddlewares...)
}

