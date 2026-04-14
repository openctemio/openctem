package routes

import (
	"github.com/openctemio/api/internal/infra/http/handler"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/domain/permission"
)

// registerBusinessUnitRoutes registers business unit management routes.
func registerBusinessUnitRoutes(
	router Router,
	h *handler.BusinessUnitHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
) {
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	router.Group("/api/v1/business-units", func(r Router) {
		r.GET("/", h.List, middleware.Require(permission.AssetsRead))
		r.POST("/", h.Create, middleware.Require(permission.AssetsWrite))
		r.GET("/{id}", h.Get, middleware.Require(permission.AssetsRead))
		r.PUT("/{id}", h.Update, middleware.Require(permission.AssetsWrite))
		r.DELETE("/{id}", h.Delete, middleware.Require(permission.AssetsWrite))
		r.POST("/{id}/assets", h.AddAsset, middleware.Require(permission.AssetsWrite))
		r.DELETE("/{id}/assets/{assetId}", h.RemoveAsset, middleware.Require(permission.AssetsWrite))
	}, tenantMiddlewares...)
}
