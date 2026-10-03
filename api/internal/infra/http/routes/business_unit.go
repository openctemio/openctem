package routes

import (
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
)

// registerBusinessUnitRoutes registers business unit management routes.
func registerBusinessUnitRoutes(
	router Router,
	h *handler.BusinessUnitHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
	moduleGate Middleware,
) {
	// Append the module gate after tenant extraction so it can read the tenant.
	tenantMiddlewares := append(buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware), moduleGate)

	router.Group("/api/v1/business-units", func(r Router) {
		r.GET("/", h.List, middleware.Require(permission.AssetsRead))
		r.POST("/", h.Create, middleware.Require(permission.AssetsWrite))
		r.GET("/{id}", h.Get, middleware.Require(permission.AssetsRead))
		r.PUT("/{id}", h.Update, middleware.Require(permission.AssetsWrite))
		// Deleting a business unit is owner/admin only (owner decision
		// 2026-10-02): members hold assets:write, and a delete drops the
		// unit's asset links and child hierarchy for the whole organization.
		r.DELETE("/{id}", h.Delete, middleware.RequireAdmin(), middleware.Require(permission.AssetsWrite))
		r.POST("/{id}/assets", h.AddAsset, middleware.Require(permission.AssetsWrite))
		r.DELETE("/{id}/assets/{assetId}", h.RemoveAsset, middleware.Require(permission.AssetsWrite))
	}, tenantMiddlewares...)
}
