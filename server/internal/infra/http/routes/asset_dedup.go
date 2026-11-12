package routes

import (
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
)

// registerAssetDedupRoutes registers asset deduplication review endpoints.
// RFC-001: Asset Identity Resolution & Deduplication.
func registerAssetDedupRoutes(
	router Router,
	h *handler.AdminDedupHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
) {
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	router.Group("/api/v1/assets/dedup", func(r Router) {
		// Reading the queue is a read (the web route and the asset overview
		// show it to every assets:read member); acting on it merges or keeps
		// assets apart, which needs assets:delete.
		r.GET("/reviews", h.ListPending, middleware.Require(permission.AssetsRead))
		r.POST("/reviews/{id}/approve", h.Approve, middleware.Require(permission.AssetsDelete))
		r.POST("/reviews/{id}/reject", h.Reject, middleware.Require(permission.AssetsDelete))
		r.GET("/merge-log", h.MergeLog, middleware.Require(permission.AssetsRead))
	}, tenantMiddlewares...)
}
