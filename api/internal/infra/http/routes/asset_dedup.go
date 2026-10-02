package routes

import (
	"github.com/openctemio/api/internal/infra/http/handler"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/domain/permission"
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
		r.GET("/reviews", h.ListPending, middleware.Require(permission.AssetsWrite))
		r.POST("/reviews/{id}/approve", h.Approve, middleware.Require(permission.AssetsDelete))
		r.POST("/reviews/{id}/reject", h.Reject, middleware.Require(permission.AssetsDelete))
		r.GET("/merge-log", h.MergeLog, middleware.Require(permission.AssetsRead))
	}, tenantMiddlewares...)
}
