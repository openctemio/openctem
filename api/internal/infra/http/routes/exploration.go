package routes

// "How we found this" for a finding and an asset
// (docs/architecture/exploration.md).

import (
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
)

// registerStoryRoutes registers GET /api/v1/findings/{id}/story and GET
// /api/v1/assets/{id}/story. The gate is the one of reading the subject; the
// data scope guard answers 404 for a subject outside the caller's scope, and
// the service reads the finding exactly as GET /findings/{id} does. Runs,
// sensors and scope entries in the story follow scans:read, sensors:read and
// attack_surface:scope:read (handler).
func registerStoryRoutes(router Router, h *handler.StoryHandler, authMiddleware, userSyncMiddleware Middleware) {
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)
	router.Group("/api/v1/findings/{id}/story", func(r Router) {
		r.GET("/", h.FindingStory, middleware.Require(permission.FindingsRead))
	}, tenantMiddlewares...)
	router.Group("/api/v1/assets/{id}/story", func(r Router) {
		r.GET("/", h.AssetStory, middleware.Require(permission.AssetsRead))
	}, tenantMiddlewares...)
}
