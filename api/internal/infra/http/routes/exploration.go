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

// registerExplorationLeadRoutes registers /api/v1/exploration/leads
// (docs/architecture/exploration.md, "Approvals and people"). Reading
// follows assets:read and the caller's data scope (the service reads every
// lead through it: out of scope answers 404). Opening a lead asks for a
// step, so it needs scans:execute; approving lets an active step run, so
// it needs scans:approve and a fresh step-up; dismissing needs
// scans:approve.
func registerExplorationLeadRoutes(router Router, h *handler.ExplorationLeadHandler, authMiddleware, userSyncMiddleware Middleware) {
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)
	router.Group("/api/v1/exploration/leads", func(r Router) {
		r.GET("/", h.List, middleware.Require(permission.AssetsRead))
		r.POST("/", h.Open, middleware.Require(permission.ScansExecute))
		r.POST("/approve", h.Approve, middleware.Require(permission.ScansApprove), requireStepUp())
		r.POST("/dismiss", h.Dismiss, middleware.Require(permission.ScansApprove))
		r.GET("/{id}", h.Get, middleware.Require(permission.AssetsRead))
	}, tenantMiddlewares...)
}
