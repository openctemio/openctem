package routes

import (
	"github.com/openctemio/openctem/server/internal/infra/http/handler"
	"github.com/openctemio/openctem/server/internal/infra/http/middleware"
	"github.com/openctemio/openctem/server/pkg/domain/permission"
)

// registerContentCatalogRoutes registers the content catalog as one
// organization sees it (RFC-099). The tenant comes from the JWT. Reads need
// content:read; install, update, rollback, uninstall and the decisions on
// requests need content:install and a recent sign-in; the approval option
// needs the organization settings permission and a recent sign-in;
// publishing and revoking private packages need content:publish and a
// recent sign-in.
func registerContentCatalogRoutes(router Router, h *handler.ContentCatalogHandler, authMiddleware, userSyncMiddleware Middleware) {
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)
	router.Group("/api/v1/content", func(r Router) {
		r.GET("/packages", h.List, middleware.Require(permission.ContentRead))
		r.GET("/packages/{namespace}/{name}", h.Get, middleware.Require(permission.ContentRead))
		r.GET("/installs", h.Installs, middleware.Require(permission.ContentRead))
		r.POST("/installs", h.Install, middleware.Require(permission.ContentInstall), requireStepUpSensitive())
		r.POST("/installs/{namespace}/{name}/update", h.Update, middleware.Require(permission.ContentInstall), requireStepUpSensitive())
		r.POST("/installs/{namespace}/{name}/rollback", h.Rollback, middleware.Require(permission.ContentInstall), requireStepUpSensitive())
		r.PUT("/installs/{namespace}/{name}/pin", h.Pin, middleware.Require(permission.ContentInstall))
		r.DELETE("/installs/{namespace}/{name}", h.Uninstall, middleware.Require(permission.ContentInstall), requireStepUpSensitive())
		r.GET("/requests", h.Requests, middleware.Require(permission.ContentRead))
		r.POST("/requests/{id}/approve", h.Approve, middleware.Require(permission.ContentInstall), requireStepUpSensitive())
		r.POST("/requests/{id}/reject", h.Reject, middleware.Require(permission.ContentInstall), requireStepUpSensitive())
		r.POST("/requests/{id}/cancel", h.Cancel, middleware.Require(permission.ContentInstall))
		r.GET("/settings", h.Settings, middleware.Require(permission.ContentRead))
		r.PUT("/settings", h.PutSettings, middleware.Require(permission.SettingsWrite), requireStepUpSensitive())
		r.GET("/trust", h.Trust, middleware.Require(permission.ContentRead))
		r.POST("/private-packages", h.Publish, middleware.Require(permission.ContentPublish), requireStepUpSensitive())
		r.POST("/private-packages/{namespace}/{name}/{version}/revoke", h.RevokePrivate, middleware.Require(permission.ContentPublish), requireStepUpSensitive())
	}, tenantMiddlewares...)
}
