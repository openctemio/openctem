package routes

import (
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
)

// registerScopeLetterRoutes registers the authorization letter routes
// (RFC-065 §13), gated by the scope_config module. Uploading a letter
// authorizes nothing (the entries naming it go through the approval
// policy); revoking narrows and needs the scope approval permission.
func registerScopeLetterRoutes(router Router, h *handler.ScopeLetterHandler, authMiddleware, userSyncMiddleware, moduleGate Middleware) {
	tenantMiddlewares := append(buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware), moduleGate)
	router.Group("/api/v1/scope/letters", func(r Router) {
		r.GET("/", h.List, middleware.Require(permission.ScopeRead))
		r.POST("/", h.Upload, middleware.Require(permission.ScopeWrite))
		r.GET("/{id}/file", h.File, middleware.Require(permission.ScopeRead))
		r.POST("/{id}/revoke", h.Revoke, middleware.Require(permission.ScopeApprove))
	}, tenantMiddlewares...)
}
