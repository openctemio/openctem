package routes

import (
	"github.com/openctemio/api/internal/infra/http/handler"
)

// registerUserDashboardRoutes registers the per-user customizable dashboards
// API (RFC-021). Mounted under /api/v1/me/*: self-scoped, so no permission gate
// is required — the same token+tenant middleware chain as the other /me/*
// routes establishes the caller, and every handler scopes to that caller's
// (tenant, user).
func registerUserDashboardRoutes(
	router Router,
	h *handler.UserDashboardHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
) {
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	router.Group("/api/v1/me/dashboards", func(r Router) {
		r.GET("/", h.List)
		r.POST("/", h.Create)
		r.GET("/{id}", h.Get)
		r.PUT("/{id}", h.Update)
		r.DELETE("/{id}", h.Delete)
		r.POST("/{id}/default", h.SetDefault)
	}, tenantMiddlewares...)
}
