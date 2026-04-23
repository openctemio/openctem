package routes

import (
	"github.com/openctemio/api/internal/infra/http/handler"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/domain/permission"
)

// registerIOCRoutes registers CRUD routes for the tenant IOC catalogue.
// Reuses threat_intel:read/write permissions — semantically an IOC is
// a tenant-scoped piece of threat intelligence.
func registerIOCRoutes(
	router Router,
	h *handler.IOCHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
) {
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	router.Group("/api/v1/iocs", func(r Router) {
		r.GET("/", h.List, middleware.Require(permission.ThreatIntelRead))
		r.POST("/", h.Create, middleware.Require(permission.ThreatIntelWrite))
		r.GET("/{id}", h.Get, middleware.Require(permission.ThreatIntelRead))
		r.DELETE("/{id}", h.Delete, middleware.Require(permission.ThreatIntelWrite))
	}, tenantMiddlewares...)
}
