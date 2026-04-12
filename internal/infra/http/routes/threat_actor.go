package routes

import (
	"github.com/openctemio/api/internal/infra/http/handler"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/domain/permission"
)

// registerThreatActorRoutes registers threat actor intelligence routes.
func registerThreatActorRoutes(
	router Router,
	h *handler.ThreatActorHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
) {
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	router.Group("/api/v1/threat-actors", func(r Router) {
		r.GET("/", h.List, middleware.Require(permission.ThreatIntelRead))
		r.POST("/", h.Create, middleware.Require(permission.ThreatIntelWrite))
		r.GET("/{id}", h.Get, middleware.Require(permission.ThreatIntelRead))
		r.DELETE("/{id}", h.Delete, middleware.Require(permission.ThreatIntelWrite))
	}, tenantMiddlewares...)
}
