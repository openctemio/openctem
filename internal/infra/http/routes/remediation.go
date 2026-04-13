package routes

import (
	"github.com/openctemio/api/internal/infra/http/handler"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/domain/permission"
)

// registerRemediationCampaignRoutes registers remediation campaign routes.
func registerRemediationCampaignRoutes(
	router Router,
	h *handler.RemediationCampaignHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
) {
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	router.Group("/api/v1/remediation/campaigns", func(r Router) {
		r.GET("/", h.List, middleware.Require(permission.FindingsRead))
		r.POST("/", h.Create, middleware.Require(permission.FindingsWrite))
		r.GET("/{id}", h.Get, middleware.Require(permission.FindingsRead))
		r.PATCH("/{id}/status", h.UpdateStatus, middleware.Require(permission.FindingsWrite))
		r.DELETE("/{id}", h.Delete, middleware.Require(permission.FindingsWrite))
	}, tenantMiddlewares...)
}
