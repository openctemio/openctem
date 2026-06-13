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
		r.GET("/", h.List, middleware.Require(permission.RemediationRead))
		r.POST("/", h.Create, middleware.Require(permission.RemediationWrite))
		r.GET("/{id}", h.Get, middleware.Require(permission.RemediationRead))
		r.PATCH("/{id}", h.Update, middleware.Require(permission.RemediationWrite))
		r.PATCH("/{id}/status", h.UpdateStatus, middleware.Require(permission.RemediationWrite))
		r.POST("/{id}/refresh", h.Refresh, middleware.Require(permission.RemediationWrite))
		r.DELETE("/{id}", h.Delete, middleware.Require(permission.RemediationWrite))
	}, tenantMiddlewares...)
}
