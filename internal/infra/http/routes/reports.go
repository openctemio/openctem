package routes

import (
	"github.com/openctemio/api/internal/infra/http/handler"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/domain/permission"
)

// registerReportScheduleRoutes registers report schedule endpoints.
func registerReportScheduleRoutes(
	router Router,
	h *handler.ReportScheduleHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
) {
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	router.Group("/api/v1/reports/schedules", func(r Router) {
		r.GET("/", h.List, middleware.Require(permission.ReportsRead))
		r.POST("/", h.Create, middleware.Require(permission.ReportsWrite))
		r.GET("/{id}", h.Get, middleware.Require(permission.ReportsRead))
		r.DELETE("/{id}", h.Delete, middleware.Require(permission.ReportsWrite))
		r.PATCH("/{id}/toggle", h.Toggle, middleware.Require(permission.ReportsWrite))
	}, tenantMiddlewares...)
}
