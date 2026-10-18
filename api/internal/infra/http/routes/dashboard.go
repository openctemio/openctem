package routes

import (
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
)

// registerUserDashboardRoutes registers the dashboards API
// (docs/architecture/dashboards.md).
//
// Personal dashboards live under /api/v1/me/*: self-scoped, so no permission
// gate; every handler scopes to the caller's (tenant, user).
//
// Organization dashboards live under /api/v1/organization/dashboards:
// reading needs dashboards:org:view (the service also applies the
// dashboard's audience), every change needs dashboards:org:manage.
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
		r.PUT("/{id}/schedule", h.SetSchedule)
		r.POST("/{id}/share", h.Share)
	}, tenantMiddlewares...)

	view := middleware.RequireAny(permission.DashboardsOrgView, permission.DashboardsOrgManage)
	manage := middleware.Require(permission.DashboardsOrgManage)
	router.Group("/api/v1/organization/dashboards", func(r Router) {
		r.GET("/", h.ListOrg, view)
		r.POST("/", h.CreateOrg, manage)
		r.PUT("/order", h.ReorderOrg, manage)
		r.GET("/{id}", h.GetOrg, view)
		r.PUT("/{id}", h.UpdateOrg, manage)
		r.DELETE("/{id}", h.DeleteOrg, manage)
		r.POST("/{id}/default", h.SetOrgDefault, manage)
		r.PUT("/{id}/audience", h.SetOrgAudience, manage)
		r.PUT("/{id}/schedule", h.SetOrgSchedule, manage)
	}, tenantMiddlewares...)

	router.Group("/api/v1/organization/settings/dashboards", func(r Router) {
		r.GET("/", h.GetSettings, middleware.Require(permission.DashboardRead))
		r.PUT("/", h.UpdateSettings, middleware.RequireAdmin())
	}, tenantMiddlewares...)
}
