package routes

import (
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
)

// registerUserDashboardRoutes registers the dashboards API
// (docs/architecture/dashboards.md).
//
// Personal dashboards live under /api/v1/me/*: the layout routes are
// self-scoped (every handler scopes to the caller's tenant and user, so no
// permission gate). The routes that compute figures (preview, data, refresh)
// need dashboard:read, and each metric also needs the permission of what it
// counts (widgets.Service), so a role never reads through a dashboard what
// it cannot read directly.
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

	read := middleware.Require(permission.DashboardRead)
	router.Group("/api/v1/me/dashboards", func(r Router) {
		r.GET("/", h.List)
		r.POST("/", h.Create)
		// Static catalog of typed widget metrics; no organization data.
		r.GET("/widget-catalog", h.WidgetCatalog)
		// One typed widget computed for the caller's own scope.
		r.POST("/widget-preview", h.PreviewWidget, read)
		r.GET("/{id}", h.Get)
		r.GET("/{id}/data", h.PersonalData, read)
		r.POST("/{id}/refresh", h.RefreshPersonal, read)
		r.PUT("/{id}", h.Update)
		r.DELETE("/{id}", h.Delete)
		r.POST("/{id}/default", h.SetDefault)
		r.PUT("/{id}/schedule", h.SetSchedule)
		r.POST("/{id}/share", h.Share)
		r.POST("/{id}/flow-panel", h.AddFlowPanel)
		r.DELETE("/{id}/flow-panel/{widget_id}", h.UndoFlowPanel)
	}, tenantMiddlewares...)

	view := middleware.RequireAny(permission.DashboardsOrgView, permission.DashboardsOrgManage)
	manage := middleware.Require(permission.DashboardsOrgManage)
	router.Group("/api/v1/organization/dashboards", func(r Router) {
		r.GET("/", h.ListOrg, view)
		r.POST("/", h.CreateOrg, manage)
		r.PUT("/order", h.ReorderOrg, manage)
		r.GET("/{id}", h.GetOrg, view)
		r.GET("/{id}/data", h.OrgData, view)
		r.POST("/{id}/refresh", h.RefreshOrg, view)
		r.PUT("/{id}", h.UpdateOrg, manage)
		r.DELETE("/{id}", h.DeleteOrg, manage)
		r.POST("/{id}/default", h.SetOrgDefault, manage)
		r.PUT("/{id}/audience", h.SetOrgAudience, manage)
		r.PUT("/{id}/schedule", h.SetOrgSchedule, manage)
		r.POST("/{id}/flow-panel", h.AddOrgFlowPanel, manage)
		r.DELETE("/{id}/flow-panel/{widget_id}", h.UndoOrgFlowPanel, manage)
	}, tenantMiddlewares...)

	router.Group("/api/v1/organization/settings/dashboards", func(r Router) {
		r.GET("/", h.GetSettings, middleware.Require(permission.DashboardRead))
		r.PUT("/", h.UpdateSettings, middleware.RequireAdmin())
	}, tenantMiddlewares...)
}
