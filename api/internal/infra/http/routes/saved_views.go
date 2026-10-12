package routes

import (
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
)

// registerSavedViewRoutes mounts /api/v1/views (saved list views, D15). The
// only page with views today is Findings, so the routes need findings:read;
// the service checks each view's page permission again.
func registerSavedViewRoutes(router Router, h *handler.SavedViewHandler, authMiddleware, userSyncMiddleware Middleware) {
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)
	router.Group("/api/v1/views", func(r Router) {
		read := middleware.Require(permission.FindingsRead)
		r.GET("/", h.List, read)
		r.POST("/", h.Create, read)
		r.GET("/{id}", h.Get, read)
		r.PUT("/{id}", h.Update, read)
		r.DELETE("/{id}", h.Delete, read)
	}, tenantMiddlewares...)
}
