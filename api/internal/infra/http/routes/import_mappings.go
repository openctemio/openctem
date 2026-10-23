package routes

import (
	"time"

	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
)

// registerImportMappingRoutes registers the organization's import mappings
// (docs/rfcs/RFC-126-import-mappings.md).
//
// Reading a mapping needs integrations:read or assets:import (an uploader
// picks one); writing, validating and previewing need integrations:manage.
// A preview parses up to 5 MiB of hostile input, so it is limited per
// organization: 20 per minute, burst 5, across all its members.
func registerImportMappingRoutes(router Router, h *handler.ImportMappingHandler, authMiddleware, userSyncMiddleware Middleware) {
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)
	previewRL := middleware.NewRateLimiter(&config.RateLimitConfig{
		Enabled:         true,
		RequestsPerSec:  20.0 / 60.0,
		Burst:           5,
		CleanupInterval: 5 * time.Minute,
	}, nil)
	read := middleware.RequireAny(permission.IntegrationsRead, permission.AssetsImport)
	manage := middleware.Require(permission.IntegrationsManage)
	body := middleware.BodyLimit(handler.MaxImportMappingBody)
	router.Group("/api/v1/import-mappings", func(r Router) {
		r.GET("/", h.List, read)
		r.GET("/templates", h.Templates, read)
		r.POST("/", h.Create, manage, body)
		r.POST("/validate", h.Validate, manage, body)
		r.POST("/preview", h.Preview, manage, previewRL.TenantMiddleware(),
			middleware.BodyLimit(handler.MaxImportMappingPreviewBody))
		r.GET("/{id}", h.Get, read)
		r.PATCH("/{id}", h.Update, manage, body)
		r.DELETE("/{id}", h.Delete, manage, requireStepUp())
		r.POST("/{id}/versions", h.AddVersion, manage, body)
		r.GET("/{id}/versions/{version}", h.GetVersion, read)
	}, tenantMiddlewares...)
}
