package routes

import (
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
)

// registerFindingLifecycleRoutes mounts the organization's finding
// lifecycles (docs/rfcs/RFC-110-tenant-lifecycles.md): the sub-status
// catalog and the lifecycle schemes with their versions. Tenant from the
// token. Reading needs findings:read (sub-status names show on findings
// anyway); every change needs findings:lifecycles:write, and publishing a
// version, changing or archiving a scheme and archiving a sub-status also
// need a recent sign-in.
func registerFindingLifecycleRoutes(router Router, h *handler.FindingLifecycleHandler, authMiddleware, userSyncMiddleware Middleware) {
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	router.Group("/api/v1/lifecycle-sub-statuses", func(r Router) {
		r.GET("/", h.ListSubStatuses, middleware.Require(permission.FindingsRead))
		r.POST("/", h.CreateSubStatus, middleware.Require(permission.FindingsLifecyclesWrite))
		r.PATCH("/{id}", h.UpdateSubStatus, middleware.Require(permission.FindingsLifecyclesWrite))
		r.DELETE("/{id}", h.ArchiveSubStatus, middleware.Require(permission.FindingsLifecyclesWrite), requireStepUp())
		r.POST("/{id}/reactivate", h.ReactivateSubStatus, middleware.Require(permission.FindingsLifecyclesWrite))
	}, tenantMiddlewares...)

	router.Group("/api/v1/lifecycles", func(r Router) {
		r.GET("/", h.ListLifecycles, middleware.Require(permission.FindingsRead))
		r.GET("/{id}", h.GetLifecycle, middleware.Require(permission.FindingsRead))
		r.GET("/{id}/versions", h.ListLifecycleVersions, middleware.Require(permission.FindingsRead))
		r.GET("/{id}/versions/{version_id}", h.GetLifecycleVersion, middleware.Require(permission.FindingsRead))
		r.POST("/", h.CreateLifecycle, middleware.Require(permission.FindingsLifecyclesWrite))
		r.PATCH("/{id}", h.UpdateLifecycle, middleware.Require(permission.FindingsLifecyclesWrite), requireStepUp())
		r.DELETE("/{id}", h.ArchiveLifecycle, middleware.Require(permission.FindingsLifecyclesWrite), requireStepUp())
		r.POST("/{id}/versions", h.CreateLifecycleDraft, middleware.Require(permission.FindingsLifecyclesWrite))
		r.PUT("/{id}/versions/{version_id}", h.UpdateLifecycleDraft, middleware.Require(permission.FindingsLifecyclesWrite))
		r.POST("/{id}/versions/{version_id}/test", h.TestLifecycleVersion, middleware.Require(permission.FindingsLifecyclesWrite))
		r.POST("/{id}/versions/{version_id}/publish", h.PublishLifecycleVersion,
			middleware.Require(permission.FindingsLifecyclesWrite), requireStepUp())
	}, tenantMiddlewares...)
}
