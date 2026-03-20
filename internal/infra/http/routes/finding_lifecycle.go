package routes

import (
	"github.com/openctemio/api/internal/infra/http/handler"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/domain/permission"
)

// RegisterFindingLifecycleRoutes registers closed-loop finding lifecycle routes.
//
// RESTful API:
//
//	GET  /api/v1/findings/groups                      → List finding groups (multi-dimension)
//	GET  /api/v1/findings/{cveId}/related-cves        → Find related CVEs (same component)
//	POST /api/v1/findings/actions/fix-applied          → Mark findings as fix applied (dev/owner)
//	POST /api/v1/findings/actions/verify               → Verify fix-applied findings (security)
//	POST /api/v1/findings/actions/reject-fix            → Reject fix (security)
//	POST /api/v1/findings/actions/assign-to-owners      → Auto-assign to asset owners
// registerFindingLifecycleRoutes registers closed-loop lifecycle endpoints.
// Uses /api/v1/finding-groups and /api/v1/finding-actions to avoid
// Chi mount conflict with existing /api/v1/findings group.
func registerFindingLifecycleRoutes(
	router Router,
	h *handler.FindingLifecycleHandler,
	authMiddleware, userSyncMiddleware Middleware,
) {
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	// Group view
	router.Group("/api/v1/finding-groups", func(r Router) {
		r.GET("/", h.ListFindingGroups, middleware.Require(permission.FindingsRead))
		r.GET("/related-cves/{cveId}", h.GetRelatedCVEs, middleware.Require(permission.FindingsRead))
	}, tenantMiddlewares...)

	// Actions
	router.Group("/api/v1/finding-actions", func(r Router) {
		r.POST("/fix-applied", h.FixApplied, middleware.Require(permission.FindingsFixApply))
		r.POST("/verify", h.Verify, middleware.Require(permission.FindingsVerify))
		r.POST("/reject-fix", h.RejectFix, middleware.Require(permission.FindingsVerify))
		r.POST("/assign-to-owners", h.AssignToOwners, middleware.Require(permission.FindingsWrite))
	}, tenantMiddlewares...)
}
