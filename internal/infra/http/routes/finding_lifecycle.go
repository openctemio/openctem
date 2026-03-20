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
func registerFindingLifecycleRoutes(
	router Router,
	h *handler.FindingLifecycleHandler,
	authMiddleware, userSyncMiddleware Middleware,
) {
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	// Finding lifecycle routes
	router.Group("/api/v1/findings", func(r Router) {
		// Group view (read)
		r.GET("/groups", h.ListFindingGroups, middleware.Require(permission.FindingsRead))

		// Related CVEs (read) — path avoids conflict with /{id}/* routes
		r.GET("/related-cves/{cveId}", h.GetRelatedCVEs, middleware.Require(permission.FindingsRead))

		// Actions (write) — rate limited to prevent bulk abuse
		r.POST("/actions/fix-applied", h.FixApplied,
			middleware.Require(permission.FindingsFixApply))
		r.POST("/actions/verify", h.Verify,
			middleware.Require(permission.FindingsVerify))
		r.POST("/actions/reject-fix", h.RejectFix,
			middleware.Require(permission.FindingsVerify))
		r.POST("/actions/assign-to-owners", h.AssignToOwners,
			middleware.Require(permission.FindingsWrite))
	}, tenantMiddlewares...)
}
