package routes

import (
	"github.com/openctemio/api/pkg/domain/admin"
)

// =============================================================================
// Platform Admin Routes
// =============================================================================
//
// These routes are for OpenCTEM platform administrators only.
// They manage shared infrastructure that serves all tenants.
//
// All admin routes use API Key authentication via X-Admin-API-Key header.
// This is separate from tenant admin routes which use RequireTeamAdmin.
//
// AUTHORIZATION MODEL (route-layer, centralized here — do NOT rely on ad-hoc
// in-handler role checks for the guarantee):
//
//	Group                     Read (GET)        Write (POST/PATCH/DELETE)
//	------------------------  ----------------  --------------------------
//	/admin/auth/validate      any admin         —
//	/admin/users              super_admin       super_admin (+ audited)
//	/admin/audit-logs         any admin         —
//	/admin/target-mappings    any admin         ops_admin+ (+ audited)
//
// Roles (pkg/domain/admin): super_admin > ops_admin > readonly.

// registerAdminRoutes registers all platform admin endpoints.
// These are privileged operations for managing shared infrastructure.
// Note: authMiddleware and userSyncMiddleware are kept for interface compatibility
// but not used since admin routes use API Key authentication.
func registerAdminRoutes(
	router Router,
	h Handlers,
	_ Middleware, // authMiddleware - unused, admin uses API Key auth
	_ Middleware, // userSyncMiddleware - unused, admin uses API Key auth
) {
	// ==========================================================================
	// Admin API Key authenticated routes (for Admin UI)
	// ==========================================================================
	if h.AdminAuthMiddleware == nil {
		return
	}

	// Base chain: authenticate the admin API key. Every admin route requires
	// at least a valid admin key (any role).
	adminAPIKeyMiddlewares := []Middleware{h.AdminAuthMiddleware.Authenticate}

	// Super-admin group guard, composed onto the base chain. Built here so the
	// authorization guarantee lives at the route layer, not in handlers.
	// (append onto a fresh slice so the shared base chain is never aliased.)
	superAdminOnly := append(append([]Middleware{}, adminAPIKeyMiddlewares...),
		h.AdminAuthMiddleware.RequireRole(admin.AdminRoleSuperAdmin))

	// Auth validation — any authenticated admin may validate its own key.
	if h.AdminAuth != nil {
		router.Group("/api/v1/admin/auth", func(r Router) {
			r.GET("/validate", h.AdminAuth.Validate)
		}, adminAPIKeyMiddlewares...)
	}

	// Admin user management — the platform admin roster (emails, key prefixes,
	// last-used IPs). Restricted to super_admin for BOTH reads and writes:
	// only super_admin CanManageAdmins, and the roster itself is sensitive
	// (AUTHZ-8: List/Get were previously ungated, so any admin key — including
	// readonly — could enumerate all admins). Writes are additionally audited.
	if h.AdminUser != nil {
		router.Group("/api/v1/admin/users", func(r Router) {
			r.GET("/", h.AdminUser.List)
			r.GET("/{id}", h.AdminUser.Get)

			if h.AdminAuditMiddleware != nil {
				r.POST("/", h.AdminUser.Create, h.AdminAuditMiddleware.AuditAdminCreate())
				r.PATCH("/{id}", h.AdminUser.Update, h.AdminAuditMiddleware.AuditAdminUpdate())
				r.DELETE("/{id}", h.AdminUser.Delete, h.AdminAuditMiddleware.AuditAdminDelete())
				r.POST("/{id}/rotate-key", h.AdminUser.RotateKey, h.AdminAuditMiddleware.AuditAdminRotateKey())
			} else {
				r.POST("/", h.AdminUser.Create)
				r.PATCH("/{id}", h.AdminUser.Update)
				r.DELETE("/{id}", h.AdminUser.Delete)
				r.POST("/{id}/rotate-key", h.AdminUser.RotateKey)
			}
		}, superAdminOnly...)
	}

	// Audit log endpoints — read-only, viewable by ANY admin role (readonly
	// included: CanViewAuditLogs is true for all three roles).
	if h.AdminAudit != nil {
		router.Group("/api/v1/admin/audit-logs", func(r Router) {
			r.GET("/", h.AdminAudit.List)
			r.GET("/stats", h.AdminAudit.GetStats)
			r.GET("/{id}", h.AdminAudit.Get)
		}, adminAPIKeyMiddlewares...)
	}

	// Target mapping management (scanner target type -> asset type).
	// Reads: any admin. Writes: ops_admin+ (readonly rejected) — target
	// mappings are shared platform configuration, gated at the route layer to
	// match the domain's CanManage* semantics. Writes are rate-limited + audited.
	if h.AdminTargetMapping != nil {
		router.Group("/api/v1/admin/target-mappings", func(r Router) {
			// Read operations — any authenticated admin.
			r.GET("/stats", h.AdminTargetMapping.GetStats)
			r.GET("/", h.AdminTargetMapping.List)
			r.GET("/{id}", h.AdminTargetMapping.Get)

			// Write operations — ops_admin+, rate-limited, and (when wired) audited.
			var writeMiddlewares []Middleware
			writeMiddlewares = append(writeMiddlewares, h.AdminAuthMiddleware.RequireRole(admin.AdminRoleSuperAdmin, admin.AdminRoleOpsAdmin))
			if h.AdminMappingRateLimiter != nil {
				writeMiddlewares = append(writeMiddlewares, h.AdminMappingRateLimiter.WriteMiddleware())
			}

			if h.AdminAuditMiddleware != nil {
				r.POST("/", h.AdminTargetMapping.Create, append(cloneMW(writeMiddlewares), h.AdminAuditMiddleware.AuditTargetMappingCreate())...)
				r.PATCH("/{id}", h.AdminTargetMapping.Update, append(cloneMW(writeMiddlewares), h.AdminAuditMiddleware.AuditTargetMappingUpdate())...)
				r.DELETE("/{id}", h.AdminTargetMapping.Delete, append(cloneMW(writeMiddlewares), h.AdminAuditMiddleware.AuditTargetMappingDelete())...)
			} else {
				r.POST("/", h.AdminTargetMapping.Create, cloneMW(writeMiddlewares)...)
				r.PATCH("/{id}", h.AdminTargetMapping.Update, cloneMW(writeMiddlewares)...)
				r.DELETE("/{id}", h.AdminTargetMapping.Delete, cloneMW(writeMiddlewares)...)
			}
		}, adminAPIKeyMiddlewares...)
	}
}

// cloneMW returns a copy of the middleware slice so appending a per-route
// middleware (e.g. an audit factory) cannot mutate the shared write chain.
func cloneMW(mws []Middleware) []Middleware {
	return append([]Middleware{}, mws...)
}
