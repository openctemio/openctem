package routes

import (
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/domain/admin"
)

// =============================================================================
// Platform Admin Routes
// =============================================================================
//
// These routes are for OpenCTEM platform administrators only.
// They manage shared infrastructure that serves all tenants.
//
// Every admin route requires a verified console session (RFC-022): the
// administrator signed in on /login and passed the TOTP step. There are no
// admin API keys. This is separate from tenant admin routes (RequireTeamAdmin).
//
// AUTHORIZATION MODEL (route-layer, centralized here — do NOT rely on ad-hoc
// in-handler role checks for the guarantee):
//
//	Group                     Read (GET)        Write (POST/PATCH/DELETE)
//	------------------------  ----------------  --------------------------
//	/admin/auth/validate      any admin         —
//	/admin/users              super_admin       super_admin (+ audited)
//	/admin/administrators     —                 super_admin (audited)
//	/admin/audit-logs         any admin         —
//	/admin/target-mappings    any admin         ops_admin+ (+ audited)
//
// Roles (pkg/domain/admin): super_admin > ops_admin > readonly.

// registerAdminRoutes registers all platform admin endpoints.
// These are privileged operations for managing shared infrastructure.
// Note: authMiddleware and userSyncMiddleware are kept for interface compatibility
// but not used: admin routes authenticate the console session.
func registerAdminRoutes(
	router Router,
	h Handlers,
	_ Middleware, // authMiddleware - unused, admin uses the console session
	_ Middleware, // userSyncMiddleware - unused, admin uses the console session
) {
	// ==========================================================================
	// Console-session authenticated routes
	// ==========================================================================
	if h.AdminAuthMiddleware == nil {
		return
	}

	// Base chain: a verified console session (any role).
	adminMiddlewares := []Middleware{h.AdminAuthMiddleware.Authenticate}

	// Super-admin group guard, composed onto the base chain. Built here so the
	// authorization guarantee lives at the route layer, not in handlers.
	// (append onto a fresh slice so the shared base chain is never aliased.)
	superAdminOnly := append(append([]Middleware{}, adminMiddlewares...),
		h.AdminAuthMiddleware.RequireRole(admin.AdminRoleSuperAdmin))

	// Auth: one group (chi cannot mount the same prefix twice), so the guard is
	// per route. /validate needs a verified console session. The console steps (RFC-022) run after the normal /login: the
	// refresh-token cookie names the user, /session opens a pending console
	// session and /mfa completes it. They share the tenant login's rate limits.
	if h.AdminAuth != nil || h.AdminConsole != nil {
		consoleRL := middleware.NewAuthRateLimiter(middleware.DefaultAuthRateLimitConfig(), nil)
		loginRL := consoleRL.LoginMiddleware()
		authed := h.AdminAuthMiddleware.Authenticate

		router.Group("/api/v1/admin/auth", func(r Router) {
			if h.AdminAuth != nil {
				r.GET("/validate", h.AdminAuth.Validate, authed)
			}
			if h.AdminConsole != nil {
				r.POST("/session", h.AdminConsole.StartSession, loginRL)
				r.POST("/mfa", h.AdminConsole.VerifyMFA, loginRL)
				r.POST("/logout", h.AdminConsole.Logout)
			}
		})
	}

	// Provisioning a platform administrator (links or creates the users-table
	// account they sign in with). Super admin only; the service writes the
	// audit row (console.admin_provisioned).
	if h.AdminConsole != nil {
		router.Group("/api/v1/admin/administrators", func(r Router) {
			r.POST("/", h.AdminConsole.Provision)
		}, superAdminOnly...)
	}

	// Organizations (RFC-022 Phase 2): the platform admin's cross-tenant view,
	// organization creation, and per-organization SSO. Reads are open to any
	// admin; creating an organization needs ops_admin+; SSO changes (the
	// organization's login trust) need super_admin. SAML, identity-provider and
	// verified-domain setup reuse the tenant handlers under AdminTenantScope,
	// which sets the path organization as the request tenant.
	if h.AdminOrganization != nil {
		opsWrite := h.AdminAuthMiddleware.RequireRole(admin.AdminRoleSuperAdmin, admin.AdminRoleOpsAdmin)
		superWrite := h.AdminAuthMiddleware.RequireRole(admin.AdminRoleSuperAdmin)
		scope := middleware.AdminTenantScope(h.AdminOrganization.TenantExists)
		audit := func(action string) []Middleware {
			if h.AdminAuditMiddleware == nil {
				return nil
			}
			return []Middleware{h.AdminAuditMiddleware.AuditLog(action, "tenant", middleware.AdminTenantParam)}
		}
		with := func(mws ...[]Middleware) []Middleware {
			out := []Middleware{}
			for _, m := range mws {
				out = append(out, m...)
			}
			return out
		}
		read := []Middleware{scope}
		write := func(action string) []Middleware { return with([]Middleware{superWrite, scope}, audit(action)) }

		router.Group("/api/v1/admin/tenants", func(r Router) {
			r.GET("/", h.AdminOrganization.List)
			r.POST("/", h.AdminOrganization.Create, with([]Middleware{opsWrite}, audit("organization.create"))...)
			r.GET("/{tenantId}", h.AdminOrganization.Get)

			r.GET("/{tenantId}/sso/enforcement", h.AdminOrganization.GetSSOEnforcement)
			r.PUT("/{tenantId}/sso/enforcement", h.AdminOrganization.SetSSOEnforcement,
				with([]Middleware{superWrite}, audit("organization.sso_enforcement"))...)

			if h.SAML != nil {
				r.GET("/{tenantId}/sso/saml", h.SAML.GetConfig, read...)
				r.PUT("/{tenantId}/sso/saml", h.SAML.SetConfig, write("organization.saml_update")...)
				r.DELETE("/{tenantId}/sso/saml", h.SAML.DeleteConfig, write("organization.saml_delete")...)
			}
			if h.SSO != nil {
				r.GET("/{tenantId}/sso/identity-providers", h.SSO.ListProviders, read...)
				r.POST("/{tenantId}/sso/identity-providers", h.SSO.CreateProvider, write("organization.idp_create")...)
				r.GET("/{tenantId}/sso/identity-providers/{id}", h.SSO.GetProvider, read...)
				r.PUT("/{tenantId}/sso/identity-providers/{id}", h.SSO.UpdateProvider, write("organization.idp_update")...)
				r.DELETE("/{tenantId}/sso/identity-providers/{id}", h.SSO.DeleteProvider, write("organization.idp_delete")...)
			}
			if h.VerifiedDomain != nil {
				r.GET("/{tenantId}/sso/verified-domains", h.VerifiedDomain.List, read...)
				r.POST("/{tenantId}/sso/verified-domains", h.VerifiedDomain.AddDomain, write("organization.domain_add")...)
				r.POST("/{tenantId}/sso/verified-domains/{id}/verify", h.VerifiedDomain.Verify, write("organization.domain_verify")...)
				r.DELETE("/{tenantId}/sso/verified-domains/{id}", h.VerifiedDomain.Delete, write("organization.domain_delete")...)
			}
		}, adminMiddlewares...)
	}

	// Admin user management — the platform admin roster (emails, last-used
	// IPs). New administrators are added through /admin/administrators. Restricted to super_admin for BOTH reads and writes:
	// only super_admin CanManageAdmins, and the roster itself is sensitive
	// (AUTHZ-8: List/Get were previously ungated, so any admin key — including
	// readonly — could enumerate all admins). Writes are additionally audited.
	if h.AdminUser != nil {
		router.Group("/api/v1/admin/users", func(r Router) {
			r.GET("/", h.AdminUser.List)
			r.GET("/{id}", h.AdminUser.Get)

			if h.AdminAuditMiddleware != nil {
				r.PATCH("/{id}", h.AdminUser.Update, h.AdminAuditMiddleware.AuditAdminUpdate())
				r.DELETE("/{id}", h.AdminUser.Delete, h.AdminAuditMiddleware.AuditAdminDelete())
				if h.AdminConsole != nil {
					r.POST("/{id}/reset-credentials", h.AdminConsole.ResetCredentials)
				}
			} else {
				r.PATCH("/{id}", h.AdminUser.Update)
				r.DELETE("/{id}", h.AdminUser.Delete)
				if h.AdminConsole != nil {
					r.POST("/{id}/reset-credentials", h.AdminConsole.ResetCredentials)
				}
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
		}, adminMiddlewares...)
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
		}, adminMiddlewares...)
	}
}

// cloneMW returns a copy of the middleware slice so appending a per-route
// middleware (e.g. an audit factory) cannot mutate the shared write chain.
func cloneMW(mws []Middleware) []Middleware {
	return append([]Middleware{}, mws...)
}
