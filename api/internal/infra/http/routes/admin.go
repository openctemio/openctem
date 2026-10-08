package routes

import (
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
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
//	/admin/overview           any admin         —
//	/admin/platform-users     any admin (view   ops_admin+, reason, rate-limited,
//	                          audited)          audited; platform admins refused
//	/admin/users              super_admin       super_admin (+ audited)
//	/admin/administrators     —                 super_admin (audited)
//	/admin/audit-logs         any admin         —
//	/admin/target-mappings    any admin         ops_admin+ (+ audited)
//	/admin/threat-intel       any admin         ops_admin+ (+ audited)
//	/admin/platform-idp       super_admin       super_admin (audited)
//	/admin/settings/plans     any admin         super_admin + fresh TOTP code
//	/admin/tenants/{id}/plan  any admin         ops_admin+ (plan, overrides; audited)
//	/admin/settings/signup    any admin         super_admin + fresh TOTP code
//	                                            (critical audit, admins emailed)
//	/admin/tenants/{id}/audit-chain
//	                          any admin         rebaseline: super_admin + fresh
//	                                            TOTP code (audited, both logs)
//	/admin/auth/idp*          public (sign-in)  public, rate-limited
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
		consoleRL := newAuthRateLimiter("console")
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
				r.POST("/password", h.AdminConsole.ChangePassword, consoleRL.PasswordMiddleware(), authed)
				// Platform identity provider sign-in (RFC-022 revision 4). Not a
				// credential-guessing surface (the IdP authenticates, the state is
				// single use), so it uses the token-exchange bucket (20/min) rather
				// than the 5/min login bucket: behind the UI proxy every
				// administrator shares one client IP, and one IdP sign-in is
				// start + callback + the TOTP step. The TOTP step (/mfa) stays on
				// the login bucket.
				idpRL := consoleRL.TokenExchangeMiddleware()
				r.GET("/idp", h.AdminConsole.IdPInfo)
				r.POST("/idp/start", h.AdminConsole.IdPStart, idpRL)
				r.POST("/idp/callback", h.AdminConsole.IdPCallback, idpRL)
			}
		})
	}

	// Build identity for the console's Help > About (any admin role).
	router.GET("/api/v1/admin/version", handler.Version, adminMiddlewares...)

	// The console overview's attention queue (any admin role): counts only,
	// no tenant content and no administrator emails.
	if h.AdminOverview != nil {
		router.GET("/api/v1/admin/overview", h.AdminOverview.Get, adminMiddlewares...)
	}

	// Plan defaults (Console > System > Plans): any admin reads; a super admin
	// changes them with a fresh authenticator code (checked in the handler,
	// audited, the other administrators told).
	if h.Plan != nil {
		requireSuperPlans := h.AdminAuthMiddleware.RequireRole(admin.AdminRoleSuperAdmin)
		router.Group("/api/v1/admin/settings/plans", func(r Router) {
			r.GET("/", h.Plan.GetDefaults)
			r.PUT("/", h.Plan.UpdateDefaults, requireSuperPlans)
		}, adminMiddlewares...)
	}

	// The sign-up policy (Console > System > Sign-up): who may create an
	// organization. Any admin reads; a super admin changes it with a fresh
	// authenticator code (checked in the handler, which also writes the
	// critical audit row and tells the other administrators).
	// One group per prefix (chi cannot mount the same prefix twice): the
	// super-admin guard is on the PUT route.
	if h.AdminSignup != nil {
		requireSuper := h.AdminAuthMiddleware.RequireRole(admin.AdminRoleSuperAdmin)
		router.Group("/api/v1/admin/settings/signup", func(r Router) {
			r.GET("/", h.AdminSignup.Get)
			r.PUT("/", h.AdminSignup.Update, requireSuper)
		}, adminMiddlewares...)
	}

	// Provisioning a platform administrator (links or creates the users-table
	// account they sign in with). Super admin only; the service writes the
	// audit row (console.admin_provisioned).
	if h.AdminConsole != nil {
		router.Group("/api/v1/admin/administrators", func(r Router) {
			r.POST("/", h.AdminConsole.Provision)
		}, superAdminOnly...)

		// The administrators' identity provider (System -> Admin sign-in). The
		// service writes high-severity audit rows for every change.
		router.Group("/api/v1/admin/platform-idp", func(r Router) {
			r.GET("/", h.AdminConsole.GetPlatformIdP)
			r.PUT("/", h.AdminConsole.PutPlatformIdP)
			r.DELETE("/", h.AdminConsole.DeletePlatformIdP)
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

			// Organization users: list, and bootstrap the FIRST owner of an
			// organization that has none (RFC-022 rev. 5). The platform
			// administrator never adds users to an organization that has an
			// owner (409); the owner and its administrators do that.
			r.GET("/{tenantId}/users", h.AdminOrganization.ListUsers, read...)
			r.POST("/{tenantId}/users", h.AdminOrganization.CreateUser,
				with([]Middleware{opsWrite, scope}, audit("organization.user_create"))...)

			r.GET("/{tenantId}/sso/enforcement", h.AdminOrganization.GetSSOEnforcement)
			r.PUT("/{tenantId}/sso/enforcement", h.AdminOrganization.SetSSOEnforcement,
				with([]Middleware{superWrite}, audit("organization.sso_enforcement"))...)

			if h.SAML != nil {
				r.GET("/{tenantId}/sso/saml", h.SAML.GetConfig, read...)
				r.PUT("/{tenantId}/sso/saml", h.SAML.SetConfig, write("organization.saml_update")...)
				r.DELETE("/{tenantId}/sso/saml", h.SAML.DeleteConfig, write("organization.saml_delete")...)
			}
			// SAML and identity-provider creates/updates from here wait for an
			// owner of the organization (unless it has no owner yet); the
			// admin sees what is pending.
			if h.SSOChange != nil {
				r.GET("/{tenantId}/sso/changes", h.SSOChange.AdminList, read...)
			}
			if h.SSO != nil {
				r.GET("/{tenantId}/sso/identity-providers", h.SSO.ListProviders, read...)
				r.POST("/{tenantId}/sso/identity-providers", h.SSO.CreateProvider, write("organization.idp_create")...)
				r.GET("/{tenantId}/sso/identity-providers/{id}", h.SSO.GetProvider, read...)
				r.PUT("/{tenantId}/sso/identity-providers/{id}", h.SSO.UpdateProvider, write("organization.idp_update")...)
				r.DELETE("/{tenantId}/sso/identity-providers/{id}", h.SSO.DeleteProvider, write("organization.idp_delete")...)
			}
			// The organization's audit hash-chain: classify (any admin) and
			// rebaseline (super_admin). The rebaseline handler also demands a
			// fresh authenticator code and writes its own high-severity admin
			// audit row (with the rebaseline id and the outcome), so it does not
			// take the generic audit middleware.
			if h.AdminAuditChain != nil {
				r.GET("/{tenantId}/audit-chain", h.AdminAuditChain.Classify, read...)
				r.POST("/{tenantId}/audit-chain/rebaseline", h.AdminAuditChain.Rebaseline, superWrite, scope)
			}

			// Plan and limits of one organization: any admin reads (with
			// the over-limit flag); ops_admin+ changes the plan or sets a
			// per-organization limit (audited by the service).
			// Idle lifecycle of a Free organization: any admin reads;
			// ops_admin+ exempts it (audited by the service).
			if h.IdleWorkspace != nil {
				r.GET("/{tenantId}/idle", h.IdleWorkspace.Get, read...)
				r.PUT("/{tenantId}/idle/exemption", h.IdleWorkspace.SetExemption, with([]Middleware{opsWrite, scope})...)
			}

			if h.Plan != nil {
				r.GET("/{tenantId}/plan", h.Plan.GetTenantPlan, read...)
				r.PUT("/{tenantId}/plan", h.Plan.SetTenantPlan, with([]Middleware{opsWrite, scope})...)
				r.PUT("/{tenantId}/plan/overrides/{key}", h.Plan.SetOverride, with([]Middleware{opsWrite, scope})...)
				r.DELETE("/{tenantId}/plan/overrides/{key}", h.Plan.DeleteOverride, with([]Middleware{opsWrite, scope})...)
			}

			if h.VerifiedDomain != nil {
				r.GET("/{tenantId}/sso/verified-domains", h.VerifiedDomain.List, read...)
				r.POST("/{tenantId}/sso/verified-domains", h.VerifiedDomain.AddDomain, write("organization.domain_add")...)
				r.POST("/{tenantId}/sso/verified-domains/{id}/verify", h.VerifiedDomain.Verify, write("organization.domain_verify")...)
				r.DELETE("/{tenantId}/sso/verified-domains/{id}", h.VerifiedDomain.Delete, write("organization.domain_delete")...)
				r.PATCH("/{tenantId}/sso/verified-domains/{id}", h.VerifiedDomain.UpdateJIT, write("organization.domain_jit")...)
			}
		}, adminMiddlewares...)
	}

	// Console > Users (RFC-022 revision 14): find an account across
	// organizations (any admin; viewing one is audited) and run a support
	// action on it (ops_admin+, reason required, rate-limited, audited).
	// Account-level facts only, never organization data.
	if h.AdminPlatformUser != nil {
		opsSupport := []Middleware{h.AdminAuthMiddleware.RequireRole(admin.AdminRoleSuperAdmin, admin.AdminRoleOpsAdmin)}
		if h.AdminSupportRateLimiter != nil {
			opsSupport = append(opsSupport, h.AdminSupportRateLimiter.WriteMiddleware())
		}
		audited := func(action string, base []Middleware) []Middleware {
			out := cloneMW(base)
			if h.AdminAuditMiddleware != nil {
				out = append(out, h.AdminAuditMiddleware.AuditLog(action, "user", "userId"))
			}
			return out
		}
		router.Group("/api/v1/admin/platform-users", func(r Router) {
			r.GET("/", h.AdminPlatformUser.Search)
			r.GET("/{userId}", h.AdminPlatformUser.Get, audited("platform_user.view", nil)...)
			r.POST("/{userId}/revoke-sessions", h.AdminPlatformUser.RevokeSessions, audited("platform_user.revoke_sessions", opsSupport)...)
			r.POST("/{userId}/unlock", h.AdminPlatformUser.Unlock, audited("platform_user.unlock", opsSupport)...)
			r.POST("/{userId}/password-reset", h.AdminPlatformUser.SendPasswordReset, audited("platform_user.password_reset", opsSupport)...)
			r.POST("/{userId}/resend-verification", h.AdminPlatformUser.ResendVerification, audited("platform_user.resend_verification", opsSupport)...)
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
					r.POST("/{id}/break-glass-test", h.AdminConsole.ConfirmBreakGlassTest)
					r.DELETE("/{id}/idp-binding", h.AdminConsole.UnbindIdP)
				}
			} else {
				r.PATCH("/{id}", h.AdminUser.Update)
				r.DELETE("/{id}", h.AdminUser.Delete)
				if h.AdminConsole != nil {
					r.POST("/{id}/reset-credentials", h.AdminConsole.ResetCredentials)
					r.POST("/{id}/break-glass-test", h.AdminConsole.ConfirmBreakGlassTest)
					r.DELETE("/{id}/idp-binding", h.AdminConsole.UnbindIdP)
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

	// Threat-intelligence feeds (EPSS, CISA KEV): platform-wide, so only the
	// platform administrator runs or toggles their sync. Reads: any admin.
	// Writes: ops_admin+, audited.
	if h.ThreatIntel != nil {
		router.Group("/api/v1/admin/threat-intel", func(r Router) {
			r.GET("/sync", h.ThreatIntel.GetSyncStatuses)
			feedWrite := []Middleware{h.AdminAuthMiddleware.RequireRole(admin.AdminRoleSuperAdmin, admin.AdminRoleOpsAdmin)}
			syncMW, toggleMW := cloneMW(feedWrite), cloneMW(feedWrite)
			if h.AdminAuditMiddleware != nil {
				syncMW = append(syncMW, h.AdminAuditMiddleware.AuditLog("threat_intel.sync", "threat_intel_feed", ""))
				toggleMW = append(toggleMW, h.AdminAuditMiddleware.AuditLog("threat_intel.sync_toggle", "threat_intel_feed", ""))
			}
			r.POST("/sync", h.ThreatIntel.TriggerSync, syncMW...)
			r.PATCH("/sync/{source}", h.ThreatIntel.SetSyncEnabled, toggleMW...)
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
			r.GET("/types", h.AdminTargetMapping.Types)
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
