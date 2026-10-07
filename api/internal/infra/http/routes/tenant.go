package routes

import (
	"net/http"
	"time"

	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// registerTenantRoutes registers tenant management endpoints.
// API uses "tenant", UI displays "Team".
//
// `tenantRepo` is used for the URL-path tenant lookup (TenantContext
// resolves slug → id) and for invitation handlers. `membershipReader`
// is the (possibly cached) reader the RequireMembership middleware
// uses for the per-request status check — pass the same value as
// tenantRepo if no cache is available.
func registerTenantRoutes(
	router Router,
	h *handler.TenantHandler,
	authMiddleware, userSyncMiddleware Middleware,
	tenantRepo tenant.Repository,
	membershipReader middleware.MembershipReader,
	localAuth *handler.LocalAuthHandler,
	ssoChanges *handler.SSOChangeHandler,
) {
	if membershipReader == nil {
		membershipReader = tenantRepo
	}

	// Build base middleware chain
	baseMiddlewares := []Middleware{authMiddleware}
	if userSyncMiddleware != nil {
		baseMiddlewares = append(baseMiddlewares, userSyncMiddleware)
	}

	// Tenant routes (authenticated user context)
	router.Group("/api/v1/tenants", func(r Router) {
		// List user's tenants
		r.GET("/", h.List)

		// Create a new tenant
		r.POST("/", h.Create)

		// GET /api/v1/tenants/{tenant} is registered in the
		// /api/v1/tenants/{tenant} group below: that group mounts a
		// sub-router on the exact path, so a route for it here is never
		// reached (it answered 405).
	}, baseMiddlewares...)

	// Tenantless module-preset catalog — used by the team-creation
	// form so the admin can pick a preset BEFORE the tenant exists.
	// No tenant-specific data is returned; the payload is the same
	// product-spec catalog served by the tenant-scoped variant.
	router.Group("/api/v1/module-presets", func(r Router) {
		r.GET("/", h.ListModulePresets)
	}, baseMiddlewares...)

	// Tenant-scoped routes - consolidated into single group to avoid chi mount conflicts
	// Base middleware applies to all: auth + userSync + tenantContext + membership
	tenantMiddlewares := make([]Middleware, 0, len(baseMiddlewares)+2)
	tenantMiddlewares = append(tenantMiddlewares, baseMiddlewares...)
	tenantMiddlewares = append(tenantMiddlewares,
		middleware.TenantContext(tenantRepo),
		middleware.RequireMembership(membershipReader))
	// The organization's IP allowlist, for the organization in the URL.
	if ipAllowlistMiddleware != nil {
		tenantMiddlewares = append(tenantMiddlewares, ipAllowlistMiddleware)
	}
	// Per-request SSO enforcement for the organization in the URL, with the
	// caller's role there (RequireMembership above puts it in the context).
	// The token-tenant chains run the same gate through buildBaseMiddlewares;
	// this chain does not use that builder, so it adds the gate here.
	if ssoEnforcementMiddleware != nil {
		tenantMiddlewares = append(tenantMiddlewares, ssoEnforcementMiddleware)
	}
	// The per-user read budget of the token-tenant chains.
	if readRateLimitMiddleware != nil {
		tenantMiddlewares = append(tenantMiddlewares, readRateLimitMiddleware)
	}

	router.Group("/api/v1/tenants/{tenant}", func(r Router) {
		// Read operations - any member (viewer+). The group chain scopes
		// the tenant to the caller's membership (and IP allowlist), so a
		// non-member cannot read another tenant's record.
		r.GET("/", h.Get, tenantPerm(permission.TeamRead))
		r.GET("/members", h.ListMembers, tenantPerm(permission.MembersRead))
		r.GET("/members/stats", h.GetMemberStats, tenantPerm(permission.MembersRead))
		r.GET("/invitations", h.ListInvitations, tenantPerm(permission.MembersRead))
		r.GET("/settings", h.GetSettings, tenantPerm(permission.SettingsRead))

		// Admin operations (admin+)
		r.PATCH("/", h.Update, middleware.RequireTeamAdmin(), tenantPerm(permission.TeamUpdate))
		r.POST("/members", h.AddMember, middleware.RequireTeamAdmin(), tenantPerm(permission.MembersWrite))
		r.PATCH("/members/{userId}", h.UpdateMemberRole, middleware.RequireTeamAdmin(), tenantPerm(permission.MembersWrite))
		r.POST("/members/{userId}/suspend", h.SuspendMember, middleware.RequireTeamAdmin(), tenantPerm(permission.MembersWrite))
		r.POST("/members/{userId}/reactivate", h.ReactivateMember, middleware.RequireTeamAdmin(), tenantPerm(permission.MembersWrite))
		r.POST("/invitations", h.CreateInvitation, middleware.RequireTeamAdmin(), tenantPerm(permission.MembersInvite))
		// Administrator-created accounts: create a user with roles and a
		// one-time set-password link; reissue the link while the account is unused.
		r.POST("/users", h.CreateUser, middleware.RequireTeamAdmin(), tenantPerm(permission.MembersWrite))
		r.POST("/users/{userId}/setup-link", h.ReissueSetupLink, middleware.RequireTeamAdmin(), tenantPerm(permission.MembersWrite))
		r.POST("/invitations/{invitationId}/resend", h.ResendInvitation, middleware.RequireTeamAdmin(), tenantPerm(permission.MembersInvite))
		r.DELETE("/invitations/{invitationId}", h.DeleteInvitation, middleware.RequireTeamAdmin(), tenantPerm(permission.MembersInvite))

		// Settings management (admin+)
		r.PATCH("/settings/general", h.UpdateGeneralSettings, middleware.RequireTeamAdmin(), tenantPerm(permission.SettingsWrite))
		r.PATCH("/settings/branding", h.UpdateBrandingSettings, middleware.RequireTeamAdmin(), tenantPerm(permission.SettingsWrite))
		r.PATCH("/settings/branch", h.UpdateBranchSettings, middleware.RequireTeamAdmin(), tenantPerm(permission.SettingsWrite))

		// Pentest settings (admin+)
		r.GET("/settings/pentest", h.GetPentestSettings, middleware.RequireTeamAdmin(), tenantPerm(permission.SettingsRead))
		r.PATCH("/settings/pentest", h.UpdatePentestSettings, middleware.RequireTeamAdmin(), tenantPerm(permission.SettingsWrite))

		// Asset identity settings (admin+) — RFC-001
		r.GET("/settings/asset-identity", h.GetAssetIdentitySettings, middleware.RequireTeamAdmin(), tenantPerm(permission.SettingsRead))
		r.PATCH("/settings/asset-identity", h.UpdateAssetIdentitySettings, middleware.RequireTeamAdmin(), tenantPerm(permission.SettingsWrite))

		// Asset source priority settings (admin+) — RFC-003 Phase 1a

		// Asset lifecycle settings (admin+) — stale detection + snooze.
		r.GET("/settings/asset-lifecycle", h.GetAssetLifecycleSettings, middleware.RequireTeamAdmin(), tenantPerm(permission.SettingsRead))
		r.PUT("/settings/asset-lifecycle", h.UpdateAssetLifecycleSettings, middleware.RequireTeamAdmin(), tenantPerm(permission.SettingsWrite))
		r.POST("/settings/asset-lifecycle/dry-run", h.DryRunAssetLifecycle, middleware.RequireTeamAdmin(), tenantPerm(permission.SettingsWrite))

		// Risk scoring settings (admin+)
		r.GET("/settings/risk-scoring", h.GetRiskScoringSettings, middleware.RequireTeamAdmin(), tenantPerm(permission.SettingsRead))
		r.PATCH("/settings/risk-scoring", h.UpdateRiskScoringSettings, middleware.RequireTeamAdmin(), tenantPerm(permission.SettingsWrite))
		r.POST("/settings/risk-scoring/preview", h.PreviewRiskScoringChanges, middleware.RequireTeamAdmin(), tenantPerm(permission.SettingsWrite))
		r.POST("/settings/risk-scoring/recalculate", h.RecalculateRiskScores, middleware.RequireTeamAdmin(), tenantPerm(permission.SettingsWrite))
		r.GET("/settings/risk-scoring/presets", h.GetRiskScoringPresets, middleware.RequireTeamAdmin(), tenantPerm(permission.SettingsRead))

		// Module management (admin+)
		r.GET("/settings/modules", h.GetTenantModules, middleware.RequireTeamAdmin(), tenantPerm(permission.SettingsRead))
		r.PATCH("/settings/modules", h.UpdateTenantModules, middleware.RequireTeamAdmin(), tenantPerm(permission.SettingsWrite))
		r.POST("/settings/modules/reset", h.ResetTenantModules, middleware.RequireTeamAdmin(), tenantPerm(permission.SettingsWrite))
		// Platform-wide module dependency graph (static spec from
		// pkg/domain/module/dependency.go). UI uses this to render
		// dependency badges + "disabling X will also affect Y" dialogs.
		r.GET("/settings/modules/graph", h.GetModuleDependencyGraph, middleware.RequireTeamAdmin(), tenantPerm(permission.SettingsRead))
		// Dry-run validation of a toggle — UI calls this BEFORE the
		// PATCH commit so the admin can confirm cascading impact.
		r.POST("/settings/modules/validate", h.ValidateTenantModuleToggle, middleware.RequireTeamAdmin(), tenantPerm(permission.SettingsWrite))
		// Module presets — curated bundles for common use cases
		// (VM, ASM, Pentest, SBOM, Compliance, CTEM Full, …).
		// List endpoint serves the static catalog; preview is a
		// dry-run diff; apply writes the diff through the normal
		// UpdateTenantModules pipeline (validation + audit reuse).
		r.GET("/settings/modules/presets", h.ListModulePresets, middleware.RequireTeamAdmin(), tenantPerm(permission.SettingsRead))
		r.POST("/settings/modules/presets/{presetId}/preview", h.PreviewModulePreset, middleware.RequireTeamAdmin(), tenantPerm(permission.SettingsWrite))
		r.POST("/settings/modules/presets/{presetId}/apply", h.ApplyModulePreset, middleware.RequireTeamAdmin(), tenantPerm(permission.SettingsWrite))

		// Product-bundle subscription: persistent, live-resolved packaging.
		// GET returns the current subscription + catalog; POST replaces it.
		r.GET("/settings/modules/bundles", h.GetModuleBundles, middleware.RequireTeamAdmin(), tenantPerm(permission.SettingsRead))
		r.POST("/settings/modules/bundles", h.SubscribeModuleBundles, middleware.RequireTeamAdmin(), tenantPerm(permission.SettingsWrite))

		// Security settings (owner only - sensitive)
		r.PATCH("/settings/security", h.UpdateSecuritySettings, middleware.RequireTeamOwner(), tenantPerm(permission.SettingsWrite), requireStepUp())

		// SSO changes a platform administrator proposed for this organization
		// (RFC-022). Owner only: approving one installs who can sign in.
		// The service re-checks ownership in the database.
		if ssoChanges != nil {
			r.GET("/settings/sso/changes", ssoChanges.OwnerList, middleware.RequireTeamOwner())
			r.POST("/settings/sso/changes/{changeId}/approve", ssoChanges.Approve, middleware.RequireTeamOwner(), requireStepUp())
			r.POST("/settings/sso/changes/{changeId}/reject", ssoChanges.Reject, middleware.RequireTeamOwner())
		}

		// Owner-only operations
		r.DELETE("/", h.Delete, middleware.RequireTeamOwner(), tenantPerm(permission.TeamDelete), requireStepUp())
	}, tenantMiddlewares...)

	// Invitation routes - mixed public and authenticated. The token is the
	// credential, so every route is rate limited per IP, in the shared auth
	// store (its own "invitation" budget, 20/min: the UI makes a lookup +
	// accept per invitation, and users behind one NAT share an IP).
	//
	// The token travels in the request body (RFC-041). The /{token}/...
	// routes are deprecated aliases with the same handlers and chains;
	// Deprecated() runs first so that even their errors say so.
	invitationRL := newAuthRateLimiter("invitation").TokenExchangeMiddleware()
	authed := func(mw ...Middleware) []Middleware {
		return append(append(append([]Middleware{}, mw...), baseMiddlewares...), invitationRL)
	}
	router.Group("/api/v1/invitations", func(r Router) {
		// Public: what the token grants, before sign-in.
		r.POST("/lookup", h.LookupInvitation, invitationRL)
		// Public: decline (holding the token is the authorization).
		r.POST("/decline", h.DeclineInvitationToken, invitationRL)
		// Public: accept with a refresh token, for an invited user who has
		// no organization yet (so only a refresh token).
		if localAuth != nil {
			r.POST("/accept-with-refresh", localAuth.AcceptInvitationWithRefreshBody, invitationRL)
		}
		// Authenticated: accept as the signed-in, invited email.
		r.POST("/accept", ChainFunc(h.AcceptInvitationToken, authed()...).ServeHTTP)

		// Deprecated aliases: the token in the path.
		r.GET("/{token}/preview", h.GetInvitationPreview, invitationDeprecated("preview", "/api/v1/invitations/lookup"), invitationRL)
		r.POST("/{token}/decline", h.DeclineInvitation, invitationDeprecated("decline", "/api/v1/invitations/decline"), invitationRL)
		if localAuth != nil {
			r.POST("/{token}/accept-with-refresh", localAuth.AcceptInvitationWithRefresh,
				invitationDeprecated("accept_with_refresh", "/api/v1/invitations/accept-with-refresh"), invitationRL)
		}
		r.GET("/{token}", ChainFunc(h.GetInvitation, authed(invitationDeprecated("get", "/api/v1/invitations/lookup"))...).ServeHTTP)
		r.POST("/{token}/accept", ChainFunc(h.AcceptInvitation, authed(invitationDeprecated("accept", "/api/v1/invitations/accept"))...).ServeHTTP)
	})
}

// The /api/v1/invitations/{token}/... aliases are deprecated now and removed
// on the RFC-041 D10 date for web-only aliases (emailed links point at the
// web app, never at these).
var (
	invitationPathDeprecatedAt = time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)
	invitationPathSunsetAt     = time.Date(2027, 1, 15, 0, 0, 0, 0, time.UTC)
)

// invitationDeprecated marks one /api/v1/invitations/{token}/... alias. The
// metric label is a fixed name, never the request path (which holds the token).
func invitationDeprecated(name, successor string) Middleware {
	return middleware.Deprecated(middleware.Deprecation{
		Plane:        "auth",
		Route:        "invitations_token_path_" + name,
		Successor:    successor,
		DeprecatedAt: invitationPathDeprecatedAt,
		SunsetAt:     invitationPathSunsetAt,
	})
}

// tenantPerm gates a /api/v1/tenants/{tenant}/... route on a permission held
// in the path tenant (RequireTenantPermission). It runs after the group's
// TenantContext and RequireMembership.
//
// The checker is read per request, not at registration, because Register sets
// it after the route table may already be built.
func tenantPerm(p permission.Permission) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			middleware.RequireTenantPermission(tenantPermissionChecker, p.String())(next).ServeHTTP(w, r)
		})
	}
}

// registerOrganizationMemberRoutes wires member administration under the
// token singleton /api/v1/organization: the tenant comes from the credential,
// never from the path (docs/architecture/api-conventions.md §2).
//
// DELETE .../members/{member_id}/mfa resets a member's second factor. The
// route admits owners and administrators; the service re-checks the caller's
// live membership and adds the peer-administrator, self and
// other-organization rules.
//
// The member lifecycle (RFC-050): GET .../access-report lists what the member
// holds and owns, POST .../offboard strips access with mandatory reassignment
// and keeps a tombstone, POST .../erase (owner only) anonymises an offboarded
// person. The service loads the membership within the caller's tenant (404
// otherwise) and applies the peer-administrator rule.
func registerOrganizationMemberRoutes(router Router, localAuth *handler.LocalAuthHandler, tenantH *handler.TenantHandler, authMiddleware, userSyncMiddleware Middleware) {
	if localAuth == nil && tenantH == nil {
		return
	}
	router.Group("/api/v1/organization/members/{member_id}", func(r Router) {
		if localAuth != nil {
			r.DELETE("/mfa", localAuth.ResetMemberMFA, middleware.RequireAdmin(), requireStepUp())
		}
		if tenantH != nil {
			r.GET("/access-report", tenantH.GetMemberAccessReport, middleware.RequireAdmin(), middleware.Require(permission.MembersRead))
			r.POST("/offboard", tenantH.OffboardMember, middleware.RequireAdmin(), middleware.Require(permission.MembersWrite), requireStepUp())
			r.POST("/erase", tenantH.EraseMemberPersonalData, middleware.RequireOwner(), requireStepUp())
		}
	}, buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)...)
}
