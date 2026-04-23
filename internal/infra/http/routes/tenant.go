package routes

import (
	"github.com/openctemio/api/internal/infra/http/handler"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/domain/tenant"
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

		// Get tenant by ID or slug
		r.GET("/{tenant}", h.Get)
	}, baseMiddlewares...)

	// Tenantless module-preset catalogue — used by the team-creation
	// form so the admin can pick a preset BEFORE the tenant exists.
	// No tenant-specific data is returned; the payload is the same
	// product-spec catalogue served by the tenant-scoped variant.
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

	router.Group("/api/v1/tenants/{tenant}", func(r Router) {
		// Read operations - any member (viewer+)
		r.GET("/members", h.ListMembers)
		r.GET("/members/stats", h.GetMemberStats)
		r.GET("/invitations", h.ListInvitations)
		r.GET("/settings", h.GetSettings)

		// Admin operations (admin+)
		r.PATCH("/", h.Update, middleware.RequireTeamAdmin())
		r.POST("/members", h.AddMember, middleware.RequireTeamAdmin())
		r.PATCH("/members/{userId}", h.UpdateMemberRole, middleware.RequireTeamAdmin())
		r.POST("/members/{userId}/suspend", h.SuspendMember, middleware.RequireTeamAdmin())
		r.POST("/members/{userId}/reactivate", h.ReactivateMember, middleware.RequireTeamAdmin())
		r.DELETE("/members/{userId}", h.RemoveMember, middleware.RequireTeamAdmin())
		r.POST("/invitations", h.CreateInvitation, middleware.RequireTeamAdmin())
		r.POST("/invitations/{invitationId}/resend", h.ResendInvitation, middleware.RequireTeamAdmin())
		r.DELETE("/invitations/{invitationId}", h.DeleteInvitation, middleware.RequireTeamAdmin())

		// Settings management (admin+)
		r.PATCH("/settings/general", h.UpdateGeneralSettings, middleware.RequireTeamAdmin())
		r.PATCH("/settings/branding", h.UpdateBrandingSettings, middleware.RequireTeamAdmin())
		r.PATCH("/settings/branch", h.UpdateBranchSettings, middleware.RequireTeamAdmin())

		// Pentest settings (admin+)
		r.GET("/settings/pentest", h.GetPentestSettings, middleware.RequireTeamAdmin())
		r.PATCH("/settings/pentest", h.UpdatePentestSettings, middleware.RequireTeamAdmin())

		// Asset identity settings (admin+) — RFC-001
		r.GET("/settings/asset-identity", h.GetAssetIdentitySettings, middleware.RequireTeamAdmin())
		r.PATCH("/settings/asset-identity", h.UpdateAssetIdentitySettings, middleware.RequireTeamAdmin())

		// Asset source priority settings (admin+) — RFC-003 Phase 1a
		r.GET("/settings/asset-source", h.GetAssetSourceSettings, middleware.RequireTeamAdmin())
		r.PUT("/settings/asset-source", h.UpdateAssetSourceSettings, middleware.RequireTeamAdmin())

		// Asset lifecycle settings (admin+) — stale detection + snooze.
		r.GET("/settings/asset-lifecycle", h.GetAssetLifecycleSettings, middleware.RequireTeamAdmin())
		r.PUT("/settings/asset-lifecycle", h.UpdateAssetLifecycleSettings, middleware.RequireTeamAdmin())
		r.POST("/settings/asset-lifecycle/dry-run", h.DryRunAssetLifecycle, middleware.RequireTeamAdmin())

		// Risk scoring settings (admin+)
		r.GET("/settings/risk-scoring", h.GetRiskScoringSettings, middleware.RequireTeamAdmin())
		r.PATCH("/settings/risk-scoring", h.UpdateRiskScoringSettings, middleware.RequireTeamAdmin())
		r.POST("/settings/risk-scoring/preview", h.PreviewRiskScoringChanges, middleware.RequireTeamAdmin())
		r.POST("/settings/risk-scoring/recalculate", h.RecalculateRiskScores, middleware.RequireTeamAdmin())
		r.GET("/settings/risk-scoring/presets", h.GetRiskScoringPresets, middleware.RequireTeamAdmin())

		// Module management (admin+)
		r.GET("/settings/modules", h.GetTenantModules, middleware.RequireTeamAdmin())
		r.PATCH("/settings/modules", h.UpdateTenantModules, middleware.RequireTeamAdmin())
		r.POST("/settings/modules/reset", h.ResetTenantModules, middleware.RequireTeamAdmin())
		// Platform-wide module dependency graph (static spec from
		// pkg/domain/module/dependency.go). UI uses this to render
		// dependency badges + "disabling X will also affect Y" dialogs.
		r.GET("/settings/modules/graph", h.GetModuleDependencyGraph, middleware.RequireTeamAdmin())
		// Dry-run validation of a toggle — UI calls this BEFORE the
		// PATCH commit so the admin can confirm cascading impact.
		r.POST("/settings/modules/validate", h.ValidateTenantModuleToggle, middleware.RequireTeamAdmin())
		// Module presets — curated bundles for common use cases
		// (VM, ASM, Pentest, SBOM, Compliance, CTEM Full, …).
		// List endpoint serves the static catalogue; preview is a
		// dry-run diff; apply writes the diff through the normal
		// UpdateTenantModules pipeline (validation + audit reuse).
		r.GET("/settings/modules/presets", h.ListModulePresets, middleware.RequireTeamAdmin())
		r.POST("/settings/modules/presets/{presetId}/preview", h.PreviewModulePreset, middleware.RequireTeamAdmin())
		r.POST("/settings/modules/presets/{presetId}/apply", h.ApplyModulePreset, middleware.RequireTeamAdmin())

		// Security & API settings (owner only - sensitive)
		r.PATCH("/settings/security", h.UpdateSecuritySettings, middleware.RequireTeamOwner())
		r.PATCH("/settings/api", h.UpdateAPISettings, middleware.RequireTeamOwner())

		// Owner-only operations
		r.DELETE("/", h.Delete, middleware.RequireTeamOwner())
	}, tenantMiddlewares...)

	// Invitation routes - mixed public and authenticated
	router.Group("/api/v1/invitations", func(r Router) {
		// Public: preview invitation without auth (for better UX)
		r.GET("/{token}/preview", h.GetInvitationPreview)

		// Public: decline invitation (token is authorization)
		r.POST("/{token}/decline", h.DeclineInvitation)

		// Public: accept invitation with refresh token (for users without tenant)
		// This is for users who were invited but don't have a tenant yet (only refresh token)
		if localAuth != nil {
			r.POST("/{token}/accept-with-refresh", localAuth.AcceptInvitationWithRefresh)
		}

		// Authenticated: full invitation details and accept
		r.GET("/{token}", ChainFunc(h.GetInvitation, baseMiddlewares...).ServeHTTP)
		r.POST("/{token}/accept", ChainFunc(h.AcceptInvitation, baseMiddlewares...).ServeHTTP)
	})
}
