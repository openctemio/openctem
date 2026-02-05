package routes

import (
	"github.com/openctemio/api/internal/infra/http/handler"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/domain/tenant"
)

// registerTenantRoutes registers tenant management endpoints.
// API uses "tenant", UI displays "Team".
func registerTenantRoutes(
	router Router,
	h *handler.TenantHandler,
	authMiddleware, userSyncMiddleware Middleware,
	tenantRepo tenant.Repository,
	localAuth *handler.LocalAuthHandler,
) {
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

	// Tenant-scoped routes - consolidated into single group to avoid chi mount conflicts
	// Base middleware applies to all: auth + userSync + tenantContext + membership
	tenantMiddlewares := make([]Middleware, 0, len(baseMiddlewares)+2)
	tenantMiddlewares = append(tenantMiddlewares, baseMiddlewares...)
	tenantMiddlewares = append(tenantMiddlewares,
		middleware.TenantContext(tenantRepo),
		middleware.RequireMembership(tenantRepo))

	router.Group("/api/v1/tenants/{tenant}", func(r Router) {
		// Read operations - any member (viewer+)
		r.GET("/members", h.ListMembers)
		r.GET("/members/stats", h.GetMemberStats)
		r.GET("/invitations", h.ListInvitations)
		r.GET("/settings", h.GetSettings)

		// Admin operations (admin+)
		r.PATCH("/", h.Update, middleware.RequireTeamAdmin())
		r.POST("/members", h.AddMember, middleware.RequireTeamAdmin())
		r.PATCH("/members/{memberId}", h.UpdateMemberRole, middleware.RequireTeamAdmin())
		r.DELETE("/members/{memberId}", h.RemoveMember, middleware.RequireTeamAdmin())
		r.POST("/invitations", h.CreateInvitation, middleware.RequireTeamAdmin())
		r.DELETE("/invitations/{invitationId}", h.DeleteInvitation, middleware.RequireTeamAdmin())

		// Settings management (admin+)
		r.PATCH("/settings/general", h.UpdateGeneralSettings, middleware.RequireTeamAdmin())
		r.PATCH("/settings/branding", h.UpdateBrandingSettings, middleware.RequireTeamAdmin())
		r.PATCH("/settings/branch", h.UpdateBranchSettings, middleware.RequireTeamAdmin())

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
