package routes

import (
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
)

// registerSCIMRoutes wires the SCIM 2.0 provisioning API (per-tenant bearer
// token auth) plus the admin endpoints to mint/list/revoke a tenant's SCIM
// token (JWT, owner/admin only). See RFC-009.
func registerSCIMRoutes(
	router Router,
	scimHandler *handler.SCIMHandler,
	tokenHandler *handler.SCIMTokenHandler,
	scimAuth Middleware,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
) {
	// SCIM provisioning endpoints — authenticated by the per-tenant bearer token.
	if scimHandler != nil && scimAuth != nil {
		router.Group("/scim/v2", func(r Router) {
			r.GET("/ServiceProviderConfig", scimHandler.ServiceProviderConfig)
			r.GET("/ResourceTypes", scimHandler.ResourceTypes)
			r.GET("/Schemas", scimHandler.Schemas)
			r.GET("/Users", scimHandler.ListUsers)
			r.POST("/Users", scimHandler.CreateUser)
			r.GET("/Users/{id}", scimHandler.GetUser)
			r.PUT("/Users/{id}", scimHandler.ReplaceUser)
			r.PATCH("/Users/{id}", scimHandler.PatchUser)
			r.DELETE("/Users/{id}", scimHandler.DeleteUser)

			// Groups (RFC-009 Phase 9c) — membership drives tenant role.
			r.GET("/Groups", scimHandler.ListGroups)
			r.POST("/Groups", scimHandler.CreateGroup)
			r.GET("/Groups/{id}", scimHandler.GetGroup)
			r.PUT("/Groups/{id}", scimHandler.ReplaceGroup)
			r.PATCH("/Groups/{id}", scimHandler.PatchGroup)
			r.DELETE("/Groups/{id}", scimHandler.DeleteGroup)
		}, scimAuth)
	}

	// SCIM-token management — JWT. Listing and group mappings: owner/admin.
	// Minting and revoking a token: owner only — a SCIM token can create,
	// suspend and re-role every member, so it is the organization owner's
	// credential to hand out (owner decision 2026-10-02).
	if tokenHandler != nil {
		tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)
		router.Group("/api/v1/scim-tokens", func(r Router) {
			// SCIM provisioning is run by the tenant's own IT (their IdP pushes
			// users into their tenant), so it stays a tenant-admin operation —
			// unlike SAML/identity-provider/verified-domain setup in auth.go,
			// which is application-administrator only. RequireAdmin reads the
			// JWT IsAdmin flag on this JWT-tenant chain.
			r.GET("/", tokenHandler.List, middleware.RequireAdmin())
			r.POST("/", tokenHandler.Create, middleware.RequireOwner(), requireStepUp())
			// Group → role mappings (register before /{id} so the literal wins).
			r.GET("/group-mappings", tokenHandler.GetGroupMappings, middleware.RequireAdmin())
			r.PUT("/group-mappings", tokenHandler.SetGroupMappings, middleware.RequireAdmin())
			r.DELETE("/{id}", tokenHandler.Revoke, middleware.RequireOwner())
		}, tenantMiddlewares...)
	}
}
