package routes

import (
	"github.com/openctemio/api/internal/infra/http/handler"
	"github.com/openctemio/api/internal/infra/http/middleware"
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

	// Admin SCIM-token management — JWT, owner/admin.
	if tokenHandler != nil {
		tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)
		router.Group("/api/v1/scim-tokens", func(r Router) {
			r.GET("/", tokenHandler.List, middleware.RequireAdmin())
			r.POST("/", tokenHandler.Create, middleware.RequireAdmin())
			// Group → role mappings (register before /{id} so the literal wins).
			r.GET("/group-mappings", tokenHandler.GetGroupMappings, middleware.RequireAdmin())
			r.PUT("/group-mappings", tokenHandler.SetGroupMappings, middleware.RequireAdmin())
			r.DELETE("/{id}", tokenHandler.Revoke, middleware.RequireAdmin())
		}, tenantMiddlewares...)
	}
}
