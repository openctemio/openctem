package routes

import (
	"github.com/openctemio/api/internal/infra/http/handler"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/domain/permission"
)

// registerGroupRoutes registers access control group endpoints.
// Groups are used for organizing users and managing permissions.
// Tenant context is obtained from JWT token (same pattern as other handlers).
func registerGroupRoutes(
	router Router,
	h *handler.GroupHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
) {
	// Build tenant middleware chain from JWT token (same as other routes)
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	// Groups API
	router.Group("/api/v1/groups", func(r Router) {
		// List and create groups
		r.GET("/", h.ListGroups, middleware.Require(permission.GroupsRead))
		r.POST("/", h.CreateGroup, middleware.Require(permission.GroupsWrite))

		// Single group operations
		r.GET("/{groupId}", h.GetGroup, middleware.Require(permission.GroupsRead))
		r.PUT("/{groupId}", h.UpdateGroup, middleware.Require(permission.GroupsWrite))
		r.DELETE("/{groupId}", h.DeleteGroup, middleware.Require(permission.GroupsDelete))

		// Group members
		r.GET("/{groupId}/members", h.ListMembers, middleware.Require(permission.GroupsRead))
		r.POST("/{groupId}/members", h.AddMember, middleware.Require(permission.GroupsMembers))
		r.PUT("/{groupId}/members/{userId}", h.UpdateMemberRole, middleware.Require(permission.GroupsMembers))
		r.DELETE("/{groupId}/members/{userId}", h.RemoveMember, middleware.Require(permission.GroupsMembers))

		// Group permission sets
		r.GET("/{groupId}/permission-sets", h.ListAssignedPermissionSets, middleware.Require(permission.GroupsRead))
		r.POST("/{groupId}/permission-sets", h.AssignPermissionSet, middleware.Require(permission.GroupsPermissions))
		r.DELETE("/{groupId}/permission-sets/{permissionSetId}", h.UnassignPermissionSet, middleware.Require(permission.GroupsPermissions))

		// Group asset ownership
		r.GET("/{groupId}/assets", h.ListGroupAssets, middleware.Require(permission.GroupsRead))
		r.POST("/{groupId}/assets", h.AssignAsset, middleware.Require(permission.GroupsWrite))
		r.PUT("/{groupId}/assets/{assetId}", h.UpdateAssetOwnership, middleware.Require(permission.GroupsWrite))
		r.DELETE("/{groupId}/assets/{assetId}", h.UnassignAsset, middleware.Require(permission.GroupsWrite))
	}, tenantMiddlewares...)

	// Current user's groups (my groups)
	router.Group("/api/v1/me/groups", func(r Router) {
		r.GET("/", h.ListMyGroups)
	}, tenantMiddlewares...)

	// Current user's accessible assets (my assets)
	router.Group("/api/v1/me/assets", func(r Router) {
		r.GET("/", h.ListMyAssets)
	}, tenantMiddlewares...)
}

// registerPermissionSetRoutes registers permission set endpoints.
// Permission sets are used for defining collections of permissions.
// Tenant context is obtained from JWT token.
func registerPermissionSetRoutes(
	router Router,
	h *handler.PermissionSetHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
) {
	// Build tenant middleware chain from JWT token
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	// Permission Sets API
	router.Group("/api/v1/permission-sets", func(r Router) {
		// List and create permission sets
		r.GET("/", h.ListPermissionSets, middleware.Require(permission.PermissionSetsRead))
		r.POST("/", h.CreatePermissionSet, middleware.Require(permission.PermissionSetsWrite))

		// System permission sets (read-only)
		r.GET("/system", h.ListSystemPermissionSets, middleware.Require(permission.PermissionSetsRead))

		// Single permission set operations
		r.GET("/{id}", h.GetPermissionSet, middleware.Require(permission.PermissionSetsRead))
		r.PUT("/{id}", h.UpdatePermissionSet, middleware.Require(permission.PermissionSetsWrite))
		r.DELETE("/{id}", h.DeletePermissionSet, middleware.Require(permission.PermissionSetsDelete))

		// Permission items within a set
		r.POST("/{id}/permissions", h.AddPermission, middleware.Require(permission.PermissionSetsWrite))
		r.DELETE("/{id}/permissions/{permissionId}", h.RemovePermission, middleware.Require(permission.PermissionSetsWrite))
	}, tenantMiddlewares...)

	// Current user's effective permissions (legacy, kept for backward compatibility)
	router.Group("/api/v1/me/permissions", func(r Router) {
		r.GET("/", h.GetMyEffectivePermissions)
	}, tenantMiddlewares...)
}

// registerPermissionSyncRoutes registers the real-time permission sync endpoint.
// This endpoint supports ETag-based caching for efficient polling.
func registerPermissionSyncRoutes(
	router Router,
	h *handler.PermissionHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
) {
	// Build tenant middleware chain from JWT token
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	// Permission sync API with ETag support
	// This endpoint is designed for real-time permission synchronization
	// Frontend polls this endpoint and uses If-None-Match header for efficient caching
	router.Group("/api/v1/me/permissions/sync", func(r Router) {
		r.GET("/", h.GetMyPermissions)
	}, tenantMiddlewares...)
}

// registerRoleRoutes registers role management endpoints.
// Roles define what actions users can perform within a tenant.
// Tenant context is obtained from JWT token.
func registerRoleRoutes(
	router Router,
	h *handler.RoleHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
) {
	// Build tenant middleware chain from JWT token
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	// Role CRUD routes
	router.Group("/api/v1/roles", func(r Router) {
		// List and create roles
		r.GET("/", h.ListRoles, middleware.Require(permission.RolesRead))
		r.POST("/", h.CreateRole, middleware.Require(permission.RolesWrite))

		// Single role operations
		r.GET("/{roleId}", h.GetRole, middleware.Require(permission.RolesRead))
		r.PUT("/{roleId}", h.UpdateRole, middleware.Require(permission.RolesWrite))
		r.DELETE("/{roleId}", h.DeleteRole, middleware.Require(permission.RolesDelete))

		// Role members
		r.GET("/{roleId}/members", h.ListRoleMembers, middleware.Require(permission.RolesRead))

		// Bulk operations (must be before /{roleId} patterns to avoid conflicts)
		r.POST("/{roleId}/members/bulk", h.BulkAssignRoleMembers, middleware.Require(permission.RolesAssign))
	}, tenantMiddlewares...)

	// User role assignments
	router.Group("/api/v1/users/{userId}/roles", func(r Router) {
		// Get user's roles
		r.GET("/", h.GetUserRoles, middleware.Require(permission.RolesRead))

		// Assign role to user
		r.POST("/", h.AssignRole, middleware.Require(permission.RolesAssign))

		// Set all roles for user (replace)
		r.PUT("/", h.SetUserRoles, middleware.Require(permission.RolesAssign))

		// Remove role from user
		r.DELETE("/{roleId}", h.RemoveRole, middleware.Require(permission.RolesAssign))
	}, tenantMiddlewares...)

	// Permission routes (database-driven permissions list)
	router.Group("/api/v1/permissions", func(r Router) {
		// List all permissions
		r.GET("/", h.ListPermissions, middleware.Require(permission.RolesRead))

		// List modules with permissions (for UI permission picker)
		r.GET("/modules", h.ListModulesWithPermissions, middleware.Require(permission.RolesRead))
	}, tenantMiddlewares...)

	// Current user's roles
	router.Group("/api/v1/me/roles", func(r Router) {
		r.GET("/", h.GetMyRoles)
	}, tenantMiddlewares...)
}
