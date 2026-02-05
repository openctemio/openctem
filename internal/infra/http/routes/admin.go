package routes

// =============================================================================
// Platform Admin Routes
// =============================================================================
//
// These routes are for Exploop platform administrators only.
// They manage shared infrastructure that serves all tenants.
//
// All admin routes use API Key authentication via X-Admin-API-Key header.
// This is separate from tenant admin routes which use RequireTeamAdmin.

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
	if h.AdminAuthMiddleware != nil {
		adminAPIKeyMiddlewares := []Middleware{h.AdminAuthMiddleware.Authenticate}

		// Auth validation
		if h.AdminAuth != nil {
			router.Group("/api/v1/admin/auth", func(r Router) {
				r.GET("/validate", h.AdminAuth.Validate)
			}, adminAPIKeyMiddlewares...)
		}

		// Admin user management (requires super_admin role)
		if h.AdminUser != nil {
			router.Group("/api/v1/admin/admins", func(r Router) {
				r.GET("/", h.AdminUser.List)
				r.POST("/", h.AdminUser.Create)
				r.GET("/{id}", h.AdminUser.Get)
				r.PATCH("/{id}", h.AdminUser.Update)
				r.DELETE("/{id}", h.AdminUser.Delete)
				r.POST("/{id}/rotate-key", h.AdminUser.RotateKey)
			}, adminAPIKeyMiddlewares...)
		}

		// Audit log endpoints
		if h.AdminAudit != nil {
			router.Group("/api/v1/admin/audit-logs", func(r Router) {
				r.GET("/", h.AdminAudit.List)
				r.GET("/stats", h.AdminAudit.GetStats)
				r.GET("/{id}", h.AdminAudit.Get)
			}, adminAPIKeyMiddlewares...)
		}

		// Target mapping management (scanner target type -> asset type)
		if h.AdminTargetMapping != nil {
			router.Group("/api/v1/admin/target-mappings", func(r Router) {
				// Read operations (no audit/rate limiting needed)
				r.GET("/stats", h.AdminTargetMapping.GetStats)
				r.GET("/", h.AdminTargetMapping.List)
				r.GET("/{id}", h.AdminTargetMapping.Get)

				// Write operations - build middleware chain
				if h.AdminAuditMiddleware != nil {
					// With audit logging
					var writeMiddlewares []Middleware
					if h.AdminMappingRateLimiter != nil {
						writeMiddlewares = append(writeMiddlewares, h.AdminMappingRateLimiter.WriteMiddleware())
					}

					r.POST("/", h.AdminTargetMapping.Create, append(writeMiddlewares, h.AdminAuditMiddleware.AuditTargetMappingCreate())...)
					r.PATCH("/{id}", h.AdminTargetMapping.Update, append(writeMiddlewares, h.AdminAuditMiddleware.AuditTargetMappingUpdate())...)
					r.DELETE("/{id}", h.AdminTargetMapping.Delete, append(writeMiddlewares, h.AdminAuditMiddleware.AuditTargetMappingDelete())...)
				} else {
					// Without audit logging
					r.POST("/", h.AdminTargetMapping.Create)
					r.PATCH("/{id}", h.AdminTargetMapping.Update)
					r.DELETE("/{id}", h.AdminTargetMapping.Delete)
				}
			}, adminAPIKeyMiddlewares...)
		}

	}
}
