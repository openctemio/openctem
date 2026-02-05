package middleware

import (
	"context"
	"net/http"
	"slices"

	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/tenant"
	"github.com/openctemio/api/pkg/keycloak"
	"github.com/openctemio/api/pkg/logger"
)

// Auth-related context keys - use logger.ContextKey for consistency.
const (
	UserIDKey                        = logger.ContextKeyUserID
	RoleKey        logger.ContextKey = "role"
	RolesKey       logger.ContextKey = "roles"           // All realm roles
	EmailKey       logger.ContextKey = "email"           // User email
	UsernameKey    logger.ContextKey = "username"        // Preferred username
	TenantIDKey    logger.ContextKey = "tenant_id"       // Multi-tenant: tenant identifier
	TenantRoleKey  logger.ContextKey = "tenant_role"     // Multi-tenant: primary role within tenant
	TenantRolesKey logger.ContextKey = "tenant_roles"    // Multi-tenant: all roles within tenant
	ClaimsKey      logger.ContextKey = "keycloak_claims" // Full Keycloak claims for UserSync
	// Note: PermissionsKey is defined in unified_auth.go
)

// =============================================================================
// Context Getters
// =============================================================================

// GetUserID extracts the user ID from context.
func GetUserID(ctx context.Context) string {
	if id, ok := ctx.Value(UserIDKey).(string); ok {
		return id
	}
	return ""
}

// GetRole extracts the primary role from context.
func GetRole(ctx context.Context) string {
	if role, ok := ctx.Value(RoleKey).(string); ok {
		return role
	}
	return ""
}

// GetRoles extracts all realm roles from context.
func GetRoles(ctx context.Context) []string {
	if roles, ok := ctx.Value(RolesKey).([]string); ok {
		return roles
	}
	return nil
}

// GetEmail extracts the user email from context.
func GetEmail(ctx context.Context) string {
	if email, ok := ctx.Value(EmailKey).(string); ok {
		return email
	}
	return ""
}

// GetUsername extracts the preferred username from context.
func GetUsername(ctx context.Context) string {
	if username, ok := ctx.Value(UsernameKey).(string); ok {
		return username
	}
	return ""
}

// GetTenantID extracts the tenant ID from context.
func GetTenantID(ctx context.Context) string {
	if tenantID, ok := ctx.Value(TenantIDKey).(string); ok {
		return tenantID
	}
	return ""
}

// MustGetTenantID extracts tenant ID from context or panics if not found.
// Use this in handlers protected by RequireTenant() middleware.
// Panics indicate a programming error (missing middleware), not a user error.
func MustGetTenantID(ctx context.Context) string {
	tenantID := GetTenantID(ctx)
	if tenantID == "" {
		panic("MustGetTenantID: tenant ID not found in context - ensure RequireTenant() middleware is applied")
	}
	return tenantID
}

// GetTenantRole extracts the primary tenant role from context.
func GetTenantRole(ctx context.Context) string {
	if role, ok := ctx.Value(TenantRoleKey).(string); ok {
		return role
	}
	return ""
}

// GetTenantRoles extracts all tenant roles from context.
func GetTenantRoles(ctx context.Context) []string {
	if roles, ok := ctx.Value(TenantRolesKey).([]string); ok {
		return roles
	}
	return nil
}

// GetClaims extracts the full Keycloak claims from context.
func GetClaims(ctx context.Context) *keycloak.Claims {
	if claims, ok := ctx.Value(ClaimsKey).(*keycloak.Claims); ok {
		return claims
	}
	return nil
}

// RequireRole checks if the user has one of the required roles.
func RequireRole(roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userRoles := GetRoles(r.Context())
			if len(userRoles) == 0 {
				apierror.Forbidden("No role assigned").WriteJSON(w)
				return
			}

			// Check if user has any of the required roles
			for _, required := range roles {
				if slices.Contains(userRoles, required) {
					next.ServeHTTP(w, r)
					return
				}
			}

			apierror.Forbidden("Insufficient permissions").WriteJSON(w)
		})
	}
}

// RequireTenant ensures the request has a valid tenant ID.
func RequireTenant() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenantID := GetTenantID(r.Context())
			if tenantID == "" {
				apierror.Unauthorized("Tenant ID not found in token").WriteJSON(w)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// =============================================================================
// JWT Tenant Role Middleware
// =============================================================================

// RequireTenantRole checks if the user has one of the required roles within the tenant.
// Uses role from JWT token claims.
func RequireTenantRole(roles ...tenant.Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenantID := GetTenantID(r.Context())
			if tenantID == "" {
				apierror.Unauthorized("Tenant ID not found in token").WriteJSON(w)
				return
			}

			tenantRoles := GetTenantRoles(r.Context())
			tenantRole := GetTenantRole(r.Context())

			for _, required := range roles {
				if tenantRole == required.String() {
					next.ServeHTTP(w, r)
					return
				}
				if slices.Contains(tenantRoles, required.String()) {
					next.ServeHTTP(w, r)
					return
				}
			}

			apierror.Forbidden("Insufficient tenant permissions").WriteJSON(w)
		})
	}
}

// RequireMinTenantRole checks if the user has at least the minimum role level.
// Uses role hierarchy: owner > admin > member > viewer.
func RequireMinTenantRole(minRole tenant.Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenantID := GetTenantID(r.Context())
			if tenantID == "" {
				apierror.Unauthorized("Tenant ID not found in token").WriteJSON(w)
				return
			}

			tenantRole := GetTenantRole(r.Context())
			if tenantRole == "" {
				apierror.Forbidden("No tenant role assigned").WriteJSON(w)
				return
			}

			userRole := tenant.Role(tenantRole)
			if !userRole.IsValid() {
				apierror.Forbidden("Invalid tenant role").WriteJSON(w)
				return
			}

			if userRole.Priority() < minRole.Priority() {
				apierror.Forbidden("Insufficient tenant permissions").WriteJSON(w)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireWritePermission allows owner, admin, and member roles.
func RequireWritePermission() func(http.Handler) http.Handler {
	return RequireTenantRole(tenant.RoleOwner, tenant.RoleAdmin, tenant.RoleMember)
}

// RequireDeletePermission allows owner and admin roles only.
func RequireDeletePermission() func(http.Handler) http.Handler {
	return RequireTenantRole(tenant.RoleOwner, tenant.RoleAdmin)
}
