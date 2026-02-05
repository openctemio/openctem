package middleware

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/openctemio/api/internal/config"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/permission"
	"github.com/openctemio/api/pkg/jwt"
	"github.com/openctemio/api/pkg/keycloak"
	"github.com/openctemio/api/pkg/logger"
)

// Additional context keys for local auth.
const (
	SessionIDKey         logger.ContextKey = "session_id"
	PermissionsKey       logger.ContextKey = "permissions"
	IsAdminKey           logger.ContextKey = "is_admin"
	AuthProviderKey      logger.ContextKey = "auth_provider"
	LocalClaimsKey       logger.ContextKey = "local_claims"
	TenantMembershipsKey logger.ContextKey = "tenant_memberships"
	AccessibleTenantsKey logger.ContextKey = "accessible_tenants"
)

// AuthProvider values for context.
const (
	AuthProviderLocal = "local"
	AuthProviderOIDC  = "oidc"
)

// UnifiedAuthConfig holds configuration for unified auth middleware.
type UnifiedAuthConfig struct {
	Provider       config.AuthProvider
	LocalValidator *jwt.Generator
	OIDCValidator  *keycloak.Validator
	Logger         *logger.Logger
}

// DefaultAccessTokenCookieName is the default cookie name for access tokens.
// This should match the frontend's auth.cookieName configuration.
const DefaultAccessTokenCookieName = "auth_token"

// extractToken extracts the JWT token from the request.
// Priority: Authorization header > Cookie > query parameter "token"
// Cookie-based auth is preferred for WebSocket (browser sends cookies automatically).
// Query parameter is needed for SSE/EventSource which cannot send custom headers.
func extractToken(r *http.Request) string {
	// 1. Try Authorization header first (standard API auth)
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") && parts[1] != "" {
			return parts[1]
		}
	}

	// 2. Try httpOnly cookie (for WebSocket connections)
	// Browser automatically sends cookies during WebSocket upgrade request
	// This eliminates the need for frontend to expose token via query param
	if cookie, err := r.Cookie(DefaultAccessTokenCookieName); err == nil && cookie.Value != "" {
		return cookie.Value
	}

	// 3. Fallback to query parameter for SSE/EventSource
	// Note: Query param auth is less secure (logged in URLs), only use for SSE
	if token := r.URL.Query().Get("token"); token != "" {
		return token
	}

	return ""
}

// UnifiedAuth creates an authentication middleware that supports both local and OIDC authentication.
// The middleware tries to validate tokens based on the configured auth provider:
// - "local": Only validates local JWT tokens
// - "oidc": Only validates Keycloak/OIDC tokens
// - "hybrid": Tries local first, then falls back to OIDC
//
// Token extraction order:
// 1. Authorization header (Bearer <token>)
// 2. Query parameter "token" (for SSE/EventSource which can't send headers)
func UnifiedAuth(cfg UnifiedAuthConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenString := extractToken(r)
			if tokenString == "" {
				apierror.Unauthorized("Missing authorization token").WriteJSON(w)
				return
			}

			var ctx context.Context
			var err error

			switch cfg.Provider {
			case config.AuthProviderLocal:
				ctx, err = validateLocalToken(r.Context(), tokenString, cfg.LocalValidator)
			case config.AuthProviderOIDC:
				ctx, err = validateOIDCToken(r.Context(), tokenString, cfg.OIDCValidator, cfg.Logger)
			case config.AuthProviderHybrid:
				// Try local first, then OIDC
				ctx, err = validateLocalToken(r.Context(), tokenString, cfg.LocalValidator)
				if err != nil && cfg.OIDCValidator != nil {
					ctx, err = validateOIDCToken(r.Context(), tokenString, cfg.OIDCValidator, cfg.Logger)
				}
			default:
				apierror.InternalError(errors.New("invalid auth provider configuration")).WriteJSON(w)
				return
			}

			if err != nil {
				handleAuthError(w, err, cfg.Logger, r.Context())
				return
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// validateLocalToken validates a local JWT token and returns context with claims.
func validateLocalToken(ctx context.Context, tokenString string, validator *jwt.Generator) (context.Context, error) {
	if validator == nil {
		return nil, errors.New("local auth not configured")
	}

	claims, err := validator.ValidateAccessToken(tokenString)
	if err != nil {
		return nil, err
	}

	// Add claims to context
	ctx = context.WithValue(ctx, UserIDKey, claims.UserID)
	ctx = context.WithValue(ctx, SessionIDKey, claims.SessionID)
	ctx = context.WithValue(ctx, RoleKey, claims.Role)
	ctx = context.WithValue(ctx, EmailKey, claims.Email)
	ctx = context.WithValue(ctx, TenantIDKey, claims.TenantID)
	ctx = context.WithValue(ctx, PermissionsKey, claims.Permissions)
	ctx = context.WithValue(ctx, IsAdminKey, claims.IsAdmin)
	ctx = context.WithValue(ctx, AuthProviderKey, AuthProviderLocal)
	ctx = context.WithValue(ctx, LocalClaimsKey, claims)

	// Add tenant memberships to context for authorization
	ctx = context.WithValue(ctx, TenantMembershipsKey, claims.Tenants)

	// Extract accessible tenant IDs for easy filtering
	accessibleTenants := claims.GetAccessibleTenantIDs()
	ctx = context.WithValue(ctx, AccessibleTenantsKey, accessibleTenants)

	return ctx, nil
}

// validateOIDCToken validates an OIDC (Keycloak) token and returns context with claims.
func validateOIDCToken(ctx context.Context, tokenString string, validator *keycloak.Validator, log *logger.Logger) (context.Context, error) {
	if validator == nil {
		return nil, errors.New("OIDC auth not configured")
	}

	claims, err := validator.ValidateToken(tokenString)
	if err != nil {
		if log != nil {
			log.Debug("OIDC token validation failed",
				"error", err,
				"request_id", GetRequestID(ctx),
			)
		}
		return nil, err
	}

	// Add claims to context
	ctx = context.WithValue(ctx, UserIDKey, claims.GetUserID())
	ctx = context.WithValue(ctx, RoleKey, claims.GetPrimaryRole())
	ctx = context.WithValue(ctx, RolesKey, claims.GetRealmRoles())
	ctx = context.WithValue(ctx, EmailKey, claims.Email)
	ctx = context.WithValue(ctx, UsernameKey, claims.PreferredUsername)
	ctx = context.WithValue(ctx, TenantIDKey, claims.GetTenantID())
	ctx = context.WithValue(ctx, AuthProviderKey, AuthProviderOIDC)
	ctx = context.WithValue(ctx, ClaimsKey, claims)

	return ctx, nil
}

// handleAuthError writes appropriate error responses based on the error type.
func handleAuthError(w http.ResponseWriter, err error, log *logger.Logger, ctx context.Context) {
	// Check for local JWT errors
	switch {
	case errors.Is(err, jwt.ErrExpiredToken):
		apierror.Unauthorized("Token has expired").WriteJSON(w)
		return
	case errors.Is(err, jwt.ErrInvalidToken):
		apierror.Unauthorized("Invalid token").WriteJSON(w)
		return
	case errors.Is(err, jwt.ErrInvalidTokenType):
		apierror.Unauthorized("Invalid token type").WriteJSON(w)
		return
	}

	// Check for Keycloak errors
	switch {
	case errors.Is(err, keycloak.ErrExpiredToken):
		apierror.Unauthorized("Token has expired").WriteJSON(w)
	case errors.Is(err, keycloak.ErrInvalidToken):
		apierror.Unauthorized("Invalid token").WriteJSON(w)
	case errors.Is(err, keycloak.ErrInvalidIssuer):
		apierror.Unauthorized("Invalid token issuer").WriteJSON(w)
	case errors.Is(err, keycloak.ErrInvalidAudience):
		apierror.Unauthorized("Invalid token audience").WriteJSON(w)
	case errors.Is(err, keycloak.ErrKeyNotFound):
		apierror.Unauthorized("Token signing key not found").WriteJSON(w)
	case errors.Is(err, keycloak.ErrJWKSUnavailable):
		apierror.ServiceUnavailable("Authentication service unavailable").WriteJSON(w)
	default:
		if log != nil {
			log.Debug("Token validation failed",
				"error", err,
				"request_id", GetRequestID(ctx),
			)
		}
		apierror.Unauthorized("Token validation failed").WriteJSON(w)
	}
}

// GetSessionID extracts the session ID from context.
func GetSessionID(ctx context.Context) string {
	if id, ok := ctx.Value(SessionIDKey).(string); ok {
		return id
	}
	return ""
}

// GetPermissions extracts the permissions from context.
func GetPermissions(ctx context.Context) []string {
	if perms, ok := ctx.Value(PermissionsKey).([]string); ok {
		return perms
	}
	return nil
}

// IsAdmin checks if the user has admin flag set (owner or admin role).
// When true, the user bypasses general permission checks.
// For owner-only operations (team delete, billing), use IsOwner() instead.
func IsAdmin(ctx context.Context) bool {
	if admin, ok := ctx.Value(IsAdminKey).(bool); ok {
		return admin
	}
	return false
}

// GetAuthProvider extracts the auth provider from context.
func GetAuthProvider(ctx context.Context) string {
	if provider, ok := ctx.Value(AuthProviderKey).(string); ok {
		return provider
	}
	return ""
}

// GetLocalClaims extracts local JWT claims from context.
func GetLocalClaims(ctx context.Context) *jwt.Claims {
	if claims, ok := ctx.Value(LocalClaimsKey).(*jwt.Claims); ok {
		return claims
	}
	return nil
}

// GetTenantMemberships extracts tenant memberships from context.
func GetTenantMemberships(ctx context.Context) []jwt.TenantMembership {
	if memberships, ok := ctx.Value(TenantMembershipsKey).([]jwt.TenantMembership); ok {
		return memberships
	}
	return nil
}

// GetAccessibleTenants extracts the list of tenant IDs the user has access to.
func GetAccessibleTenants(ctx context.Context) []string {
	if tenants, ok := ctx.Value(AccessibleTenantsKey).([]string); ok {
		return tenants
	}
	return nil
}

// HasTenantAccess checks if the user has access to a specific tenant.
func HasTenantAccess(ctx context.Context, tenantID string) bool {
	// Check from JWT claims first
	if claims := GetLocalClaims(ctx); claims != nil {
		return claims.HasTenantAccess(tenantID)
	}

	// Fallback to accessible tenants list
	accessibleTenants := GetAccessibleTenants(ctx)
	for _, t := range accessibleTenants {
		if t == tenantID {
			return true
		}
	}
	return false
}

// GetUserTenantRole returns the user's role in a specific tenant.
func GetUserTenantRole(ctx context.Context, tenantID string) string {
	if claims := GetLocalClaims(ctx); claims != nil {
		return claims.GetTenantRole(tenantID)
	}
	return ""
}

// HasTenantRole checks if user has a specific role (or higher) in a tenant.
func HasTenantRole(ctx context.Context, tenantID string, requiredRole string) bool {
	if claims := GetLocalClaims(ctx); claims != nil {
		return claims.HasTenantRole(tenantID, requiredRole)
	}
	return false
}

// HasPermission checks if the user has a specific permission.
// Owner/Admin (IsAdmin flag in JWT) bypass permission checks - they have almost all permissions.
// Member/Viewer/Custom roles: permissions fetched from DB (not in JWT).
// For owner-only operations, use IsOwner() or RequireOwner() middleware.
func HasPermission(ctx context.Context, permission string) bool {
	// Owner and Admin bypass permission checks
	if IsAdmin(ctx) {
		return true
	}

	// For local auth, check permissions array from JWT
	perms := GetPermissions(ctx)
	if slices.Contains(perms, permission) {
		return true
	}

	// For OIDC, check claims or roles
	if claims := GetLocalClaims(ctx); claims != nil {
		return claims.HasPermission(permission)
	}

	return false
}

// HasAnyPermission checks if the user has any of the specified permissions.
func HasAnyPermission(ctx context.Context, permissions ...string) bool {
	for _, perm := range permissions {
		if HasPermission(ctx, perm) {
			return true
		}
	}
	return false
}

// =============================================================================
// Permission Middleware
// =============================================================================

// Require creates a middleware that requires a specific permission.
// Uses permission.Permission constants for type safety.
//
// Example:
//
//	r.POST("/", middleware.Require(permission.AssetsWrite)(handler))
//	r.DELETE("/{id}", middleware.Require(permission.AssetsDelete)(handler))
func Require(perm permission.Permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !HasPermission(r.Context(), perm.String()) {
				apierror.Forbidden("Insufficient permissions").WriteJSON(w)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireAny creates a middleware that requires any of the specified permissions.
// Uses permission.Permission constants for type safety.
//
// Example:
//
//	r.GET("/", middleware.RequireAny(permission.AssetsRead, permission.RepositoriesRead)(handler))
func RequireAny(perms ...permission.Permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for _, perm := range perms {
				if HasPermission(r.Context(), perm.String()) {
					next.ServeHTTP(w, r)
					return
				}
			}
			apierror.Forbidden("Insufficient permissions").WriteJSON(w)
		})
	}
}

// RequireAll creates a middleware that requires all of the specified permissions.
// Uses permission.Permission constants for type safety.
//
// Example:
//
//	r.POST("/", middleware.RequireAll(permission.AssetsWrite, permission.RepositoriesWrite)(handler))
func RequireAll(perms ...permission.Permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for _, perm := range perms {
				if !HasPermission(r.Context(), perm.String()) {
					apierror.Forbidden("Insufficient permissions").WriteJSON(w)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireAdmin creates a middleware that requires admin access (owner or admin role).
func RequireAdmin() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !IsAdmin(r.Context()) {
				apierror.Forbidden("Admin access required").WriteJSON(w)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// IsOwner checks if the user has the owner role.
// Use this for owner-only operations like team deletion, billing management.
func IsOwner(ctx context.Context) bool {
	role := GetRole(ctx)
	return role == "owner"
}

// RequireOwner creates a middleware that requires owner role.
// Use this for sensitive operations that only the owner should perform:
// - TeamDelete: Deleting the tenant
// - BillingManage: Managing billing settings
// - GroupsDelete, PermissionSetsDelete, AssignmentRulesDelete: Deleting access control resources
func RequireOwner() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !IsOwner(r.Context()) {
				apierror.Forbidden("Owner access required").WriteJSON(w)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// IsPlatformAdmin checks if the user has platform admin privileges.
// Platform admins can manage platform-wide resources like platform agents.
// This is typically granted to Exploop staff or system administrators.
//
// Platform admin is determined by:
// 1. Having "platform_admin" role in RealmAccess (for OIDC/Keycloak)
// 2. Being the system admin (for local auth - checks specific user IDs or emails)
func IsPlatformAdmin(ctx context.Context) bool {
	claims := GetClaims(ctx)
	if claims == nil {
		return false
	}

	// Check for platform_admin role in Keycloak realm access
	for _, role := range claims.RealmAccess.Roles {
		if role == "platform_admin" || role == "system_admin" {
			return true
		}
	}

	// For local auth, check if user email is in allowed platform admins list
	// This can be configured via environment variable PLATFORM_ADMIN_EMAILS
	// For now, we check the role from context (set by local auth)
	role := GetRole(ctx)
	if role == "platform_admin" || role == "system_admin" {
		return true
	}

	return false
}

// RequirePlatformAdmin creates a middleware that requires platform admin access.
// Platform admins can manage Exploop's shared infrastructure like platform agents.
// This is for Exploop operators, not regular tenant admins.
func RequirePlatformAdmin() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !IsPlatformAdmin(r.Context()) {
				apierror.Forbidden("Platform admin access required").WriteJSON(w)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// OptionalUnifiedAuth creates an optional authentication middleware.
// It extracts claims if present but doesn't require authentication.
func OptionalUnifiedAuth(cfg UnifiedAuthConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				next.ServeHTTP(w, r)
				return
			}

			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
				next.ServeHTTP(w, r)
				return
			}

			tokenString := parts[1]
			if tokenString == "" {
				next.ServeHTTP(w, r)
				return
			}

			var ctx context.Context
			var err error

			switch cfg.Provider {
			case config.AuthProviderLocal:
				ctx, err = validateLocalToken(r.Context(), tokenString, cfg.LocalValidator)
			case config.AuthProviderOIDC:
				ctx, err = validateOIDCToken(r.Context(), tokenString, cfg.OIDCValidator, cfg.Logger)
			case config.AuthProviderHybrid:
				ctx, err = validateLocalToken(r.Context(), tokenString, cfg.LocalValidator)
				if err != nil && cfg.OIDCValidator != nil {
					ctx, err = validateOIDCToken(r.Context(), tokenString, cfg.OIDCValidator, cfg.Logger)
				}
			}

			if err == nil && ctx != nil {
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
