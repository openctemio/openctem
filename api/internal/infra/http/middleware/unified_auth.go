package middleware

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/jwt"
	"github.com/openctemio/openctem/api/pkg/keycloak"
	"github.com/openctemio/openctem/api/pkg/logger"
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
	Provider              config.AuthProvider
	LocalValidator        *jwt.Generator
	OIDCValidator         *keycloak.Validator
	Logger                *logger.Logger
	SessionTimeoutMinutes int // Session timeout in minutes (0 = disabled)
	// RevokedSessions, when set, makes a signed-out session's access tokens
	// stop working on the next request instead of when they expire. A lookup
	// error fails open (logged): the token still expires on its own.
	RevokedSessions RevokedSessionChecker
	// CookieName is the access-token cookie (AUTH_ACCESS_TOKEN_COOKIE_NAME,
	// matching the web's NEXT_PUBLIC_AUTH_COOKIE_NAME). Empty means
	// DefaultAccessTokenCookieName. The WebSocket upgrade is the browser
	// request that reaches the API with this cookie (RFC-045).
	CookieName string
}

// RevokedSessionChecker answers whether a session id has been revoked.
type RevokedSessionChecker interface {
	IsSessionRevoked(ctx context.Context, sessionID string) (bool, error)
}

// DefaultAccessTokenCookieName is the default cookie name for access tokens.
// This should match the frontend's auth.cookieName configuration.
const DefaultAccessTokenCookieName = "auth_token"

// extractTokenWithSource extracts the JWT token from the request and reports
// whether it came from the auth_token cookie.
// Priority: Authorization header > httpOnly cookie.
//
// SECURITY (S-5): The query-parameter fallback (`?token=`) was REMOVED from
// the default extractor because tokens leak via:
//   - nginx/CDN access logs
//   - browser history & autocomplete
//   - Referer headers sent to 3rd-party domains
//   - paste-into-Slack social engineering ("here's the URL" with token in it)
//
// SSE/EventSource genuinely needs query-param auth (browsers don't allow
// custom headers on EventSource), but the codebase has migrated all
// streaming endpoints to WebSocket (which DOES forward cookies during the
// upgrade handshake). If SSE is ever reintroduced, add a dedicated extractor
// next to its route — never reintroduce a query-param fallback here.
//
// The source matters for CSRF: a cookie is attached by the browser to
// requests the page did not write (an ambient credential), so a request it
// authenticates needs CSRF protection; a header token does not.
func extractTokenWithSource(r *http.Request, cookieName string) (string, bool) {
	// 1. Try Authorization header first (standard API auth)
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") && parts[1] != "" {
			return parts[1], false
		}
	}

	// 2. Try httpOnly cookie (for WebSocket connections + cookie-based SPA)
	// Browser automatically sends cookies during WebSocket upgrade request,
	// eliminating any need for frontend to expose token via query param.
	if cookieName == "" {
		cookieName = DefaultAccessTokenCookieName
	}
	if cookie, err := r.Cookie(cookieName); err == nil && cookie.Value != "" {
		return cookie.Value, true
	}

	return "", false
}

// UnifiedAuth creates an authentication middleware that supports both local and OIDC authentication.
// The middleware tries to validate tokens based on the configured auth provider:
// - "local": Only validates local JWT tokens
// - "oidc": Only validates Keycloak/OIDC tokens
// - "hybrid": Tries local first, then falls back to OIDC
//
// Token extraction order (see extractTokenWithSource):
// 1. Authorization header (Bearer <token>)
// 2. httpOnly cookie (auth_token) — used by WebSocket upgrade and cookie SPA
func UnifiedAuth(cfg UnifiedAuthConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenString, fromCookie := extractTokenWithSource(r, cfg.CookieName)
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

			// Check session timeout based on token's issued-at (iat) claim
			if cfg.SessionTimeoutMinutes > 0 {
				if isSessionExpired(ctx, cfg.SessionTimeoutMinutes) {
					apierror.Unauthorized("Session has expired").WriteJSON(w)
					return
				}
			}

			if cfg.RevokedSessions != nil {
				if sid := GetSessionID(ctx); sid != "" {
					revoked, rerr := cfg.RevokedSessions.IsSessionRevoked(ctx, sid)
					if rerr != nil {
						if cfg.Logger != nil {
							cfg.Logger.Warn("session revocation check failed; allowing token until it expires", "error", rerr)
						}
					} else if revoked {
						apierror.Unauthorized("Session has been revoked").WriteJSON(w)
						return
					}
				}
			}

			// CSRF for cookie sessions, on every route behind this middleware.
			// The auth_token cookie is ambient, so a state-changing request it
			// authenticates must carry the double-submit token. This is
			// enforced here, where the credential's source is known, rather
			// than per route group: groups mounted without the tenant chain
			// (/users/me, /tenants/{tenant}, global catalogs) had no CSRF
			// check at all. Checked after the token so a bad session is still
			// 401, not 403.
			if fromCookie {
				if !isSafeMethod(r.Method) {
					if reason := csrfDoubleSubmitFailure(r); reason != "" {
						rejectCSRF(w, r, cfg.Logger, reason)
						return
					}
				}
				ctx = withCookieAuth(ctx)
			}

			// Update the context logger with user_id and tenant_id
			// so downstream services using logger.FromContext(ctx) get
			// request-correlated logs automatically.
			if ctxLogger := logger.FromContext(ctx); ctxLogger != nil {
				enriched := ctxLogger.WithContext(ctx)
				ctx = logger.ToContext(ctx, enriched)
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

	claims, err := validator.ValidateToken(ctx, tokenString)
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

// isSessionExpired checks if the token's issued-at time exceeds the session timeout.
// It checks both local JWT claims and OIDC claims for the IssuedAt field.
func isSessionExpired(ctx context.Context, timeoutMinutes int) bool {
	timeout := time.Duration(timeoutMinutes) * time.Minute

	// Check local JWT claims first
	if claims := GetLocalClaims(ctx); claims != nil {
		if claims.IssuedAt != nil {
			return time.Since(claims.IssuedAt.Time) > timeout
		}
	}

	// Check OIDC (Keycloak) claims
	if claims := GetClaims(ctx); claims != nil {
		if claims.IssuedAt != nil {
			return time.Since(claims.IssuedAt.Time) > timeout
		}
	}

	return false
}

// GetSessionID extracts the session ID from context.
func GetSessionID(ctx context.Context) string {
	if id, ok := ctx.Value(SessionIDKey).(string); ok {
		return id
	}
	return ""
}

// CredentialExpiresAtKey carries the expiry of the credential that
// authenticated the request when no token claims are in the context to read
// it from (the single-use WebSocket ticket).
const CredentialExpiresAtKey logger.ContextKey = "credential_expires_at"

// GetCredentialExpiry returns when the credential that authenticated the
// request stops being valid: the access token's exp (local or OIDC), or the
// value a ticket middleware recorded. Zero when unknown. A long-lived
// connection (the WebSocket) must not outlive it.
func GetCredentialExpiry(ctx context.Context) time.Time {
	if t, ok := ctx.Value(CredentialExpiresAtKey).(time.Time); ok && !t.IsZero() {
		return t
	}
	if c := GetLocalClaims(ctx); c != nil && c.ExpiresAt != nil {
		return c.ExpiresAt.Time
	}
	if c := GetClaims(ctx); c != nil && c.ExpiresAt != nil {
		return c.ExpiresAt.Time
	}
	return time.Time{}
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
	return slices.Contains(accessibleTenants, tenantID)
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
//
// When the permission-sync middleware ran (FetchedPermissionsKey set), its
// fresh set is the only answer: the token's embedded array is not consulted,
// so a revoked permission stops working on the next request, reads included.
func HasPermission(ctx context.Context, permission string) bool {
	// Owner and Admin bypass permission checks
	if IsAdmin(ctx) {
		return true
	}

	if fresh, ok := ctx.Value(FetchedPermissionsKey).([]string); ok {
		return slices.Contains(fresh, permission)
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
// - GroupsDelete, AssignmentRulesDelete: Deleting access control resources
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

// REMOVED (S-8): OptionalUnifiedAuth.
// The middleware silently passed through requests when a Bearer token was
// present but invalid (next.ServeHTTP without auth context). Future code that
// mounts it could be tricked: attacker sends `Authorization: Bearer junk` and
// reaches an unauthenticated handler that assumes claims-or-nothing.
// Confirmed zero callers via repo-wide grep before removal.
// If an SSE-style "auth optional" pattern is needed later, build a new
// middleware that returns 401 when a token is present-but-invalid (only skip
// auth on the missing-header case).
