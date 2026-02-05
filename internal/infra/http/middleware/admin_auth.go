// Package middleware provides HTTP middleware for the API server.
// This file implements admin API key authentication middleware.
package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/admin"
	"github.com/openctemio/api/pkg/logger"
)

// Admin auth context keys.
const (
	AdminUserKey logger.ContextKey = "admin_user"
	AdminIDKey   logger.ContextKey = "admin_id"
	AdminRoleKey logger.ContextKey = "admin_role"
)

// AdminAPIKeyHeader is the header name for admin API key authentication.
const AdminAPIKeyHeader = "X-Admin-API-Key"

// AdminAuthMiddleware provides authentication for admin API endpoints.
type AdminAuthMiddleware struct {
	adminRepo admin.Repository
	logger    *logger.Logger
}

// NewAdminAuthMiddleware creates a new AdminAuthMiddleware.
func NewAdminAuthMiddleware(adminRepo admin.Repository, log *logger.Logger) *AdminAuthMiddleware {
	return &AdminAuthMiddleware{
		adminRepo: adminRepo,
		logger:    log.With("middleware", "admin_auth"),
	}
}

// Authenticate validates the admin API key and adds admin info to context.
// Use this middleware for all admin endpoints.
func (m *AdminAuthMiddleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract API key from header
		apiKey := r.Header.Get(AdminAPIKeyHeader)
		if apiKey == "" {
			// Also check Authorization header with Bearer scheme
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				apiKey = strings.TrimPrefix(authHeader, "Bearer ")
			}
		}

		if apiKey == "" {
			m.logger.Debug("admin auth: missing API key")
			apierror.Unauthorized("missing admin API key").WriteJSON(w)
			return
		}

		// Authenticate
		adminUser, err := m.adminRepo.AuthenticateByAPIKey(r.Context(), apiKey)
		if err != nil {
			if admin.IsAuthError(err) {
				m.logger.Debug("admin auth: invalid API key",
					"prefix", admin.ExtractAPIKeyPrefix(apiKey),
					"error", err)
				apierror.Unauthorized("invalid admin API key").WriteJSON(w)
				return
			}
			m.logger.Error("admin auth: authentication error", "error", err)
			apierror.InternalError(err).WriteJSON(w)
			return
		}

		// Record usage (async - don't block request)
		go func() {
			ip := extractIP(r)
			if err := m.adminRepo.RecordUsage(context.Background(), adminUser.ID(), ip); err != nil {
				m.logger.Error("failed to record admin API key usage", "error", err)
			}
		}()

		// Add admin info to context
		ctx := r.Context()
		ctx = context.WithValue(ctx, AdminUserKey, adminUser)
		ctx = context.WithValue(ctx, AdminIDKey, adminUser.ID().String())
		ctx = context.WithValue(ctx, AdminRoleKey, string(adminUser.Role()))

		// Add to logger context for request tracing
		ctx = context.WithValue(ctx, logger.ContextKeyUserID, adminUser.ID().String())

		m.logger.Debug("admin auth: authenticated",
			"admin_id", adminUser.ID().String(),
			"email", adminUser.Email(),
			"role", adminUser.Role())

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireRole creates middleware that requires a specific admin role.
// Use after Authenticate middleware.
func (m *AdminAuthMiddleware) RequireRole(roles ...admin.AdminRole) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			adminUser := GetAdminUser(r.Context())
			if adminUser == nil {
				m.logger.Error("admin auth: RequireRole called without Authenticate")
				apierror.Unauthorized("authentication required").WriteJSON(w)
				return
			}

			// Check if admin has one of the required roles
			hasRole := false
			for _, role := range roles {
				if adminUser.Role() == role {
					hasRole = true
					break
				}
			}

			if !hasRole {
				m.logger.Debug("admin auth: insufficient role",
					"admin_id", adminUser.ID().String(),
					"role", adminUser.Role(),
					"required_roles", roles)
				apierror.Forbidden("insufficient permissions").WriteJSON(w)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequirePermission creates middleware that requires a specific permission.
// Use after Authenticate middleware.
func (m *AdminAuthMiddleware) RequirePermission(action string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			adminUser := GetAdminUser(r.Context())
			if adminUser == nil {
				m.logger.Error("admin auth: RequirePermission called without Authenticate")
				apierror.Unauthorized("authentication required").WriteJSON(w)
				return
			}

			if !adminUser.HasPermission(action) {
				m.logger.Debug("admin auth: permission denied",
					"admin_id", adminUser.ID().String(),
					"role", adminUser.Role(),
					"action", action)
				apierror.Forbidden("permission denied: " + action).WriteJSON(w)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// =============================================================================
// Context Getters
// =============================================================================

// GetAdminUser extracts the admin user from context.
func GetAdminUser(ctx context.Context) *admin.AdminUser {
	if adminUser, ok := ctx.Value(AdminUserKey).(*admin.AdminUser); ok {
		return adminUser
	}
	return nil
}

// GetAdminID extracts the admin ID from context.
func GetAdminID(ctx context.Context) string {
	if id, ok := ctx.Value(AdminIDKey).(string); ok {
		return id
	}
	return ""
}

// GetAdminRole extracts the admin role from context.
func GetAdminRole(ctx context.Context) string {
	if role, ok := ctx.Value(AdminRoleKey).(string); ok {
		return role
	}
	return ""
}

// MustGetAdminUser extracts admin user from context or panics if not found.
// Use this in handlers protected by Authenticate() middleware.
func MustGetAdminUser(ctx context.Context) *admin.AdminUser {
	adminUser := GetAdminUser(ctx)
	if adminUser == nil {
		panic("MustGetAdminUser: admin user not found in context - ensure Authenticate() middleware is applied")
	}
	return adminUser
}

// =============================================================================
// Helper Functions
// =============================================================================

// extractIP extracts the client IP from the request.
//
// SECURITY NOTE: This function is designed for audit logging purposes only.
// It does NOT trust X-Forwarded-For or X-Real-IP headers by default because
// these headers can be spoofed by malicious clients.
//
// The function uses RemoteAddr (which cannot be spoofed at TCP level) as the
// primary source. Proxy headers are only used when explicitly configured as
// trusted (via TrustedProxies configuration).
//
// For proper IP extraction behind a reverse proxy:
// 1. Configure your reverse proxy to set X-Forwarded-For
// 2. Configure TrustedProxies with the proxy's IP range
// 3. The proxy should overwrite (not append to) X-Forwarded-For from untrusted sources
func extractIP(r *http.Request) string {
	// SECURITY: Always use RemoteAddr as the authoritative source.
	// RemoteAddr is set by the Go HTTP server from the actual TCP connection
	// and cannot be spoofed by the client.
	ip := r.RemoteAddr

	// Remove port from RemoteAddr (format is "IP:port" or "[IPv6]:port")
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		// Handle IPv6 addresses in brackets
		if strings.HasPrefix(ip, "[") {
			if bracketIdx := strings.Index(ip, "]"); bracketIdx != -1 {
				ip = ip[1:bracketIdx]
			}
		} else {
			ip = ip[:idx]
		}
	}

	return ip
}
