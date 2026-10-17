// Package middleware provides HTTP middleware for the API server.
// This file implements platform administrator authentication: a verified
// console session (RFC-022). Administrators have no API keys.
package middleware

import (
	"context"
	"net/http"
	"time"

	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Admin auth context keys.
const (
	AdminUserKey       logger.ContextKey = "admin_user"
	AdminIDKey         logger.ContextKey = "admin_id"
	AdminRoleKey       logger.ContextKey = "admin_role"
	AdminAuthMethodKey logger.ContextKey = "admin_auth_method"
)

// AdminAuthMethodSession is the only way an admin request is authenticated.
const AdminAuthMethodSession = "session"

// Console (RFC-022) cookie names. The session and CSRF cookies are HttpOnly and
// scoped to the admin API path, so they are never sent to tenant routes. The
// CSRF token is separate from the tenant csrf_token so the two shells can be
// open in one browser.
const (
	AdminSessionCookie = "admin_session"
	AdminMFACookie     = "admin_mfa"
	AdminCSRFCookie    = "admin_csrf"
)

// AdminSessionAuthenticator resolves a console session token to its admin.
type AdminSessionAuthenticator interface {
	Authenticate(ctx context.Context, token string) (*admin.AdminUser, error)
}

// adminSessionDetailer is implemented by authenticators that also return the
// session (how it was authenticated), which the temporary-password gate needs.
type adminSessionDetailer interface {
	AuthenticateSession(ctx context.Context, token string) (*admin.AdminUser, *admin.Session, error)
}

// CodePasswordChangeRequired is the error code of the temporary-password gate.
const CodePasswordChangeRequired apierror.Code = "PASSWORD_CHANGE_REQUIRED"

// AdminSessionKey holds the authenticated console session.
const AdminSessionKey logger.ContextKey = "admin_session"

// passwordChangeAllowed lists what a session holding a temporary password may
// call: who am I, change the password (logout needs no session).
var passwordChangeAllowed = map[string]bool{
	"GET /api/v1/admin/auth/validate":  true,
	"POST /api/v1/admin/auth/password": true,
}

// CodeFactorEnrollmentRequired is the error code of the enrollment gate.
const CodeFactorEnrollmentRequired apierror.Code = "FACTOR_ENROLLMENT_REQUIRED"

// enrollmentAllowed lists what a session held by "require WebAuthn" may call
// until the administrator complies: who am I, read and register security
// keys, confirm with a code or key, and generate recovery codes.
var enrollmentAllowed = map[string]bool{
	"GET /api/v1/admin/auth/validate":                      true,
	"POST /api/v1/admin/auth/password":                     true,
	"GET /api/v1/admin/auth/factors":                       true,
	"POST /api/v1/admin/auth/webauthn/credentials/options": true,
	"POST /api/v1/admin/auth/webauthn/credentials":         true,
	"POST /api/v1/admin/auth/recovery-codes":               true,
	"POST /api/v1/admin/auth/step-up/webauthn/options":     true,
	"POST /api/v1/admin/auth/step-up/webauthn":             true,
}

// AdminAuthMiddleware provides authentication for admin API endpoints.
type AdminAuthMiddleware struct {
	sessions AdminSessionAuthenticator
	logger   *logger.Logger
	// elevation: administrators act as read-only unless their session is
	// elevated (ADMIN_ELEVATION=required).
	elevation bool
	now       func() time.Time
}

// WithElevation makes every request act as the session's acting role:
// read-only unless the session holds a live elevation.
func (m *AdminAuthMiddleware) WithElevation(on bool) *AdminAuthMiddleware {
	m.elevation = on
	return m
}

// authenticateSession accepts a verified console session cookie and, for
// state-changing methods, requires the CSRF header to be that session's
// token (AdminCSRFToken: bound to the session, whatever cookies are sent).
func (m *AdminAuthMiddleware) authenticateSession(r *http.Request) (*admin.AdminUser, *admin.Session, bool) {
	if m.sessions == nil {
		return nil, nil, false
	}
	c, err := r.Cookie(AdminSessionCookie)
	if err != nil || c.Value == "" {
		return nil, nil, false
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
	default:
		if !ValidAdminCSRF(c.Value, r.Header.Get(CSRFHeaderName)) {
			m.logger.Debug("admin auth: session request failed CSRF check")
			return nil, nil, false
		}
	}
	if d, ok := m.sessions.(adminSessionDetailer); ok {
		a, sess, err := d.AuthenticateSession(r.Context(), c.Value)
		if err != nil {
			return nil, nil, false
		}
		return a, sess, true
	}
	a, err := m.sessions.Authenticate(r.Context(), c.Value)
	if err != nil {
		return nil, nil, false
	}
	return a, nil, true
}

// NewAdminAuthMiddleware creates the admin authentication middleware over the
// console session service.
func NewAdminAuthMiddleware(sessions AdminSessionAuthenticator, log *logger.Logger) *AdminAuthMiddleware {
	return &AdminAuthMiddleware{
		sessions: sessions,
		logger:   log.With("middleware", "admin_auth"),
		now:      time.Now,
	}
}

// Authenticate requires a verified console session and adds the admin to the
// request context. An X-Admin-API-Key or Bearer header is not accepted.
func (m *AdminAuthMiddleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		adminUser, sess, ok := m.authenticateSession(r)
		if !ok {
			m.logger.Debug("admin auth: no valid console session")
			apierror.Unauthorized("admin authentication required").WriteJSON(w)
			return
		}
		// A session opened with a temporary password may only change it.
		if adminUser.PasswordChangeRequired() && sess != nil && sess.AuthMethod == admin.AuthMethodPassword &&
			!passwordChangeAllowed[r.Method+" "+r.URL.Path] {
			apierror.New(http.StatusForbidden, CodePasswordChangeRequired,
				"Change your temporary password before using the console").WriteJSON(w)
			return
		}
		// "require WebAuthn": an administrator who has not registered enough
		// security keys and recovery codes may only enroll.
		if sess != nil && sess.EnrollmentRequired && !enrollmentAllowed[r.Method+" "+r.URL.Path] {
			apierror.New(http.StatusForbidden, CodeFactorEnrollmentRequired,
				"Register your security keys and recovery codes before using the console").WriteJSON(w)
			return
		}
		// Time-boxed elevation: without a live elevation the administrator
		// acts as read-only, whatever their own role.
		if m.elevation {
			adminUser.ActAs(sess.ActingRole(m.now()))
		}
		ctx := withAdmin(r.Context(), adminUser, AdminAuthMethodSession)
		if sess != nil {
			ctx = context.WithValue(ctx, AdminSessionKey, sess)
		}
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
				if adminUser.EffectiveRole() == role {
					hasRole = true
					break
				}
			}

			if !hasRole {
				m.logger.Debug("admin auth: insufficient role",
					"admin_id", adminUser.ID().String(),
					"role", adminUser.EffectiveRole(),
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
					"role", adminUser.EffectiveRole(),
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
	// SECURITY (S-4): the TCP peer is authoritative; forwarding headers count
	// only when that peer is a configured trusted proxy. Without trusted
	// proxies this is r.RemoteAddr, so a client cannot choose its own IP.
	return getClientIP(r)
}

// withAdmin stores the authenticated admin (and how it authenticated) on ctx.
func withAdmin(ctx context.Context, a *admin.AdminUser, method string) context.Context {
	ctx = context.WithValue(ctx, AdminUserKey, a)
	ctx = context.WithValue(ctx, AdminIDKey, a.ID().String())
	ctx = context.WithValue(ctx, AdminRoleKey, string(a.EffectiveRole()))
	ctx = context.WithValue(ctx, AdminAuthMethodKey, method)
	// Logger context for request tracing.
	return context.WithValue(ctx, logger.ContextKeyUserID, a.ID().String())
}

// GetAdminAuthMethod returns how the request was authenticated (AdminAuthMethodSession).
func GetAdminAuthMethod(ctx context.Context) string {
	if v, ok := ctx.Value(AdminAuthMethodKey).(string); ok {
		return v
	}
	return ""
}

// ClientIP returns the request's client IP the same way admin auth records it.
func ClientIP(r *http.Request) string { return extractIP(r) }

// GetAdminSession returns the authenticated console session, or nil.
func GetAdminSession(ctx context.Context) *admin.Session {
	if s, ok := ctx.Value(AdminSessionKey).(*admin.Session); ok {
		return s
	}
	return nil
}
