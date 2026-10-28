// Package middleware provides HTTP middleware for the API server.
// This file implements platform administrator authentication: a verified
// console session (RFC-022). Administrators have no API keys. Authorization is
// by platform permission (RFC-134): RequirePlatform on each console route.
package middleware

import (
	"context"
	"net/http"
	"time"

	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/platformauthz"
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

// PlatformRoleReader returns the platform roles an administrator holds
// (RFC-134).
type PlatformRoleReader interface {
	HeldRoles(ctx context.Context, adminID string) ([]platformauthz.RoleKey, error)
}

// AdminAuthMiddleware provides authentication for admin API endpoints.
type AdminAuthMiddleware struct {
	sessions AdminSessionAuthenticator
	// roles reads the platform roles; without it an administrator holds the
	// base role of their tier only.
	roles  PlatformRoleReader
	logger *logger.Logger
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

// WithPlatformRoles reads each administrator's platform roles from r.
func (m *AdminAuthMiddleware) WithPlatformRoles(r PlatformRoleReader) *AdminAuthMiddleware {
	m.roles = r
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
		a, sess, err := d.AuthenticateSession(sessionContext(r), c.Value)
		if err != nil {
			return nil, nil, false
		}
		return a, sess, true
	}
	a, err := m.sessions.Authenticate(sessionContext(r), c.Value)
	if err != nil {
		return nil, nil, false
	}
	return a, nil, true
}

// AdminBackgroundHeader marks a console read made without the administrator
// (a periodic refresh of an open page). It never grants anything: it only
// stops the request from counting as activity for the idle timeout.
const AdminBackgroundHeader = "X-Admin-Background"

// sessionContext is the request context, marked as background for a read
// that carries AdminBackgroundHeader. A write always counts as activity.
func sessionContext(r *http.Request) context.Context {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		if r.Header.Get(AdminBackgroundHeader) == "1" {
			return admin.WithBackgroundRequest(r.Context())
		}
	}
	return r.Context()
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
		now := m.now()
		if m.elevation {
			adminUser.ActAs(sess.ActingRole(now))
		}
		// Platform permissions: the roles held, narrowed to the baseline reads
		// plus the role the session is elevated as (when elevation is on).
		roles := []platformauthz.RoleKey{platformauthz.BaseRoleFor(platformauthz.Tier(adminUser.Role()))}
		if m.roles != nil {
			held, err := m.roles.HeldRoles(r.Context(), adminUser.ID().String())
			if err != nil {
				m.logger.Error("admin auth: read platform roles", "error", err)
				apierror.ServiceUnavailable("The console cannot read your roles right now").WriteJSON(w)
				return
			}
			roles = held
		}
		var elevated platformauthz.RoleKey
		if sess != nil {
			elevated = sess.ElevatedAs(now)
		}
		adminUser.SetPlatformAccess(roles, platformauthz.Acting(roles, m.elevation, elevated))
		// A route's permission whose guard ran before this authentication.
		if p, ok := r.Context().Value(pendingPlatformPermKey).(platformauthz.Permission); ok && !adminUser.Can(p) {
			denyPlatform(w, m.logger, adminUser, p)
			return
		}
		ctx := withAdmin(r.Context(), adminUser, AdminAuthMethodSession)
		if sess != nil {
			ctx = context.WithValue(ctx, AdminSessionKey, sess)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// pendingPlatformPermKey carries a route's platform permission to an
// authentication that runs after the route's guard (a route that lists the
// session check among its own middlewares).
const pendingPlatformPermKey logger.ContextKey = "admin_pending_platform_permission"

// RequirePlatform allows the request only when the authenticated
// administrator acts with platform permission p (RFC-134). Every console route
// gets one through the console route registration, which refuses to register
// a route with no permission, so a console route is denied by default. When
// the session check runs later in the route's chain, the check moves there.
func (m *AdminAuthMiddleware) RequirePlatform(p platformauthz.Permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			a := GetAdminUser(r.Context())
			if a == nil {
				next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), pendingPlatformPermKey, p)))
				return
			}
			if !a.Can(p) {
				denyPlatform(w, m.logger, a, p)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func denyPlatform(w http.ResponseWriter, log *logger.Logger, a *admin.AdminUser, p platformauthz.Permission) {
	log.Debug("admin auth: platform permission denied",
		"admin_id", a.ID().String(), "permission", string(p), "role", a.EffectiveRole())
	apierror.Forbidden("insufficient permissions").WriteJSON(w)
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
