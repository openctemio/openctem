package middleware

import (
	"net/http"
	"path"
	"strings"

	"github.com/openctemio/openctem/api/pkg/apierror"
)

// Account-only sessions (docs/architecture/tenantless-account-space.md).
//
// A signed-in person who belongs to no organization holds an access token
// without a tenant claim. That token reaches only the routes below: the
// person's own account (profile, security, sessions, sign-in methods,
// preferences), the organizations list (their own memberships, which is
// empty) and creating one where the policy allows it, accepting an
// invitation sent to their address, sign-out and step-up. Every other route
// refuses it in UnifiedAuth, before any handler runs: the list is deny by
// default, so a route added later is refused until it is added here on
// purpose. Tests walk every registered route against this list
// (routes/tenantless_allowlist_test.go).

// tenantlessRoutes is the allow-list: "METHOD /path", with {name} for one
// path segment. Keep it narrow; never add a prefix that holds tenant data.
var tenantlessRoutes = []string{
	// Profile and preferences.
	"GET /api/v1/users/me",
	"PUT /api/v1/users/me",
	"GET /api/v1/users/me/preferences",
	"PUT /api/v1/users/me/preferences",
	// Own memberships (empty for this session) and creating an organization
	// (the handler applies the organization-creation policy).
	"GET /api/v1/users/me/tenants",
	"GET /api/v1/tenants",
	"POST /api/v1/tenants",
	"GET /api/v1/module-presets",
	// Security: password, sessions, two-factor.
	"POST /api/v1/users/me/change-password",
	"GET /api/v1/users/me/sessions",
	"DELETE /api/v1/users/me/sessions",
	"DELETE /api/v1/users/me/sessions/{sessionId}",
	"GET /api/v1/users/me/2fa",
	"POST /api/v1/users/me/2fa/setup",
	"POST /api/v1/users/me/2fa/enable",
	"POST /api/v1/users/me/2fa/disable",
	"POST /api/v1/users/me/2fa/recovery-codes",
	"POST /api/v1/me/2fa/replacement/start",
	"POST /api/v1/me/2fa/replacement/complete",
	// Sign-in methods (each change needs a proof typed for it).
	"GET /api/v1/me/sign-in-methods",
	"DELETE /api/v1/me/sign-in-methods/{id}",
	"POST /api/v1/me/sign-in-method-links/{provider}/start",
	"POST /api/v1/me/sign-in-method-links/{provider}/complete",
	"POST /api/v1/me/pending-sign-in-link/describe",
	"POST /api/v1/me/pending-sign-in-link/complete",
	"POST /api/v1/me/pending-sign-in-link/cancel",
	// Deleting the account (step-up).
	"DELETE /api/v1/me/account",
	"GET /api/v1/me/account/deletion",
	// Accepting an invitation sent to this address, by its token.
	"POST /api/v1/invitations/accept",
	// Session: step-up and sign-out.
	"GET /api/v1/auth/step-up",
	"POST /api/v1/auth/step-up",
	"POST /api/v1/auth/logout",
	// Product facts with no tenant data.
	"GET /api/v1/version",
	"GET /api/v1/announcements",
}

type tenantlessRoute struct {
	method   string
	segments []string
}

var tenantlessIndex = func() []tenantlessRoute {
	out := make([]tenantlessRoute, 0, len(tenantlessRoutes))
	for _, r := range tenantlessRoutes {
		method, p, _ := strings.Cut(r, " ")
		out = append(out, tenantlessRoute{method: method, segments: splitPath(p)})
	}
	return out
}()

func splitPath(p string) []string {
	return strings.Split(strings.Trim(p, "/"), "/")
}

// TenantlessRoutes returns a copy of the allow-list (for tests and docs).
func TenantlessRoutes() []string {
	return append([]string(nil), tenantlessRoutes...)
}

// TenantlessAllowed reports whether an account-only session may call method
// on urlPath. A path that is not in canonical form (dot segments, empty
// segments) is refused rather than normalised, so it can never be matched
// against a route other than the one the router serves.
func TenantlessAllowed(method, urlPath string) bool {
	trimmed := strings.TrimSuffix(urlPath, "/")
	if trimmed == "" || path.Clean(trimmed) != trimmed {
		return false
	}
	got := splitPath(trimmed)
	for _, r := range tenantlessIndex {
		if r.method != method || len(r.segments) != len(got) {
			continue
		}
		if segmentsMatch(r.segments, got) {
			return true
		}
	}
	return false
}

func segmentsMatch(pattern, got []string) bool {
	for i, p := range pattern {
		if strings.HasPrefix(p, "{") && strings.HasSuffix(p, "}") {
			if got[i] == "" {
				return false
			}
			continue
		}
		if p != got[i] {
			return false
		}
	}
	return true
}

// refuseTenantless writes the answer for a route an account-only session may
// not call. 401, as the tenant chain answered a token without a tenant
// before this check existed: the web client then exchanges its refresh token
// for an organization token when the person has one. The code tells an
// account-only client that no exchange will help.
func refuseTenantless(w http.ResponseWriter) {
	apierror.FromCode(apierror.CodeTenantRequired).WriteJSON(w)
}
