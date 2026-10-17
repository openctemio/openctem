package middleware

// The platform administration console answers only to allowed client
// networks (ADMIN_ALLOWED_CIDRS; RFC-022 revision 20). The gate wraps the
// whole server and acts on the console's path prefix, so every console route,
// the sign-in steps included and any route added later, is covered.

import (
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// CodeAdminNetworkNotAllowed is the refusal of a console request from a
// network outside ADMIN_ALLOWED_CIDRS.
const CodeAdminNetworkNotAllowed apierror.Code = "ADMIN_NETWORK_NOT_ALLOWED"

// AdminAPIPrefix is the console's API path prefix.
const AdminAPIPrefix = "/api/v1/admin"

// IsAdminAPIPath reports whether path, once cleaned (repeated slashes, "."
// and ".." segments, a trailing slash), is the console API or below it.
func IsAdminAPIPath(p string) bool {
	c := cleanRequestPath(p)
	return c == AdminAPIPrefix || strings.HasPrefix(c, AdminAPIPrefix+"/")
}

func cleanRequestPath(p string) string {
	return path.Clean("/" + p)
}

// adminPathForms are the paths a request can be routed as: the decoded path,
// the raw (escaped) path decoded, and chi's cleaned routing path, each
// cleaned. The router cleans the path after the global middleware has run,
// so a check on the raw path alone could be passed with "//" or "/./".
func adminPathForms(r *http.Request) []string {
	forms := []string{r.URL.Path}
	if r.URL.RawPath != "" {
		if u, err := url.PathUnescape(r.URL.RawPath); err == nil {
			forms = append(forms, u)
		}
	}
	if rctx := chi.RouteContext(r.Context()); rctx != nil && rctx.RoutePath != "" {
		forms = append(forms, rctx.RoutePath)
	}
	return forms
}

// hasEncodedSeparator reports a percent-encoded "/", "." or "\" in the raw
// path, or a backslash: ways to make one path read as two.
func hasEncodedSeparator(r *http.Request) bool {
	raw := strings.ToLower(r.URL.RawPath)
	return strings.Contains(raw, "%2f") || strings.Contains(raw, "%2e") || strings.Contains(raw, "%5c") ||
		strings.Contains(r.URL.Path, "\\")
}

// MayBeAdminAPIRequest reports whether any way of reading the request's path
// reaches the console API (or it carries an encoded separator next to the
// console prefix). Gates that keep the console away use it: when in doubt,
// it is the console.
func MayBeAdminAPIRequest(r *http.Request) bool {
	for _, f := range adminPathForms(r) {
		if IsAdminAPIPath(f) {
			return true
		}
	}
	return hasEncodedSeparator(r) && strings.Contains(strings.ToLower(r.URL.Path+r.URL.RawPath), "admin")
}

// OnlyAdminAPIRequest reports whether every way of reading the request's
// path is the console API, with no encoded separator: what may pass where
// only the console is served.
func OnlyAdminAPIRequest(r *http.Request) bool {
	if hasEncodedSeparator(r) {
		return false
	}
	for _, f := range adminPathForms(r) {
		if !IsAdminAPIPath(f) {
			return false
		}
	}
	return true
}

// AdminNetworkGate refuses console requests whose client address (the TCP
// peer, or X-Forwarded-For from a trusted proxy, as everywhere else) is not in
// allowed. Any reading of the path that reaches the console counts (see
// MayBeAdminAPIRequest). An address that cannot be parsed is refused. Other
// paths pass. RequireAdminNetwork applies the same check inside the console's
// own routes.
func AdminNetworkGate(allowed []netip.Prefix, log *logger.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !MayBeAdminAPIRequest(r) {
				next.ServeHTTP(w, r)
				return
			}
			refuseOutsideAdminNetwork(allowed, log, next).ServeHTTP(w, r)
		})
	}
}

// RequireAdminNetwork is the console network check for the console's routes
// themselves (defense in depth behind AdminNetworkGate): every request it
// sees was routed to the console, whatever its raw path looked like.
func RequireAdminNetwork(allowed []netip.Prefix, log *logger.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return refuseOutsideAdminNetwork(allowed, log, next)
	}
}

func refuseOutsideAdminNetwork(allowed []netip.Prefix, log *logger.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := ClientIP(r)
		if adminNetworkAllowed(allowed, ip) {
			next.ServeHTTP(w, r)
			return
		}
		if log != nil {
			log.Warn("admin console request from a network outside ADMIN_ALLOWED_CIDRS", "client_ip", ip, "path", r.URL.Path)
		}
		apierror.New(http.StatusForbidden, CodeAdminNetworkNotAllowed,
			"The platform console is not reachable from this network").WriteJSON(w)
	})
}

func adminNetworkAllowed(allowed []netip.Prefix, ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap()
	for _, p := range allowed {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
