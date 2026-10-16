package middleware

// The platform administration console answers only to allowed client
// networks (ADMIN_ALLOWED_CIDRS; RFC-022 revision 20). The gate wraps the
// whole server and acts on the console's path prefix, so every console route,
// the sign-in steps included and any route added later, is covered.

import (
	"net/http"
	"net/netip"
	"strings"

	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// CodeAdminNetworkNotAllowed is the refusal of a console request from a
// network outside ADMIN_ALLOWED_CIDRS.
const CodeAdminNetworkNotAllowed apierror.Code = "ADMIN_NETWORK_NOT_ALLOWED"

// AdminAPIPrefix is the console's API path prefix.
const AdminAPIPrefix = "/api/v1/admin"

// IsAdminAPIPath reports whether path is the console API or below it.
func IsAdminAPIPath(path string) bool {
	return path == AdminAPIPrefix || strings.HasPrefix(path, AdminAPIPrefix+"/")
}

// AdminNetworkGate refuses console requests whose client address (the TCP
// peer, or X-Forwarded-For from a trusted proxy, as everywhere else) is not in
// allowed. An address that cannot be parsed is refused. Other paths pass.
func AdminNetworkGate(allowed []netip.Prefix, log *logger.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !IsAdminAPIPath(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}
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
