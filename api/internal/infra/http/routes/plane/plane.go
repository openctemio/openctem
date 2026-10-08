// Package plane is the table of API planes (RFC-041 §5, docs/rfcs/RFC-041-api-path-design.md):
// which path prefixes belong to which audience, and which prefixes are closed
// to new routes.
//
// It is data with no dependencies, so the route-style lint
// (tools/lint/routestyle), the edge configuration and a future sensor-gateway
// mode (RFC-040) can all read the same table. A route that matches no plane,
// or a plane whose authenticator it does not run, fails the lint.
package plane

import "strings"

// Plane is one audience of the API, separable at the edge by its prefix.
type Plane string

const (
	// User is the tenant API. The tenant comes from the credential.
	User Plane = "user"
	// Self is the caller's own account; the one place that lists tenants.
	Self Plane = "self"
	// Auth is the public sign-in flow (login, SSO, OAuth, SAML, invitations).
	Auth Plane = "auth"
	// Admin is the platform admin console (RFC-022).
	Admin Plane = "admin"
	// Sensor is the sensor protocol (v2, plus v1 until its removal).
	Sensor Plane = "sensor"
	// Inbound is third-party webhooks verified by per-tenant HMAC.
	Inbound Plane = "inbound"
	// SCIM is SCIM 2.0 provisioning (RFC 7644).
	SCIM Plane = "scim"
	// MCP is the read-only MCP server (RFC-016) and its OAuth resource
	// metadata (RFC-062).
	MCP Plane = "mcp"
	// Ops is liveness, readiness, metrics and the API docs.
	Ops Plane = "ops"
)

// Rule maps a path prefix (or an exact path) onto a plane.
type Rule struct {
	Plane Plane
	// Prefix matches the path itself and everything below it ("/x" matches
	// "/x" and "/x/y", not "/xy").
	Prefix string
	// Closed: no new route may be registered here. Existing routes are
	// deprecated aliases that are removed on the RFC-041 §6.2 schedule.
	Closed bool
	// Successor names where the routes of a closed prefix moved.
	Successor string
}

// Rules is the plane table. The longest matching prefix wins, so a specific
// rule (e.g. a sensor route that still lives under /api/v1/validation)
// overrides the user-plane catch-all.
var Rules = []Rule{
	{Plane: Ops, Prefix: "/health"},
	{Plane: Ops, Prefix: "/ready"},
	{Plane: Ops, Prefix: "/metrics"},
	{Plane: Ops, Prefix: "/openapi.yaml"},
	{Plane: Ops, Prefix: "/docs"},

	{Plane: Sensor, Prefix: "/api/v2/sensor"},
	{Plane: Sensor, Prefix: "/api/v3/sensor"},
	{Plane: Sensor, Prefix: "/api/v1/agent", Closed: true, Successor: "/api/v2/sensor"},
	{Plane: Sensor, Prefix: "/api/v1/validation/evidence", Closed: true, Successor: "/api/v2/sensor/evidence"},

	{Plane: Admin, Prefix: "/api/v1/admin"},

	{Plane: Inbound, Prefix: "/hooks"},
	{Plane: Inbound, Prefix: "/api/v1/webhooks/incoming", Closed: true, Successor: "/hooks"},

	{Plane: SCIM, Prefix: "/scim/v2"},
	{Plane: MCP, Prefix: "/api/v1/mcp"},
	// RFC 9728 Protected Resource Metadata of the MCP endpoint (RFC-062).
	{Plane: MCP, Prefix: "/.well-known/oauth-protected-resource"},

	{Plane: Auth, Prefix: "/api/v1/auth"},
	{Plane: Auth, Prefix: "/api/v1/invitations"},
	{Plane: Auth, Prefix: "/api/v1/invitations/{token}", Closed: true, Successor: "/api/v1/invitations"},

	{Plane: Self, Prefix: "/api/v1/me"},
	{Plane: Self, Prefix: "/api/v1/users/me", Closed: true, Successor: "/api/v1/me"},
	{Plane: Self, Prefix: "/api/v1/version"},
	{Plane: Self, Prefix: "/api/v1/announcements"},
	{Plane: Self, Prefix: "/api/v1/ws"},

	{Plane: User, Prefix: "/api/v1/agents", Closed: true, Successor: "/api/v1/sensors"},
	{Plane: User, Prefix: "/api/v1/tenants/{tenant}", Closed: true, Successor: "/api/v1/organization"},
	{Plane: User, Prefix: "/api/v1"},
}

// Of returns the rule that governs path (a route pattern such as
// "/api/v1/findings/{id}"), or false when no plane claims it.
func Of(path string) (Rule, bool) {
	best, found := Rule{}, false
	for _, r := range Rules {
		if !hasPathPrefix(path, r.Prefix) {
			continue
		}
		if !found || len(r.Prefix) > len(best.Prefix) {
			best, found = r, true
		}
	}
	return best, found
}

// hasPathPrefix reports whether path is prefix or lies below it. A path
// parameter in the prefix ("{tenant}") matches any parameter name in path.
func hasPathPrefix(path, prefix string) bool {
	ps, xs := strings.Split(strings.Trim(path, "/"), "/"), strings.Split(strings.Trim(prefix, "/"), "/")
	if len(xs) > len(ps) {
		return false
	}
	for i, x := range xs {
		p := ps[i]
		if isParam(x) && isParam(p) {
			continue
		}
		if x != p {
			return false
		}
	}
	return true
}

func isParam(seg string) bool {
	return strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}")
}
