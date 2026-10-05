package unit

import (
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
)

// An `oct_` API key reaches the tenant REST routes, bounded by its scopes. A
// route WITHOUT a permission gate is not bounded by anything, so every
// ungated route (routeAuthzAllowlist / allowlistPrefixes in
// route_authz_coverage_test.go) must either refuse keys
// (middleware.APIKeyRouteDenied) or not accept keys at all. Allowlisting a new
// ungated route therefore forces a decision here.

// keyChainExempt lists allowlisted prefixes that are not mounted on a
// key-capable chain (buildTokenTenantMiddlewares), with the reason.
var keyChainExempt = map[string]string{
	"/api/v1/agent/":              "sensor protocol v1: sensor-key auth only",
	"/api/v2/sensor":              "sensor protocol v2: sensor authenticator only",
	"/api/v1/agents":              "308 redirect to /api/v1/sensors",
	"/scim/v2":                    "SCIM bearer token auth only",
	"/api/v1/scim":                "SCIM bearer token auth only (token management is /api/v1/scim-tokens, denied)",
	"/api/v1/mcp":                 "key-only endpoint (the MCP server)",
	"/api/v1/webhooks/incoming":   "HMAC-verified inbound webhooks",
	"/api/v1/module-presets":      "JWT-only base chain",
	"/api/v1/version":             "JWT-only base chain (authMiddleware, no oct_ keys)",
	"/api/v1/validation/evidence": "sensor-key auth only",
	"/health":                     "public",
	"/ready":                      "public",
	"/metrics":                    "MetricsAuth bearer",
	"/openapi.yaml":               "public",
	"/docs":                       "public",
}

func TestAPIKeyPolicy_EveryUngatedRouteRefusesKeys(t *testing.T) {
	for _, p := range allowlistPrefixes {
		if middleware.APIKeyRouteDenied(strings.TrimSuffix(p.prefix, "/")) {
			continue
		}
		if _, ok := keyChainExempt[p.prefix]; ok {
			continue
		}
		t.Errorf("ungated prefix %q (%s) is reachable by an API key: add it to the key denylist in "+
			"middleware/apikey_auth.go, or to keyChainExempt with the reason keys cannot reach it", p.prefix, p.reason)
	}
	for route, reason := range routeAuthzAllowlist {
		path := route[strings.IndexByte(route, ' ')+1:]
		if middleware.APIKeyRouteDenied(path) {
			continue
		}
		if _, ok := keyChainExempt[path]; ok {
			continue
		}
		t.Errorf("ungated route %q (%s) is reachable by an API key", route, reason)
	}
}

// Credential, account and admin areas never accept a key, whatever its scopes.
func TestAPIKeyPolicy_SensitiveAreasDenied(t *testing.T) {
	for _, p := range []string{
		"/api/v1/api-keys", "/api/v1/api-keys/{id}/revoke", "/api/v1/scim-tokens",
		"/api/v1/users/me/password", "/api/v1/users/me/mfa", "/api/v1/users/me/sessions",
		"/api/v1/users/{userId}/roles", "/api/v1/me/permissions", "/api/v1/admin/tenants",
		"/api/v1/auth/token", "/api/v1/tenants/{tenant}/members", "/api/v1/invitations/{token}",
		"/api/v1/invitations/accept", "/api/v1/invitations/lookup",
	} {
		if !middleware.APIKeyRouteDenied(p) {
			t.Errorf("%s must refuse API keys", p)
		}
	}
}
