package routestyle_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/tools/lint/routestyle"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for range 10 {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("go.mod not found")
	return ""
}

// TestRoutesFollowTheConventions is the RFC-041 route-style gate. A new
// violation fails; so does a baseline line that no longer matches one (the
// baseline only shrinks).
func TestRoutesFollowTheConventions(t *testing.T) {
	root := repoRoot(t)
	routes, err := routestyle.Routes(filepath.Join(root, "internal", "infra", "http", "routes"))
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) < 500 {
		t.Fatalf("found only %d routes: the AST walk is broken, not the code", len(routes))
	}
	baseline, err := routestyle.Baseline(filepath.Join(root, "api", "openapi", "route-style-baseline.txt"))
	if err != nil {
		t.Fatal(err)
	}

	found := map[string]bool{}
	var fresh []string
	for _, v := range routestyle.Check(routes) {
		found[v.Key()] = true
		if !baseline[v.Key()] {
			fresh = append(fresh, v.Key()+"  — "+v.Msg)
		}
	}
	var stale []string
	for k := range baseline {
		if !found[k] {
			stale = append(stale, k)
		}
	}
	t.Logf("routes=%d violations=%d baseline=%d", len(routes), len(found), len(baseline))
	if len(fresh) > 0 {
		t.Errorf("%d route(s) break the API conventions (docs/architecture/api-conventions.md).\n"+
			"Fix the route; only if that is impossible, add the line to api/openapi/route-style-baseline.txt "+
			"in the same PR, where a reviewer sees it:\n  %s", len(fresh), strings.Join(fresh, "\n  "))
	}
	if len(stale) > 0 {
		t.Errorf("%d baseline line(s) no longer match a violation; delete them (the baseline only shrinks):\n  %s",
			len(stale), strings.Join(stale, "\n  "))
	}
}

func check(method, path, chain string) []string {
	var out []string
	for _, v := range routestyle.Check([]routestyle.Route{{Method: method, Path: path, Chain: chain}}) {
		out = append(out, v.Rule)
	}
	return out
}

const tenantChain = "tenantMiddlewares buildTokenTenantMiddlewares(authMiddleware, userSync)"

func TestRules(t *testing.T) {
	for _, tc := range []struct {
		method, path, chain string
		want                string // comma-separated rules, "" for none
	}{
		{"GET", "/api/v1/findings/{finding_id}", tenantChain, ""},
		{"POST", "/api/v1/findings/{finding_id}/verify", tenantChain, ""},
		{"GET", "/api/v1/findings/stats", tenantChain, ""},
		{"POST", "/api/v1/findings/bulk/resolve", tenantChain, ""},
		{"GET", "/api/v2/sensor/hello", "middleware.V2Observe(name) | h.Authenticate", ""},
		{"GET", "/api/v1/admin/users", "adminMiddlewares []Middleware{h.AdminAuthMiddleware.Authenticate}", ""},

		{"GET", "/api/v1/nowhere", "", ""}, // under /api/v1: user plane, no violation
		{"GET", "/elsewhere", "", "R1"},
		{"POST", "/api/v1/validation/evidence2", "ingestHandler.AuthenticateSource", "R1"},
		{"GET", "/api/v2/sensor/x", tenantChain, "R1"},
		{"GET", "/api/v1/findings", "h.AdminAuthMiddleware.Authenticate | " + tenantChain, "R1"},
		{"GET", "/.well-known/oauth-protected-resource", "", ""}, // RFC 8615 prefix
		{"GET", "/api/v1/.well-known/x", tenantChain, "R2"},      // only as the first segment
		{"GET", "/api/v1/scan_zones", tenantChain, "R2"},
		{"GET", "/api/v1/scanZones", tenantChain, "R2"},
		{"GET", "/api/v1/findings/{findingId}", tenantChain, "R3"},
		{"GET", "/api/v1/secret-store/{id}", tenantChain, "R4"},
		{"GET", "/api/v1/threat-intel/sync", tenantChain, "R5"},
		{"PATCH", "/api/v1/notifications/{id}/read", tenantChain, "R5"},
		{"POST", "/api/v1/scope/targets/{id}/activate", tenantChain, "R5"},
		{"POST", "/api/v1/tools/{id}/check-version", tenantChain, "R5"},
		{"GET", "/api/v1/organizations/{tenant_id}/members", tenantChain, "R6"},
		{"GET", "/api/v1/shares/{token}", tenantChain, "R7"},
		{"GET", "/api/v1/as/{a_id}/bs/{b_id}/cs/{c_id}/ds/{d_id}", tenantChain, "R8"},
		{"POST", "/api/v1/agents/{id}/x", "", "R9"},
		{"GET", "/api/v1/agents", "middleware.Deprecated(d)", ""},
		{"GET", "/scim/v2/Users", "scimAuth", ""},
		{"GET", "/api/v1/scans/{scan_id}/export", tenantChain, ""},
		{"GET", "/api/v1/auth/oauth/{provider}/authorize", "", ""},
		{"GET", "/api/v1/users/me/2fa", "", "R9"},
	} {
		got := strings.Join(check(tc.method, tc.path, tc.chain), ",")
		if got != tc.want {
			t.Errorf("%s %s: rules %q, want %q", tc.method, tc.path, got, tc.want)
		}
	}
}
