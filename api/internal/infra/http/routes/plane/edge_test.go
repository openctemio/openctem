package plane

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func gatewayPlanesPath(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate the test file")
	}
	// api/internal/infra/http/routes/plane -> api/deploy/gateway
	return filepath.Join(filepath.Dir(file), "..", "..", "..", "..", "..", "deploy", "gateway", "planes.caddy")
}

// The gateway routes by plane from a file generated from this package. The
// committed file must be what the table generates, so the edge and the route
// table cannot drift. Regenerate with UPDATE_GATEWAY_PLANES=1.
func TestGatewayPlanesFile(t *testing.T) {
	want, err := GatewayPlanesFile()
	if err != nil {
		t.Fatal(err)
	}
	path := gatewayPlanesPath(t)
	if os.Getenv("UPDATE_GATEWAY_PLANES") == "1" {
		if err := os.WriteFile(path, []byte(want), 0o644); err != nil { //nolint:gosec // repo file, world-readable like the Caddyfile
			t.Fatal(err)
		}
		return
	}
	got, err := os.ReadFile(path) //nolint:gosec // repo-local path
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	if string(got) != want {
		t.Fatalf("api/deploy/gateway/planes.caddy is not what the plane table generates.\n"+
			"Regenerate: cd api && UPDATE_GATEWAY_PLANES=1 go test ./internal/infra/http/routes/plane/ -run TestGatewayPlanesFile\n\n"+
			"generated:\n%s", want)
	}
}

func TestEveryPlaneHasAnEdge(t *testing.T) {
	for _, r := range Rules {
		if _, ok := PlaneEdges[r.Plane]; !ok {
			t.Errorf("plane %s (prefix %s) has no edge treatment", r.Plane, r.Prefix)
		}
	}
	for _, o := range EdgeOverrides {
		if _, ok := Of(o.Prefix); !ok {
			t.Errorf("edge override %s lies in no plane", o.Prefix)
		}
		if o.Why == "" {
			t.Errorf("edge override %s gives no reason", o.Prefix)
		}
	}
}

func TestEdgeOf(t *testing.T) {
	for _, tc := range []struct {
		path string
		want Edge
	}{
		{"/api/v2/sensor/results", EdgeAPI},
		{"/api/v1/agent/heartbeat", EdgeAPI},
		{"/api/v1/validation/evidence", EdgeAPI},
		{"/api/v1/validation/coverage", EdgeWeb},
		{"/api/v1/webhooks/incoming/github", EdgeAPI},
		{"/hooks/jira", EdgeAPI},
		{"/scim/v2/Users", EdgeAPI},
		{"/api/v1/mcp", EdgeAPI},
		{"/health", EdgeAPI},
		{"/metrics", EdgeInternal},
		{"/ready", EdgeInternal},
		{"/api/v1/auth/saml/acme/acs", EdgeAPI},
		{"/api/v1/auth/backchannel-logout", EdgeAPI},
		{"/api/v1/auth/login", EdgeWeb},
		{"/api/v1/ws", EdgeAPI},
		{"/api/v1/me/permissions", EdgeWeb},
		{"/api/v1/admin/tenants", EdgeWeb},
		{"/api/v1/findings", EdgeWeb},
		// The stale protocol-v0 rule is gone: these are user-plane paths now.
		{"/api/v1/platform/stats", EdgeWeb},
	} {
		got, ok := EdgeOf(tc.path)
		if !ok || got != tc.want {
			t.Errorf("EdgeOf(%q) = %q, %v; want %q", tc.path, got, ok, tc.want)
		}
	}
}

func TestGatewayPlanesFileShape(t *testing.T) {
	out, err := GatewayPlanesFile()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"(planes) {",
		"@edge_internal path /ready /ready/* /metrics /metrics/*",
		"@plane_sensor path /api/v2/sensor /api/v2/sensor/* /api/v1/agent /api/v1/agent/*",
		"/api/v1/auth/saml /api/v1/auth/saml/*",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("generated file lacks %q:\n%s", want, out)
		}
	}
	// Browser planes are never sent straight to the API by path.
	for _, never := range []string{"/api/v1/admin", "/api/v1/me ", "/api/v1/platform"} {
		if strings.Contains(out, never) {
			t.Errorf("generated file routes %q straight to the API:\n%s", never, out)
		}
	}
}
