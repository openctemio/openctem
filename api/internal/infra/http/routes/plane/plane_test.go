package plane

import "testing"

func TestOf(t *testing.T) {
	for _, tc := range []struct {
		path   string
		want   Plane
		closed bool
	}{
		{"/api/v1/findings/{id}", User, false},
		{"/api/v1/tenants", User, false},
		{"/api/v1/tenants/{tenant}/settings", User, true},
		{"/api/v1/tenants/{tenant_id}", User, true},
		{"/api/v1/agents/{id}", User, true},
		{"/api/v1/agent/heartbeat", Sensor, true},
		{"/api/v2/sensor/hello", Sensor, false},
		{"/api/v1/validation/evidence", Sensor, true},
		{"/api/v1/validation/coverage", User, false},
		{"/api/v1/admin/tenants/{tenantId}", Admin, false},
		{"/api/v1/webhooks", User, false},
		{"/api/v1/webhooks/incoming/jira", Inbound, true},
		{"/hooks/github", Inbound, false},
		{"/scim/v2/Users", SCIM, false},
		{"/api/v1/scim-tokens", User, false},
		{"/api/v1/mcp", MCP, false},
		{"/api/v1/me/permissions", Self, false},
		{"/api/v1/users/me/sessions", Self, true},
		{"/api/v1/users/{userId}/roles", User, false},
		{"/api/v1/auth/login", Auth, false},
		{"/api/v1/invitations/{token}", Auth, true},
		{"/api/v1/invitations/{token}/accept", Auth, true},
		{"/api/v1/invitations/accept", Auth, false},
		{"/api/v1/invitations/lookup", Auth, false},
		{"/health", Ops, false},
		{"/metrics", Ops, false},
	} {
		r, ok := Of(tc.path)
		if !ok || r.Plane != tc.want || r.Closed != tc.closed {
			t.Errorf("Of(%q) = %+v, %v; want plane %s closed=%v", tc.path, r, ok, tc.want, tc.closed)
		}
	}
	if _, ok := Of("/healthz"); ok {
		t.Error("Of(/healthz) matched; prefixes must match whole segments")
	}
	if _, ok := Of("/random"); ok {
		t.Error("Of(/random) matched a plane")
	}
}

func TestEveryClosedRuleNamesASuccessor(t *testing.T) {
	for _, r := range Rules {
		if r.Closed && r.Successor == "" {
			t.Errorf("closed prefix %s has no successor", r.Prefix)
		}
	}
}
