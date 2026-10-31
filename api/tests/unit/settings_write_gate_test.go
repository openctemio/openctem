package unit

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// One rule for organization settings: a change is made by an owner or an
// administrator (the built-in role), on top of any permission the route also
// checks. A custom role holding settings:write alone could otherwise change
// some sections (application access, discovery, license policy) but not the
// others. The member and viewer roles change none of them.
var orgSettingsWritePath = regexp.MustCompile(`^/api/v1/(` +
	`organization/settings/|` +
	`tenants/\{[^}]+\}/settings/|` +
	`mcp-access/(settings|clients|requests)|` +
	`oauth/requests/\{[^}]+\}/allow-publisher|` +
	`easm/settings)`)

func TestOrganizationSettingsWritesNeedAdminRole(t *testing.T) {
	m := buildRoutePermissionMap(t)
	checked := 0
	for key, gate := range m {
		method, path, ok := strings.Cut(key, " ")
		if !ok || method == "GET" || !orgSettingsWritePath.MatchString(path) {
			continue
		}
		// Previews and dry runs change nothing.
		if strings.HasSuffix(path, "/preview") || strings.HasSuffix(path, "/dry-run") || strings.HasSuffix(path, "/test") {
			continue
		}
		checked++
		if gate.MinRole != "admin" && gate.MinRole != "owner" {
			t.Errorf("%s changes organization settings without the owner or admin role (gate %+v)", key, gate)
		}
	}
	if checked < 20 {
		t.Fatalf("only %d settings write routes found; the walker or the pattern broke", checked)
	}
}

// The application-access policy, its clients and the members' requests are
// read by owners and administrators; the monitoring settings by those who can
// run a sweep. A member or viewer holding only settings:read reads none of
// them. (The route map above lists writes only, so this reads the route
// source.)
func TestOrganizationPolicyReadsAreNotOpenToEveryReader(t *testing.T) {
	root := repoRoot(t)
	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join(root, "internal", "infra", "http", "routes", name))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	mcp := regexp.MustCompile(`(?m)^.*r\.GET\("/", h\.(Get|List|ListAccessRequests),.*$`)
	lines := mcp.FindAllString(read("mcp_oauth.go"), -1)
	if len(lines) != 3 {
		t.Fatalf("found %d MCP policy/client/request reads, want 3", len(lines))
	}
	for _, l := range lines {
		if !strings.Contains(l, "RequireAdmin()") {
			t.Errorf("an MCP policy read is open to every settings reader: %s", strings.TrimSpace(l))
		}
	}
	easm := regexp.MustCompile(`(?m)^.*r\.GET\("/", h\.Get,.*$`).FindAllString(read("assets.go"), -1)
	found := false
	for _, l := range easm {
		if strings.Contains(l, "ScopeWrite") {
			found = true
		}
		if strings.Contains(l, "SettingsRead") {
			t.Errorf("EASM settings read gated by settings:read: %s", strings.TrimSpace(l))
		}
	}
	if !found {
		t.Error("GET easm/settings should need scope:write")
	}
}
