package unit

import (
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
