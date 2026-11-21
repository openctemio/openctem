package savedview

import (
	"strings"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/permission"
)

func TestPageRegistry_KeysAreUniqueStableShapedAndPermissioned(t *testing.T) {
	known := map[permission.Permission]bool{}
	for _, p := range permission.AllPermissions() {
		known[p] = true
	}
	keys, routes := map[string]bool{}, map[string]bool{}
	for _, p := range Pages() {
		if !ValidPageKey(p.Key) {
			t.Errorf("page key %q: want lower-case segments of a-z, 0-9 and \"-\" joined by \".\", at most %d characters", p.Key, MaxPageKeyLen)
		}
		if p.Key != KeyOfRoute(p.Route) {
			t.Errorf("page key %q is not the key of its route %q (%q)", p.Key, p.Route, KeyOfRoute(p.Route))
		}
		if keys[p.Key] || routes[p.Route] {
			t.Errorf("page %q (%s) is registered twice", p.Key, p.Route)
		}
		keys[p.Key], routes[p.Route] = true, true
		switch {
		case !known[p.Permission]:
			t.Errorf("page %q: %q is not a permission of the catalog", p.Key, p.Permission)
		case !strings.Contains(p.Permission.String(), "read") && p.Permission != permission.FindingsStatus &&
			p.Permission != permission.TeamUpdate && p.Permission != permission.IntegrationsManage:
			// A list is read with a read permission. The exceptions are the
			// pages whose own route needs more: the triage queue, the
			// organization settings lists and the notification delivery logs.
			t.Errorf("page %q: %q is not a read permission", p.Key, p.Permission)
		}
		if reason, excluded := PagesWithoutViews[p.Route]; excluded {
			t.Errorf("route %s has a page key and is also listed without views (%s)", p.Route, reason)
		}
		got, ok := LookupPage(p.Key)
		if !ok || got != p {
			t.Errorf("LookupPage(%q) = %+v, %v", p.Key, got, ok)
		}
	}
	for _, key := range []string{PageFindings, PageVulnerabilities, PageAssets, "scans", "scans.runs", "scans.workflows", "sensors",
		"components", "attack-surface.exposures", "emerging-threats", "attack-surface.certificates", "attack-surface.technologies",
		"credentials", "remediation.tasks", "remediation.campaigns", "findings.approvals", "scans.approvals", "settings.members"} {
		if !keys[key] {
			t.Errorf("page key %q is not registered", key)
		}
	}
	for route, reason := range PagesWithoutViews {
		if strings.TrimSpace(reason) == "" {
			t.Errorf("route %s is listed without views and without a reason", route)
		}
	}
}

func TestValidPageKey(t *testing.T) {
	for key, want := range map[string]bool{
		"findings": true, "scans.runs": true, "attack-surface.certificates": true, "settings.integrations.notifications.history": true,
		"": false, "Findings": false, "findings ": false, ".findings": false, "findings.": false, "a..b": false, "a/b": false,
		"a_b": false, "9lives": false, "findings;drop": false, "console:users": false, strings.Repeat("a", MaxPageKeyLen+1): false,
		strings.Repeat("a", MaxPageKeyLen): true,
	} {
		if got := ValidPageKey(key); got != want {
			t.Errorf("ValidPageKey(%q) = %v, want %v", key, got, want)
		}
	}
}

func TestLookupPage_UnknownKey(t *testing.T) {
	for _, key := range []string{"", "nope", "Findings", "findings.nope", "console:users"} {
		if p, ok := LookupPage(key); ok {
			t.Errorf("LookupPage(%q) = %+v, want unknown", key, p)
		}
	}
}
