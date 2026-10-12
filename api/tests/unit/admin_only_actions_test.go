package unit

import (
	"sort"
	"strings"
	"testing"
)

// Platform-operator actions live only under /api/v1/admin (the admin console:
// its own sessions, its own step-up, its own audit). A tenant-plane route
// that reaches one of them, directly or through a service method, lets the
// organization's own insiders do what only the platform operator may: this
// test fails on such a route. It uses the handler and service reach of the
// step-up mapping test.

// adminOnlyActions are method names that only admin-console routes may reach.
var adminOnlyActions = map[string]string{
	"RebaselineChain":            "re-signs the tamper-evident audit chain; the organization's owner is the insider it guards against",
	"RebaselineChainIfExplained": "re-signs the tamper-evident audit chain",
	"GetAccessibleTenants":       "every organization in the token: a cross-tenant read skips the other organizations' IP allowlist, SSO, module and data-scope checks",
}

func TestAdminOnlyActions_NotReachableFromTenantPlanes(t *testing.T) {
	reach := handlerReach(t)
	routes := parseRoutes(t)

	reaches := func(r routeRec, action string) bool {
		if r.handlerMethod == "" {
			return false
		}
		if r.handlerType != "" {
			return reach[r.handlerType+"."+r.handlerMethod][action]
		}
		// The receiver is a local variable or a field: any handler type
		// with that method (over-approximates, in the safe direction).
		for key, calls := range reach {
			if strings.HasSuffix(key, "."+r.handlerMethod) && calls[action] {
				return true
			}
		}
		return false
	}

	var leaks []string
	for _, r := range routes {
		if strings.HasPrefix(r.path, "/api/v1/admin") {
			continue
		}
		for action, why := range adminOnlyActions {
			if reaches(r, action) {
				leaks = append(leaks, r.method+" "+r.path+" ("+r.pos+") reaches "+action+": "+why)
			}
		}
	}
	sort.Strings(leaks)
	if len(leaks) > 0 {
		t.Errorf("tenant-plane routes that reach an admin-only action:\n  %s", strings.Join(leaks, "\n  "))
	}

	// The console route must still reach the rebaseline, or the mapping is
	// broken and the check above proves nothing.
	found := false
	for _, r := range routes {
		if strings.HasPrefix(r.path, "/api/v1/admin") && reaches(r, "RebaselineChainIfExplained") {
			found = true
		}
	}
	if !found {
		t.Error("no admin-console route reaches RebaselineChainIfExplained: the AST mapping is broken")
	}
}
