package unit

import (
	"slices"
	"testing"
)

// Creating and deleting a service account and minting or deleting its keys
// need service_accounts:manage; team:members:write alone (a delegated member
// manager) is not enough.
func TestServiceAccountRoutesNeedServiceAccountsManage(t *testing.T) {
	m := buildRoutePermissionMap(t)
	for route, also := range map[string]string{
		"POST /api/v1/service-accounts":                          "",
		"DELETE /api/v1/service-accounts/{id}":                   "",
		"POST /api/v1/service-accounts/{id}/api-keys":            "integrations:api_keys:write",
		"DELETE /api/v1/service-accounts/{id}/api-keys/{key_id}": "integrations:api_keys:delete",
	} {
		g, ok := m[route]
		if !ok {
			t.Errorf("route %s missing from the map", route)
			continue
		}
		if !slices.Contains(g.Permissions, "service_accounts:manage") {
			t.Errorf("%s requires %v, want service_accounts:manage", route, g.Permissions)
		}
		if slices.Contains(g.Permissions, "team:members:write") {
			t.Errorf("%s still accepts team:members:write: %v", route, g.Permissions)
		}
		if also != "" && !slices.Contains(g.Permissions, also) {
			t.Errorf("%s requires %v, want %s as well", route, g.Permissions, also)
		}
	}
}
