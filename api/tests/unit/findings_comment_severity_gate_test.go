package unit

import (
	"reflect"
	"testing"
)

// findings:write used to gate re-scoring a finding along with every other
// change, so whoever could comment or record remediation steps could also
// lower a finding's severity. Severity and classification now need
// findings:severity, comments and reactions findings:comment (migration
// 001486 grants both to every role that held findings:write).
func TestFindingSeverityAndCommentGates(t *testing.T) {
	m := buildRoutePermissionMap(t)
	want := map[string][]string{
		"PATCH /api/v1/findings/{id}/severity":                   {"findings:severity"},
		"PATCH /api/v1/findings/{id}/classify":                   {"findings:severity"},
		"POST /api/v1/findings/{id}/comments":                    {"findings:comment"},
		"PUT /api/v1/findings/{id}/comments/{comment_id}":        {"findings:comment"},
		"DELETE /api/v1/findings/{id}/comments/{comment_id}":     {"findings:comment"},
		"POST /api/v1/comments/{comment_id}/reactions":           {"findings:comment"},
		"DELETE /api/v1/comments/{comment_id}/reactions/{emoji}": {"findings:comment"},
		"POST /api/v1/findings/{id}/remediation/steps":           {"findings:write"},
		"PATCH /api/v1/findings/{id}/status":                     {"findings:status"},
		"POST /api/v1/findings/actions/fix-applied":              {"findings:fix_apply"},
	}
	for route, perms := range want {
		got, ok := m[route]
		if !ok {
			t.Errorf("%s not parsed", route)
			continue
		}
		if !reflect.DeepEqual(got.Permissions, perms) {
			t.Errorf("%s: gate %v, want %v", route, got.Permissions, perms)
		}
	}
}
