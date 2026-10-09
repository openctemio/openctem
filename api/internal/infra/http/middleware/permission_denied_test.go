package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

type deniedBody struct {
	Code    string                  `json:"code"`
	Message string                  `json:"message"`
	Details PermissionDeniedDetails `json:"details"`
}

func runGate(t *testing.T, gate func(http.Handler) http.Handler, ctx context.Context) (int, deniedBody) {
	t.Helper()
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	rec := httptest.NewRecorder()
	gate(ok).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/x", nil).WithContext(ctx))
	var b deniedBody
	if rec.Code == http.StatusForbidden {
		if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil {
			t.Fatalf("decode 403 body: %v", err)
		}
	}
	return rec.Code, b
}

func withPerms(perms ...string) context.Context {
	return context.WithValue(context.Background(), FetchedPermissionsKey, perms)
}

// A refused permission names what was missing, so the person can ask for
// exactly that grant.
func TestPermissionDenied_NamesTheMissingGrant(t *testing.T) {
	cases := []struct {
		name string
		gate func(http.Handler) http.Handler
		ctx  context.Context
		want PermissionDeniedDetails
	}{
		{
			"require", Require(permission.FindingsVerify), withPerms("findings:read"),
			PermissionDeniedDetails{MissingPermissions: []string{"findings:verify"}},
		},
		{
			"require all names only the missing ones",
			RequireAll(permission.FindingsWrite, permission.AITriageTrigger), withPerms("findings:write"),
			PermissionDeniedDetails{MissingPermissions: []string{"ai_triage:trigger"}},
		},
		{
			"require any", RequireAny(permission.SensorsRead, permission.CIRead), withPerms(),
			PermissionDeniedDetails{AnyOf: []string{"sensors:read", "scans:ci:read"}},
		},
		{
			"admin", RequireAdmin(), withPerms(),
			PermissionDeniedDetails{RequiredRole: "admin"},
		},
		{
			"team admin", RequireTeamAdmin(), context.WithValue(context.Background(), TeamRoleKey, tenant.RoleMember),
			PermissionDeniedDetails{RequiredRole: "admin"},
		},
		{
			"min team role", RequireMinTeamRole(tenant.RoleMember), context.WithValue(context.Background(), TeamRoleKey, tenant.RoleViewer),
			PermissionDeniedDetails{RequiredRole: "member"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, b := runGate(t, c.gate, c.ctx)
			if code != http.StatusForbidden || b.Code != "FORBIDDEN" {
				t.Fatalf("status %d code %q, want 403 FORBIDDEN", code, b.Code)
			}
			if !reflect.DeepEqual(b.Details, c.want) {
				t.Errorf("details %+v, want %+v", b.Details, c.want)
			}
		})
	}
}

// Holding the permission still passes; the details change nothing else.
func TestPermissionDenied_GrantedPasses(t *testing.T) {
	if code, _ := runGate(t, Require(permission.FindingsVerify), withPerms("findings:verify")); code != http.StatusNoContent {
		t.Fatalf("status %d", code)
	}
	if code, _ := runGate(t, RequireAll(permission.FindingsWrite, permission.AITriageTrigger),
		withPerms("findings:write", "ai_triage:trigger")); code != http.StatusNoContent {
		t.Fatalf("status %d", code)
	}
}
