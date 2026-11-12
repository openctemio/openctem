package handler

import (
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/role"
)

// The role editor does not offer permissions that do nothing in a custom role
// (the routes also need the owner or administrator role).
func TestToModuleResponse_HidesAdminRoleOnlyPermissions(t *testing.T) {
	m := &role.Module{ID: "team", Permissions: []*role.Permission{
		{ID: "team:members:read"}, {ID: "team:members:invite"}, {ID: "team:members:write"}, {ID: "team:read"},
	}}
	got := toModuleResponse(m)
	if len(got.Permissions) != 2 {
		t.Fatalf("got %d permissions, want 2: %+v", len(got.Permissions), got.Permissions)
	}
	for _, p := range got.Permissions {
		if p.ID == "team:members:invite" || p.ID == "team:members:write" {
			t.Errorf("%s is offered in the role editor", p.ID)
		}
	}
}
