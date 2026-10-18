package handler

import (
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/admin"
)

// The roster notice describes role, state and break-glass changes; a name
// change alone sends none.
func TestAdminRosterStateChanges(t *testing.T) {
	a, err := admin.NewAdminUser("ops@acme.io", "Ops", admin.AdminRoleOpsAdmin, nil)
	if err != nil {
		t.Fatal(err)
	}
	before := adminRosterState{role: a.Role(), active: a.IsActive(), breakGlass: a.IsBreakGlass()}
	if got := before.changes(a); got != "" {
		t.Fatalf("no change: got %q", got)
	}
	_ = a.UpdateName("Renamed")
	if got := before.changes(a); got != "" {
		t.Fatalf("a name change sends no notice: got %q", got)
	}
	if err := a.UpdateRole(admin.AdminRoleSuperAdmin); err != nil {
		t.Fatal(err)
	}
	a.Deactivate()
	got := before.changes(a)
	if !strings.Contains(got, "from Operations admin to Super admin") || !strings.Contains(got, "deactivated ops@acme.io") {
		t.Fatalf("role and state change must be described: %q", got)
	}
}
