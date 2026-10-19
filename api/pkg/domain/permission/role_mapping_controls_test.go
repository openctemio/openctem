package permission_test

import (
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// A compensating control lowers the priority and SLA of every finding on the
// assets it covers: the built-in Member and Viewer roles may read controls
// but not write them; owners and admins may (backend audit B7-R2).
func TestCompensatingControlsWrite_IsNotAMemberPermission(t *testing.T) {
	for _, r := range []tenant.Role{tenant.RoleMember, tenant.RoleViewer} {
		if permission.HasPermission(r, permission.CompensatingControlsWrite) {
			t.Errorf("%s holds %s", r, permission.CompensatingControlsWrite)
		}
	}
	if !permission.HasPermission(tenant.RoleMember, permission.CompensatingControlsRead) {
		t.Error("member lost the read permission")
	}
	for _, r := range []tenant.Role{tenant.RoleOwner, tenant.RoleAdmin} {
		if !permission.HasPermission(r, permission.CompensatingControlsWrite) {
			t.Errorf("%s lacks %s", r, permission.CompensatingControlsWrite)
		}
	}
}
