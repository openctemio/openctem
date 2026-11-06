package accesscontrol

import (
	"errors"
	"testing"

	roledom "github.com/openctemio/openctem/api/pkg/domain/role"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

func TestMembershipRoleForRoleIDs(t *testing.T) {
	custom := roledom.NewID().String()
	cases := []struct {
		name string
		ids  []string
		want tenantdom.Role
	}{
		// The bug this fixes: an invitation with only the RBAC viewer role created
		// a 'member' membership, and the tenant_members -> user_roles trigger then
		// granted the member role on top of viewer.
		{"viewer only is viewer", []string{roledom.ViewerRoleID.String()}, tenantdom.RoleViewer},
		{"custom only is viewer (least privilege)", []string{custom}, tenantdom.RoleViewer},
		{"viewer plus custom is viewer", []string{roledom.ViewerRoleID.String(), custom}, tenantdom.RoleViewer},
		{"member role is member", []string{roledom.MemberRoleID.String()}, tenantdom.RoleMember},
		{"admin rbac role stays member (team admin is granted separately)", []string{roledom.AdminRoleID.String()}, tenantdom.RoleMember},
		{"viewer plus member is member", []string{roledom.ViewerRoleID.String(), roledom.MemberRoleID.String()}, tenantdom.RoleMember},
		{"case insensitive uuid", []string{"00000000-0000-0000-0000-000000000003"}, tenantdom.RoleMember},
		{"empty is viewer", nil, tenantdom.RoleViewer},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := MembershipRoleForRoleIDs(tc.ids); got != tc.want {
				t.Fatalf("MembershipRoleForRoleIDs(%v) = %s, want %s", tc.ids, got, tc.want)
			}
		})
	}
}

func TestValidateGrantableRoleIDs(t *testing.T) {
	if err := ValidateGrantableRoleIDs([]string{roledom.ViewerRoleID.String()}); err != nil {
		t.Fatalf("viewer must be grantable: %v", err)
	}
	if err := ValidateGrantableRoleIDs(nil); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty role set must be a validation error, got %v", err)
	}
	if err := ValidateGrantableRoleIDs([]string{roledom.OwnerRoleID.String()}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("owner must never be grantable by invitation/creation, got %v", err)
	}
	if err := ValidateGrantableRoleIDs([]string{"not-a-uuid"}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("malformed id must be a validation error, got %v", err)
	}
	if err := ValidateGrantableRoleIDs([]string{"", roledom.ViewerRoleID.String()}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty id must be a validation error, got %v", err)
	}
}
