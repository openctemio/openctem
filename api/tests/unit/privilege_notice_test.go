package unit

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/accesscontrol"
	"github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/role"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type recordedPrivilege struct {
	tenant, user shared.ID
	what         string
}

type fakePrivilegeNotifier struct{ got []recordedPrivilege }

func (f *fakePrivilegeNotifier) NotifyPrivilegeIncrease(_ context.Context, tenantID, userID shared.ID, what string) {
	f.got = append(f.got, recordedPrivilege{tenantID, userID, what})
}

// Privilege increases are told to the administrators (RFC-058): the admin
// role, on every grant path; an ordinary role is not news.
func TestPrivilegeIncrease_Notified(t *testing.T) {
	ctx := context.Background()
	admin := role.AdminRoleID.String()

	t.Run("assign admin", func(t *testing.T) {
		f := newCeilingFixture(t)
		n := &fakePrivilegeNotifier{}
		f.svc.SetPrivilegeNotifier(n)
		if err := f.svc.AssignRole(ctx, accesscontrol.AssignRoleInput{TenantID: f.tenant.String(), UserID: f.member.String(), RoleID: admin},
			f.owner.String(), audit.AuditContext{}); err != nil {
			t.Fatal(err)
		}
		if len(n.got) != 1 || n.got[0].user.String() != f.member.String() || n.got[0].tenant.String() != f.tenant.String() {
			t.Fatalf("notices = %+v, want one for the member", n.got)
		}
	})

	t.Run("set roles adds admin, once", func(t *testing.T) {
		f := newCeilingFixture(t)
		n := &fakePrivilegeNotifier{}
		f.svc.SetPrivilegeNotifier(n)
		in := accesscontrol.SetUserRolesInput{TenantID: f.tenant.String(), UserID: f.member.String(),
			RoleIDs: []string{admin, role.ViewerRoleID.String()}}
		if err := f.svc.SetUserRoles(ctx, in, f.owner.String(), audit.AuditContext{}); err != nil {
			t.Fatal(err)
		}
		if len(n.got) != 1 {
			t.Fatalf("notices = %+v, want one (admin added; viewer already held)", n.got)
		}
		// Saving the same set again is not an increase.
		if err := f.svc.SetUserRoles(ctx, in, f.owner.String(), audit.AuditContext{}); err != nil {
			t.Fatal(err)
		}
		if len(n.got) != 1 {
			t.Fatalf("an unchanged set notified again: %+v", n.got)
		}
	})

	t.Run("bulk assign admin", func(t *testing.T) {
		f := newCeilingFixture(t)
		n := &fakePrivilegeNotifier{}
		f.svc.SetPrivilegeNotifier(n)
		if _, err := f.svc.BulkAssignRoleToUsers(ctx, accesscontrol.BulkAssignRoleToUsersInput{TenantID: f.tenant.String(),
			RoleID: admin, UserIDs: []string{f.member.String()}}, f.owner.String(), audit.AuditContext{}); err != nil {
			t.Fatal(err)
		}
		if len(n.got) != 1 {
			t.Fatalf("notices = %+v, want one", n.got)
		}
	})

	t.Run("viewer is not news", func(t *testing.T) {
		f := newCeilingFixture(t)
		n := &fakePrivilegeNotifier{}
		f.svc.SetPrivilegeNotifier(n)
		if err := f.svc.AssignRole(ctx, accesscontrol.AssignRoleInput{TenantID: f.tenant.String(), UserID: f.member.String(),
			RoleID: role.ViewerRoleID.String()}, f.owner.String(), audit.AuditContext{}); err != nil {
			t.Fatal(err)
		}
		if len(n.got) != 0 {
			t.Fatalf("notices = %+v, want none", n.got)
		}
	})
}
