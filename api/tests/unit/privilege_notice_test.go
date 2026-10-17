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

// wideRole registers a custom role with full data access: granting it lifts
// the data scope, so it is a privilege increase (the system roles are no
// longer granted through the Roles API at all).
func wideRole(f *ceilingFixture) role.ID {
	wide := role.New(f.tenant, "wide", "Wide", "", 10, true, []string{"assets:read"}, role.NewID())
	f.repo.roles[wide.ID().String()] = wide
	return wide.ID()
}

// Privilege increases are told to the administrators (RFC-058): the admin
// role (when an administrator creates an account or accepts an invitation)
// and full-data custom roles on every Roles API path; an ordinary role is not
// news.
func TestPrivilegeIncrease_Notified(t *testing.T) {
	ctx := context.Background()

	t.Run("assign a full-data role", func(t *testing.T) {
		f := newCeilingFixture(t)
		n := &fakePrivilegeNotifier{}
		f.svc.SetPrivilegeNotifier(n)
		if err := f.svc.AssignRole(ctx, accesscontrol.AssignRoleInput{TenantID: f.tenant.String(), UserID: f.member.String(), RoleID: wideRole(f).String()},
			f.owner.String(), audit.AuditContext{}); err != nil {
			t.Fatal(err)
		}
		if len(n.got) != 1 || n.got[0].user.String() != f.member.String() || n.got[0].tenant.String() != f.tenant.String() {
			t.Fatalf("notices = %+v, want one for the member", n.got)
		}
	})

	t.Run("set roles adds a full-data role, once", func(t *testing.T) {
		f := newCeilingFixture(t)
		n := &fakePrivilegeNotifier{}
		f.svc.SetPrivilegeNotifier(n)
		in := accesscontrol.SetUserRolesInput{TenantID: f.tenant.String(), UserID: f.member.String(),
			RoleIDs: []string{wideRole(f).String(), f.analyst.ID().String()}}
		if err := f.svc.SetUserRoles(ctx, in, f.owner.String(), audit.AuditContext{}); err != nil {
			t.Fatal(err)
		}
		if len(n.got) != 1 {
			t.Fatalf("notices = %+v, want one (full data added; the other role is not news)", n.got)
		}
		// Saving the same set again is not an increase.
		if err := f.svc.SetUserRoles(ctx, in, f.owner.String(), audit.AuditContext{}); err != nil {
			t.Fatal(err)
		}
		if len(n.got) != 1 {
			t.Fatalf("an unchanged set notified again: %+v", n.got)
		}
	})

	t.Run("bulk assign a full-data role", func(t *testing.T) {
		f := newCeilingFixture(t)
		n := &fakePrivilegeNotifier{}
		f.svc.SetPrivilegeNotifier(n)
		if _, err := f.svc.BulkAssignRoleToUsers(ctx, accesscontrol.BulkAssignRoleToUsersInput{TenantID: f.tenant.String(),
			RoleID: wideRole(f).String(), UserIDs: []string{f.member.String()}}, f.owner.String(), audit.AuditContext{}); err != nil {
			t.Fatal(err)
		}
		if len(n.got) != 1 {
			t.Fatalf("notices = %+v, want one", n.got)
		}
	})

	t.Run("the admin role given to a new account", func(t *testing.T) {
		f := newCeilingFixture(t)
		n := &fakePrivilegeNotifier{}
		f.svc.SetPrivilegeNotifier(n)
		if err := f.svc.GrantExactRoles(ctx, f.tenant.String(), f.member.String(), []string{role.AdminRoleID.String()},
			f.owner.String(), audit.AuditContext{}); err != nil {
			t.Fatal(err)
		}
		if len(n.got) != 1 {
			t.Fatalf("notices = %+v, want one", n.got)
		}
	})

	t.Run("an ordinary role is not news", func(t *testing.T) {
		f := newCeilingFixture(t)
		n := &fakePrivilegeNotifier{}
		f.svc.SetPrivilegeNotifier(n)
		plain := role.New(f.tenant, "plain", "Plain", "", 10, false, []string{"assets:read"}, role.NewID())
		f.repo.roles[plain.ID().String()] = plain
		if err := f.svc.AssignRole(ctx, accesscontrol.AssignRoleInput{TenantID: f.tenant.String(), UserID: f.member.String(),
			RoleID: plain.ID().String()}, f.owner.String(), audit.AuditContext{}); err != nil {
			t.Fatal(err)
		}
		if len(n.got) != 0 {
			t.Fatalf("notices = %+v, want none", n.got)
		}
	})
}
