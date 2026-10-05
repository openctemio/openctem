package unit

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/internal/app"

	"github.com/openctemio/openctem/api/internal/app/accesscontrol"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/role"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// Settings decisions B1 and B2 (2026-10-04):
//
//   - B1: sensors and sensor keys are admin only, so a custom role may never
//     carry an admin-only permission (sensors:write and friends), whoever
//     builds it, the owner included.
//   - B2: only the owner may make someone an administrator. An administrator
//     may manage members and viewers but not mint a peer.

func TestAdminOnlyPermissions_NotHeldByMemberOrViewer(t *testing.T) {
	for _, p := range permission.AdminOnlyPermissions() {
		if permission.HasPermission(tenant.RoleMember, p) || permission.HasPermission(tenant.RoleViewer, p) {
			t.Errorf("%s is admin-only but a member or viewer holds it", p)
		}
		if !permission.HasPermission(tenant.RoleAdmin, p) {
			t.Errorf("%s is admin-only but the admin role does not hold it", p)
		}
	}
	if !permission.IsAdminOnly("sensors:write") || permission.IsAdminOnly("sensors:read") {
		t.Fatal("sensors:write must be admin-only and sensors:read must not")
	}
}

func TestCustomRole_RefusesAdminOnlyPermissions(t *testing.T) {
	for _, p := range permission.AdminOnlyPermissions() {
		f := newCeilingFixture(t)
		ctx := context.Background()
		owner := f.owner.String()

		_, err := f.svc.CreateRole(ctx, accesscontrol.CreateRoleInput{
			TenantID: f.tenant.String(), Slug: "sensor-ops", Name: "Sensor ops", Permissions: []string{"assets:read", string(p)},
		}, owner, app.AuditContext{ActorID: owner})
		if !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("owner creates a custom role with %s: want validation error, got %v", p, err)
		}

		_, err = f.svc.UpdateRole(ctx, f.tenant.String(), f.analyst.ID().String(),
			accesscontrol.UpdateRoleInput{Permissions: []string{"assets:read", string(p)}}, app.AuditContext{ActorID: owner})
		if !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("owner adds %s to a custom role: want validation error, got %v", p, err)
		}
		for _, have := range f.analyst.Permissions() {
			if have == string(p) {
				t.Fatalf("%s was stored on the custom role despite the refusal", p)
			}
		}
	}
}

func TestCustomRole_SensorReadStaysAllowed(t *testing.T) {
	f := newCeilingFixture(t)
	owner := f.owner.String()
	if _, err := f.svc.CreateRole(context.Background(), accesscontrol.CreateRoleInput{
		TenantID: f.tenant.String(), Slug: "sensor-viewer", Name: "Sensor viewer",
		Permissions: []string{"sensors:read", "sensors:zones:read", "sensors:commands:read"},
	}, owner, app.AuditContext{ActorID: owner}); err != nil {
		t.Fatalf("a custom role with sensor read permissions: %v", err)
	}
}

func TestOnlyOwnerPromotesToAdmin(t *testing.T) {
	ctx := context.Background()
	admin := role.AdminRoleID.String()

	t.Run("admin cannot make a member an administrator", func(t *testing.T) {
		f := newCeilingFixture(t)
		tid, aid, mid := f.tenant.String(), f.admin.String(), f.member.String()
		wantForbidden(t, "AssignRole admin", f.svc.AssignRole(ctx,
			accesscontrol.AssignRoleInput{TenantID: tid, UserID: mid, RoleID: admin}, aid, app.AuditContext{}))
		wantForbidden(t, "SetUserRoles [admin]", f.svc.SetUserRoles(ctx,
			accesscontrol.SetUserRolesInput{TenantID: tid, UserID: mid, RoleIDs: []string{admin}}, aid, app.AuditContext{}))
		_, err := f.svc.BulkAssignRoleToUsers(ctx,
			accesscontrol.BulkAssignRoleToUsersInput{TenantID: tid, RoleID: admin, UserIDs: []string{mid}}, aid, app.AuditContext{})
		wantForbidden(t, "BulkAssign admin", err)
		wantForbidden(t, "GrantExactRoles [admin] (create user)", f.svc.GrantExactRoles(ctx, tid, mid, []string{admin}, aid, app.AuditContext{}))
		if f.repo.has(f.member, role.AdminRoleID) {
			t.Fatal("the member ended up an administrator")
		}
	})

	t.Run("owner may make a member an administrator", func(t *testing.T) {
		f := newCeilingFixture(t)
		if err := f.svc.AssignRole(ctx, accesscontrol.AssignRoleInput{TenantID: f.tenant.String(), UserID: f.member.String(), RoleID: admin},
			f.owner.String(), app.AuditContext{}); err != nil {
			t.Fatalf("owner grants admin: %v", err)
		}
	})

	t.Run("an administrator editing their own set keeps the admin role", func(t *testing.T) {
		f := newCeilingFixture(t)
		aid := f.admin.String()
		if err := f.svc.SetUserRoles(ctx, accesscontrol.SetUserRolesInput{TenantID: f.tenant.String(), UserID: aid,
			RoleIDs: []string{admin, role.ViewerRoleID.String()}}, aid, app.AuditContext{}); err != nil {
			t.Fatalf("admin keeps own admin role: %v", err)
		}
	})
}
