package unit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app"

	"github.com/openctemio/openctem/api/internal/app/accesscontrol"
	"github.com/openctemio/openctem/api/pkg/domain/role"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// An administrator could set their own roles to [owner] and then pass the
// owner-only routes: the handler's anti-escalation check lets administrators
// through and the service did not look at who was granting what. The role set
// a user can hand out is now bounded by their own grants, in the service.

// ceilingRepo is a role repository that tracks each user's role set.
type ceilingRepo struct {
	role.Repository
	roles map[string]*role.Role
	sets  map[string][]role.ID // user id -> role ids (single tenant)
}

func newCeilingRepo(rs ...*role.Role) *ceilingRepo {
	c := &ceilingRepo{roles: map[string]*role.Role{}, sets: map[string][]role.ID{}}
	for _, r := range rs {
		c.roles[r.ID().String()] = r
	}
	return c
}

func (c *ceilingRepo) GetByID(_ context.Context, _ role.ID, id role.ID) (*role.Role, error) {
	if r, ok := c.roles[id.String()]; ok {
		return r, nil
	}
	return nil, role.ErrRoleNotFound
}

func (c *ceilingRepo) GetUserRoles(_ context.Context, _, uid role.ID) ([]*role.Role, error) {
	out := []*role.Role{}
	for _, id := range c.sets[uid.String()] {
		out = append(out, c.roles[id.String()])
	}
	return out, nil
}

func (c *ceilingRepo) GetUserPermissions(_ context.Context, _, uid role.ID) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, id := range c.sets[uid.String()] {
		for _, p := range c.roles[id.String()].Permissions() {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	return out, nil
}

func (c *ceilingRepo) AssignRole(_ context.Context, _, uid, rid role.ID, _ *role.ID) error {
	c.sets[uid.String()] = append(c.sets[uid.String()], rid)
	return nil
}

func (c *ceilingRepo) RemoveRole(_ context.Context, _, uid, rid role.ID) error {
	var keep []role.ID
	for _, id := range c.sets[uid.String()] {
		if id != rid {
			keep = append(keep, id)
		}
	}
	c.sets[uid.String()] = keep
	return nil
}

func (c *ceilingRepo) SetUserRoles(_ context.Context, _, uid role.ID, ids []role.ID, _ *role.ID) error {
	c.sets[uid.String()] = append([]role.ID(nil), ids...)
	return nil
}

func (c *ceilingRepo) BulkAssignRoleToUsers(_ context.Context, _, rid role.ID, uids []role.ID, _ *role.ID) error {
	for _, u := range uids {
		c.sets[u.String()] = append(c.sets[u.String()], rid)
	}
	return nil
}

func (c *ceilingRepo) GetBySlug(context.Context, *role.ID, string) (*role.Role, error) {
	return nil, role.ErrRoleNotFound
}

func (c *ceilingRepo) Create(_ context.Context, r *role.Role) error {
	c.roles[r.ID().String()] = r
	return nil
}

func (c *ceilingRepo) Update(_ context.Context, r *role.Role) error {
	c.roles[r.ID().String()] = r
	return nil
}

func (c *ceilingRepo) Delete(_ context.Context, _ role.ID, id role.ID) error {
	delete(c.roles, id.String())
	return nil
}

func (c *ceilingRepo) has(uid role.ID, rid role.ID) bool {
	for _, id := range c.sets[uid.String()] {
		if id == rid {
			return true
		}
	}
	return false
}

type ceilingMembers struct{ owners map[string]bool }

func (m ceilingMembers) GetMembership(_ context.Context, uid, tid shared.ID) (*tenant.Membership, error) {
	r := tenant.RoleMember
	if m.owners[uid.String()] {
		r = tenant.RoleOwner
	}
	return tenant.NewMembership(uid, tid, r, nil)
}

type ceilingFixture struct {
	svc                    *accesscontrol.RoleService
	repo                   *ceilingRepo
	tenant                 role.ID
	owner, admin, member   role.ID
	ownerR, adminR, viewer *role.Role
	analyst                *role.Role // custom role with an owner-only permission
}

func sysRole(id role.ID, slug string, fullData bool, perms ...string) *role.Role {
	now := time.Now()
	return role.Reconstruct(id, nil, slug, slug, "", true, 0, fullData, perms, now, now, nil)
}

func newCeilingFixture(t *testing.T) *ceilingFixture {
	t.Helper()
	f := &ceilingFixture{tenant: role.NewID(), owner: role.NewID(), admin: role.NewID(), member: role.NewID()}
	f.ownerR = sysRole(role.OwnerRoleID, "owner", true, "team:delete", "roles:assign", "assets:read", "groups:delete")
	f.adminR = sysRole(role.AdminRoleID, "admin", true, "roles:assign", "assets:read")
	f.viewer = sysRole(role.ViewerRoleID, "viewer", false, "assets:read")
	f.analyst = role.New(f.tenant, "analyst", "Analyst", "", 10, false, []string{"assets:read", "team:delete"}, role.NewID())
	f.repo = newCeilingRepo(f.ownerR, f.adminR, f.viewer, f.analyst)
	f.repo.sets[f.owner.String()] = []role.ID{role.OwnerRoleID}
	f.repo.sets[f.admin.String()] = []role.ID{role.AdminRoleID}
	f.repo.sets[f.member.String()] = []role.ID{role.ViewerRoleID}
	f.svc = accesscontrol.NewRoleService(f.repo, newMockPermissionRepo(), logger.NewNop(),
		accesscontrol.WithRoleMembershipReader(ceilingMembers{owners: map[string]bool{f.owner.String(): true}}))
	return f
}

func wantForbidden(t *testing.T, what string, err error) {
	t.Helper()
	if !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("%s: want forbidden, got %v", what, err)
	}
}

func TestGrantCeiling_AdminCannotMakeThemselfOwner(t *testing.T) {
	f := newCeilingFixture(t)
	ctx := context.Background()
	tid, aid := f.tenant.String(), f.admin.String()

	wantForbidden(t, "SetUserRoles self -> [owner]", f.svc.SetUserRoles(ctx,
		accesscontrol.SetUserRolesInput{TenantID: tid, UserID: aid, RoleIDs: []string{role.OwnerRoleID.String()}}, aid, app.AuditContext{}))
	wantForbidden(t, "AssignRole self owner", f.svc.AssignRole(ctx,
		accesscontrol.AssignRoleInput{TenantID: tid, UserID: aid, RoleID: role.OwnerRoleID.String()}, aid, app.AuditContext{}))
	_, err := f.svc.BulkAssignRoleToUsers(ctx,
		accesscontrol.BulkAssignRoleToUsersInput{TenantID: tid, RoleID: role.OwnerRoleID.String(), UserIDs: []string{aid}}, aid, app.AuditContext{})
	wantForbidden(t, "BulkAssign owner -> self", err)

	if f.repo.has(f.admin, role.OwnerRoleID) {
		t.Fatal("the admin ended up with the owner role")
	}
}

func TestGrantCeiling_AdminCannotGrantRoleAboveTheirOwn(t *testing.T) {
	f := newCeilingFixture(t)
	ctx := context.Background()
	tid, aid := f.tenant.String(), f.admin.String()

	wantForbidden(t, "owner to another user", f.svc.AssignRole(ctx,
		accesscontrol.AssignRoleInput{TenantID: tid, UserID: f.member.String(), RoleID: role.OwnerRoleID.String()}, aid, app.AuditContext{}))
	wantForbidden(t, "custom role with an owner-only permission", f.svc.AssignRole(ctx,
		accesscontrol.AssignRoleInput{TenantID: tid, UserID: aid, RoleID: f.analyst.ID().String()}, aid, app.AuditContext{}))
	wantForbidden(t, "set member roles incl. that custom role", f.svc.SetUserRoles(ctx,
		accesscontrol.SetUserRolesInput{TenantID: tid, UserID: f.member.String(), RoleIDs: []string{f.analyst.ID().String()}}, aid, app.AuditContext{}))
}

func TestGrantCeiling_AdminCannotCreateOrWidenRoleBeyondTheirOwn(t *testing.T) {
	f := newCeilingFixture(t)
	ctx := context.Background()
	_, err := f.svc.CreateRole(ctx, accesscontrol.CreateRoleInput{
		TenantID: f.tenant.String(), Slug: "superuser", Name: "Superuser", Permissions: []string{"team:delete"},
	}, f.admin.String(), app.AuditContext{ActorID: f.admin.String()})
	wantForbidden(t, "create role with team:delete", err)

	widen := []string{"assets:read", "groups:delete"}
	_, err = f.svc.UpdateRole(ctx, f.tenant.String(), f.analyst.ID().String(),
		accesscontrol.UpdateRoleInput{Permissions: widen}, app.AuditContext{ActorID: f.admin.String()})
	wantForbidden(t, "update role to groups:delete", err)
}

func TestGrantCeiling_AdminCannotChangeOwnersRoles(t *testing.T) {
	f := newCeilingFixture(t)
	ctx := context.Background()
	wantForbidden(t, "admin strips the owner", f.svc.SetUserRoles(ctx,
		accesscontrol.SetUserRolesInput{TenantID: f.tenant.String(), UserID: f.owner.String(), RoleIDs: []string{role.ViewerRoleID.String()}},
		f.admin.String(), app.AuditContext{}))
	wantForbidden(t, "admin removes owner role", f.svc.RemoveRole(ctx, f.tenant.String(), f.owner.String(),
		role.OwnerRoleID.String(), app.AuditContext{ActorID: f.admin.String()}))
}

func TestGrantCeiling_AllowedChanges(t *testing.T) {
	f := newCeilingFixture(t)
	ctx := context.Background()
	tid := f.tenant.String()

	// An admin may grant roles within their own grants (but not the admin
	// role itself: only the owner promotes to admin, settings decision B2).
	if err := f.svc.AssignRole(ctx, accesscontrol.AssignRoleInput{TenantID: tid, UserID: f.member.String(), RoleID: role.ViewerRoleID.String()},
		f.admin.String(), app.AuditContext{}); err != nil {
		t.Fatalf("admin grants viewer: %v", err)
	}
	// An owner may grant anything, including the owner role and owner-only permissions.
	if err := f.svc.AssignRole(ctx, accesscontrol.AssignRoleInput{TenantID: tid, UserID: f.member.String(), RoleID: f.analyst.ID().String()},
		f.owner.String(), app.AuditContext{}); err != nil {
		t.Fatalf("owner grants custom role: %v", err)
	}
	if err := f.svc.AssignRole(ctx, accesscontrol.AssignRoleInput{TenantID: tid, UserID: f.member.String(), RoleID: role.OwnerRoleID.String()},
		f.owner.String(), app.AuditContext{}); err != nil {
		t.Fatalf("owner grants owner: %v", err)
	}
	// The tenant's owner keeps the owner role, even if they try to drop it.
	err := f.svc.SetUserRoles(ctx, accesscontrol.SetUserRolesInput{TenantID: tid, UserID: f.owner.String(), RoleIDs: []string{role.AdminRoleID.String()}},
		f.owner.String(), app.AuditContext{})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("owner drops own owner role: want validation error, got %v", err)
	}
	// A system path (no actor) still cannot grant owner.
	wantForbidden(t, "system grant of owner", f.svc.SetUserRoles(ctx,
		accesscontrol.SetUserRolesInput{TenantID: tid, UserID: f.member.String(), RoleIDs: []string{role.OwnerRoleID.String()}}, "", app.AuditContext{}))
}

// Deleting a custom role used to have no ceiling: an administrator (or any
// holder of roles:delete) could remove a role the owner built with
// permissions the administrator does not hold. Delete now uses the same
// subset check as create and update.
func TestGrantCeiling_RoleDelete(t *testing.T) {
	t.Run("admin cannot delete a role carrying an owner-only permission", func(t *testing.T) {
		f := newCeilingFixture(t)
		err := f.svc.DeleteRole(context.Background(), f.tenant.String(), f.analyst.ID().String(),
			app.AuditContext{ActorID: f.admin.String()})
		wantForbidden(t, "admin deletes analyst (team:delete)", err)
		if _, ok := f.repo.roles[f.analyst.ID().String()]; !ok {
			t.Fatal("the role was deleted despite the refusal")
		}
	})

	t.Run("admin cannot delete a role with full data access when they lack it", func(t *testing.T) {
		f := newCeilingFixture(t)
		// A delegated role manager: holds the role permissions but not full data access.
		mgr := role.New(f.tenant, "role-mgr", "Role manager", "", 10, false, []string{"assets:read", "roles:delete"}, role.NewID())
		wide := role.New(f.tenant, "wide", "Wide", "", 10, true, []string{"assets:read"}, role.NewID())
		f.repo.roles[mgr.ID().String()] = mgr
		f.repo.roles[wide.ID().String()] = wide
		uid := role.NewID()
		f.repo.sets[uid.String()] = []role.ID{mgr.ID()}
		err := f.svc.DeleteRole(context.Background(), f.tenant.String(), wide.ID().String(),
			app.AuditContext{ActorID: uid.String()})
		wantForbidden(t, "manager deletes full-data role", err)
	})

	t.Run("admin may delete a role within their own permissions", func(t *testing.T) {
		f := newCeilingFixture(t)
		within := role.New(f.tenant, "reader", "Reader", "", 10, false, []string{"assets:read"}, role.NewID())
		f.repo.roles[within.ID().String()] = within
		if err := f.svc.DeleteRole(context.Background(), f.tenant.String(), within.ID().String(),
			app.AuditContext{ActorID: f.admin.String()}); err != nil {
			t.Fatalf("admin deletes role within their set: %v", err)
		}
		if _, ok := f.repo.roles[within.ID().String()]; ok {
			t.Fatal("the role was not deleted")
		}
	})

	t.Run("owner may delete any custom role", func(t *testing.T) {
		f := newCeilingFixture(t)
		if err := f.svc.DeleteRole(context.Background(), f.tenant.String(), f.analyst.ID().String(),
			app.AuditContext{ActorID: f.owner.String()}); err != nil {
			t.Fatalf("owner deletes analyst: %v", err)
		}
		if _, ok := f.repo.roles[f.analyst.ID().String()]; ok {
			t.Fatal("the role was not deleted")
		}
	})

	t.Run("another tenant's role still reads as not found", func(t *testing.T) {
		f := newCeilingFixture(t)
		err := f.svc.DeleteRole(context.Background(), role.NewID().String(), f.analyst.ID().String(),
			app.AuditContext{ActorID: f.owner.String()})
		if !errors.Is(err, role.ErrRoleNotFound) {
			t.Fatalf("cross-tenant delete: want not found, got %v", err)
		}
	})
}
