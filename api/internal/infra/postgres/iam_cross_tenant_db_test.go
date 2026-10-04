package postgres

// Cross-tenant negatives for the IAM repository primitives (D-11, research/14
// SEC-15). Each case seeds a row in tenant B and drives the primitive as tenant
// A with B's id: the call must answer not-found and leave B's row untouched.
// Before D-11 these statements matched on `WHERE id = $1` alone, so every
// mutation here changed or removed the other tenant's row.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/group"
	"github.com/openctemio/openctem/api/pkg/domain/permissionset"
	"github.com/openctemio/openctem/api/pkg/domain/role"
	"github.com/openctemio/openctem/api/pkg/domain/scimgroup"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

func scalarString(ctx context.Context, t *testing.T, db *DB, q string, args ...any) string {
	t.Helper()
	var s string
	if err := db.QueryRowContext(ctx, q, args...).Scan(&s); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return s
}

func TestIAMRepositories_CrossTenantIsolation(t *testing.T) {
	ctx := context.Background()
	db := openRoleRaceDB(t)
	tenantA := seedTenant(ctx, t, db)
	tenantB := seedTenant(ctx, t, db)

	t.Run("group update and delete", func(t *testing.T) {
		repo := NewGroupRepository(db)
		gid := shared.NewID()
		if _, err := db.ExecContext(ctx,
			`INSERT INTO groups (id, tenant_id, name, slug) VALUES ($1, $2, 'B team', $3)`,
			gid.String(), tenantB.String(), "b-"+gid.String()); err != nil {
			t.Fatalf("seed group: %v", err)
		}
		if _, err := repo.GetByTenantAndID(ctx, tenantA, gid); !errors.Is(err, shared.ErrNotFound) {
			t.Fatalf("read as A: want not found, got %v", err)
		}
		forged := group.Reconstitute(gid, tenantA, "pwned", "pwned-"+gid.String(), "", group.GroupTypeTeam,
			nil, nil, group.GroupSettings{}, group.NotificationConfig{}, nil, true, time.Now(), time.Now())
		if err := repo.Update(ctx, forged); !errors.Is(err, group.ErrGroupNotFound) {
			t.Fatalf("update as A: want ErrGroupNotFound, got %v", err)
		}
		if err := repo.Delete(ctx, tenantA, gid); !errors.Is(err, group.ErrGroupNotFound) {
			t.Fatalf("delete as A: want ErrGroupNotFound, got %v", err)
		}
		if name := scalarString(ctx, t, db, `SELECT name FROM groups WHERE id = $1`, gid.String()); name != "B team" {
			t.Fatalf("B's group changed: name=%q", name)
		}
		if err := repo.Delete(ctx, tenantB, gid); err != nil {
			t.Fatalf("delete as owner: %v", err)
		}
	})

	t.Run("role read, update and delete", func(t *testing.T) {
		repo := NewRoleRepository(db)
		rid := seedRole(ctx, t, db, tenantB, false)
		roleID := role.MustParseID(rid.String())
		asA := role.MustParseID(tenantA.String())
		if _, err := repo.GetByID(ctx, asA, roleID); !errors.Is(err, role.ErrRoleNotFound) {
			t.Fatalf("read as A: want ErrRoleNotFound, got %v", err)
		}
		forged := role.Reconstruct(roleID, &asA, "pwned", "pwned", "", false, 10, true, nil, time.Now(), time.Now(), nil)
		if err := repo.Update(ctx, forged); !errors.Is(err, role.ErrRoleNotFound) {
			t.Fatalf("update as A: want ErrRoleNotFound, got %v", err)
		}
		if err := repo.Delete(ctx, asA, roleID); !errors.Is(err, role.ErrRoleNotFound) {
			t.Fatalf("delete as A: want ErrRoleNotFound, got %v", err)
		}
		if !roleExists(ctx, t, db, rid) {
			t.Fatal("B's role was deleted")
		}
		if got := scalarString(ctx, t, db, `SELECT name FROM roles WHERE id = $1`, rid.String()); got == "pwned" {
			t.Fatal("B's role was renamed")
		}
		// A system role (tenant_id NULL) stays readable by every tenant.
		if _, err := repo.GetByID(ctx, asA, role.OwnerRoleID); err != nil {
			t.Fatalf("system role must stay readable: %v", err)
		}
	})

	t.Run("permission set read, update and delete", func(t *testing.T) {
		repo := NewPermissionSetRepository(db)
		psID := shared.NewID()
		if _, err := db.ExecContext(ctx,
			`INSERT INTO permission_sets (id, tenant_id, name, slug, set_type) VALUES ($1, $2, 'B set', $3, 'custom')`,
			psID.String(), tenantB.String(), "b-"+psID.String()); err != nil {
			t.Fatalf("seed permission set: %v", err)
		}
		t.Cleanup(func() {
			_, _ = db.ExecContext(context.Background(), `DELETE FROM permission_sets WHERE id = $1`, psID.String())
		})
		if _, err := repo.GetByID(ctx, tenantA, psID); !errors.Is(err, permissionset.ErrPermissionSetNotFound) {
			t.Fatalf("read as A: want not found, got %v", err)
		}
		if _, err := repo.GetInheritanceChain(ctx, tenantA, psID); err != nil {
			t.Fatalf("chain as A: %v", err)
		} else if chain, _ := repo.GetInheritanceChain(ctx, tenantA, psID); len(chain) != 0 {
			t.Fatalf("chain as A must be empty, got %d", len(chain))
		}
		forged := permissionset.Reconstitute(psID, &tenantA, "pwned", "pwned-"+psID.String(), "",
			permissionset.SetTypeCustom, nil, nil, true, time.Now(), time.Now())
		if err := repo.Update(ctx, forged); !errors.Is(err, permissionset.ErrPermissionSetNotFound) {
			t.Fatalf("update as A: want not found, got %v", err)
		}
		if err := repo.Delete(ctx, tenantA, psID); !errors.Is(err, permissionset.ErrPermissionSetNotFound) {
			t.Fatalf("delete as A: want not found, got %v", err)
		}
		if name := scalarString(ctx, t, db, `SELECT name FROM permission_sets WHERE id = $1`, psID.String()); name != "B set" {
			t.Fatalf("B's permission set changed: name=%q", name)
		}
	})

	t.Run("membership read, update and delete", func(t *testing.T) {
		repo := NewTenantRepository(db)
		uid := seedUser(ctx, t, db)
		mid := shared.NewID()
		if _, err := db.ExecContext(ctx,
			`INSERT INTO tenant_members (id, user_id, tenant_id, role) VALUES ($1, $2, $3, 'member')`,
			mid.String(), uid.String(), tenantB.String()); err != nil {
			t.Fatalf("seed membership: %v", err)
		}
		if _, err := repo.GetMembershipByID(ctx, tenantA, mid); !errors.Is(err, shared.ErrNotFound) {
			t.Fatalf("read as A: want not found, got %v", err)
		}
		forged := tenant.ReconstituteMembership(mid, uid, tenantA, tenant.RoleAdmin, nil, time.Now())
		if err := repo.UpdateMembership(ctx, forged); !errors.Is(err, shared.ErrNotFound) {
			t.Fatalf("update role as A: want not found, got %v", err)
		}
		if err := forged.Suspend(shared.NewID()); err == nil {
			if err := repo.UpdateMembershipStatus(ctx, forged); !errors.Is(err, shared.ErrNotFound) {
				t.Fatalf("suspend as A: want not found, got %v", err)
			}
		}
		if err := repo.DeleteMembership(ctx, tenantA, mid); !errors.Is(err, shared.ErrNotFound) {
			t.Fatalf("delete as A: want not found, got %v", err)
		}
		var n int
		if err := db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM tenant_members WHERE id = $1 AND COALESCE(status, 'active') = 'active'`,
			mid.String()).Scan(&n); err != nil || n != 1 {
			t.Fatalf("B's membership changed (rows=%d, err=%v)", n, err)
		}
	})

	t.Run("invitation read, update and delete", func(t *testing.T) {
		repo := NewTenantRepository(db)
		inviter := seedUser(ctx, t, db)
		invID := shared.NewID()
		if _, err := db.ExecContext(ctx,
			`INSERT INTO tenant_invitations (id, tenant_id, email, role, token, invited_by, expires_at)
			 VALUES ($1, $2, $3, 'member', $4, $5, NOW() + INTERVAL '1 day')`,
			invID.String(), tenantB.String(), "inv-"+invID.String()+"@example.com", "tok-"+invID.String(), inviter.String()); err != nil {
			t.Fatalf("seed invitation: %v", err)
		}
		if _, err := repo.GetInvitationByID(ctx, tenantA, invID); !errors.Is(err, shared.ErrNotFound) {
			t.Fatalf("read as A: want not found, got %v", err)
		}
		now := time.Now()
		forged := tenant.ReconstituteInvitation(invID, tenantA, "x@example.com", tenant.RoleMember, nil,
			"attacker-token", inviter, now.Add(time.Hour), &now, now)
		if err := repo.UpdateInvitation(ctx, forged); !errors.Is(err, shared.ErrNotFound) {
			t.Fatalf("update as A: want not found, got %v", err)
		}
		if err := repo.DeleteInvitation(ctx, tenantA, invID); !errors.Is(err, shared.ErrNotFound) {
			t.Fatalf("delete as A: want not found, got %v", err)
		}
		if tok := scalarString(ctx, t, db, `SELECT token FROM tenant_invitations WHERE id = $1`, invID.String()); tok != "tok-"+invID.String() {
			t.Fatalf("B's invitation token was rewritten: %q", tok)
		}
		if err := repo.DeleteInvitation(ctx, tenantB, invID); err != nil {
			t.Fatalf("delete as owner: %v", err)
		}
	})

	t.Run("scim group membership", func(t *testing.T) {
		repo := NewScimGroupRepository(db)
		member := seedUser(ctx, t, db)
		intruder := seedUser(ctx, t, db)
		gid := shared.NewID()
		if _, err := db.ExecContext(ctx,
			`INSERT INTO scim_groups (id, tenant_id, display_name) VALUES ($1, $2, 'B admins')`,
			gid.String(), tenantB.String()); err != nil {
			t.Fatalf("seed scim group: %v", err)
		}
		if _, err := db.ExecContext(ctx,
			`INSERT INTO scim_group_members (group_id, user_id) VALUES ($1, $2)`,
			gid.String(), member.String()); err != nil {
			t.Fatalf("seed scim member: %v", err)
		}
		members := func() string {
			return scalarString(ctx, t, db,
				`SELECT COALESCE(string_agg(user_id::text, ',' ORDER BY user_id), '') FROM scim_group_members WHERE group_id = $1`,
				gid.String())
		}
		if err := repo.SetMembers(ctx, tenantA, gid, []shared.ID{intruder}); !errors.Is(err, scimgroup.ErrNotFound) {
			t.Fatalf("set members as A: want not found, got %v", err)
		}
		if err := repo.AddMembers(ctx, tenantA, gid, []shared.ID{intruder}); err != nil {
			t.Fatalf("add members as A: %v", err)
		}
		if err := repo.RemoveMembers(ctx, tenantA, gid, []shared.ID{member}); err != nil {
			t.Fatalf("remove members as A: %v", err)
		}
		if got := members(); got != member.String() {
			t.Fatalf("B's scim group membership changed from another tenant: %q", got)
		}
		if err := repo.SetMembers(ctx, tenantB, gid, []shared.ID{intruder}); err != nil {
			t.Fatalf("set members as owner: %v", err)
		}
		if got := members(); got != intruder.String() {
			t.Fatalf("owner set members: got %q", got)
		}
	})
}
