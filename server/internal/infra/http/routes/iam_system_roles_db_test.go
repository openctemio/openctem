package routes

// The team role (owner, admin, member, viewer) is the membership's role. It
// changes only through the membership routes and ownership transfer; the
// Roles API takes custom roles only, and the database refuses an owner role
// row without the owner membership. These tests run against a migrated
// database (they skip without DATABASE_URL).

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/accesscontrol"
	"github.com/openctemio/openctem/api/internal/app/apikey"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	roledom "github.com/openctemio/openctem/api/pkg/domain/role"
	"github.com/openctemio/openctem/api/pkg/logger"
)

var systemRoleIDs = []roledom.ID{roledom.OwnerRoleID, roledom.AdminRoleID, roledom.MemberRoleID, roledom.ViewerRoleID}

func (h *grbHarness) labelAndEffective(user interface{ String() string }) (label, effective string) {
	h.t.Helper()
	_ = h.db.QueryRow(`SELECT role FROM tenant_members WHERE user_id=$1 AND tenant_id=$2`, user.String(), h.tenant.String()).Scan(&label)
	_ = h.db.QueryRow(`SELECT role FROM v_user_effective_role WHERE user_id=$1 AND tenant_id=$2`, user.String(), h.tenant.String()).Scan(&effective)
	return label, effective
}

func (h *grbHarness) ownerRoleHolders() int {
	var n int
	_ = h.db.QueryRow(`SELECT count(*) FROM user_roles WHERE tenant_id=$1 AND role_id=$2`, h.tenant.String(), roledom.OwnerRoleID.String()).Scan(&n)
	return n
}

// Every Roles API path refuses every system role, for an owner actor too.
func TestIAM_RolesAPIRefusesSystemRoles(t *testing.T) {
	h := newGRBHarness(t)
	ctx := context.Background()
	before := h.ownerRoleHolders()
	for _, id := range systemRoleIDs {
		rid := id.String()
		if err := h.roleSvc.AssignRole(ctx, accesscontrol.AssignRoleInput{TenantID: h.tenant.String(), UserID: h.member.String(), RoleID: rid}, h.owner.String(), h.actx(h.owner)); !errors.Is(err, accesscontrol.ErrSystemRoleViaRoles) {
			t.Errorf("AssignRole(%s): %v", rid, err)
		}
		if err := h.roleSvc.SetUserRoles(ctx, accesscontrol.SetUserRolesInput{TenantID: h.tenant.String(), UserID: h.member.String(), RoleIDs: []string{h.analyst.String(), rid}}, h.owner.String(), h.actx(h.owner)); !errors.Is(err, accesscontrol.ErrSystemRoleViaRoles) {
			t.Errorf("SetUserRoles(%s): %v", rid, err)
		}
		if _, err := h.roleSvc.BulkAssignRoleToUsers(ctx, accesscontrol.BulkAssignRoleToUsersInput{TenantID: h.tenant.String(), RoleID: rid, UserIDs: []string{h.member.String()}}, h.owner.String(), h.actx(h.owner)); !errors.Is(err, accesscontrol.ErrSystemRoleViaRoles) {
			t.Errorf("BulkAssignRoleToUsers(%s): %v", rid, err)
		}
		if err := h.roleSvc.RemoveRole(ctx, h.tenant.String(), h.admin.String(), rid, h.actx(h.owner)); !errors.Is(err, accesscontrol.ErrSystemRoleViaRoles) {
			t.Errorf("RemoveRole(%s): %v", rid, err)
		}
	}
	if got := h.ownerRoleHolders(); got != before {
		t.Fatalf("owner role holders changed from %d to %d", before, got)
	}
	// A custom role still works through the same paths.
	if err := h.roleSvc.AssignRole(ctx, accesscontrol.AssignRoleInput{TenantID: h.tenant.String(), UserID: h.member.String(), RoleID: h.analyst.String()}, h.owner.String(), h.actx(h.owner)); err != nil {
		t.Fatalf("custom role: %v", err)
	}
	// Another tenant's custom role is not available here.
	if err := h.roleSvc.AssignRole(ctx, accesscontrol.AssignRoleInput{TenantID: h.tenant.String(), UserID: h.member.String(), RoleID: h.foreign.String()}, h.owner.String(), h.actx(h.owner)); err == nil {
		t.Fatal("a foreign tenant's role was assigned")
	}
}

// Replacing a user's custom roles never touches the team role they hold.
func TestIAM_SetUserRolesKeepsTheTeamRole(t *testing.T) {
	h := newGRBHarness(t)
	ctx := context.Background()
	h.exec(`UPDATE tenant_members SET role='admin' WHERE user_id=$1 AND tenant_id=$2`, h.admin.String(), h.tenant.String())
	if err := h.roleSvc.SetUserRoles(ctx, accesscontrol.SetUserRolesInput{TenantID: h.tenant.String(), UserID: h.admin.String(), RoleIDs: []string{h.analyst.String()}}, h.owner.String(), h.actx(h.owner)); err != nil {
		t.Fatal(err)
	}
	label, effective := h.labelAndEffective(h.admin)
	if label != "admin" || effective != "admin" {
		t.Fatalf("after a custom-role change label=%q effective=%q, want admin/admin", label, effective)
	}
	if err := h.roleSvc.SetUserRoles(ctx, accesscontrol.SetUserRolesInput{TenantID: h.tenant.String(), UserID: h.admin.String(), RoleIDs: []string{h.secretReader.String()}}, h.owner.String(), h.actx(h.owner)); err != nil {
		t.Fatal(err)
	}
	roles, _ := h.roles.GetUserRoles(ctx, rid(h.tenant), rid(h.admin))
	var hasAdmin, hasAnalyst bool
	for _, r := range roles {
		hasAdmin = hasAdmin || r.ID() == roledom.AdminRoleID
		hasAnalyst = hasAnalyst || r.ID() == rid(h.analyst)
	}
	if !hasAdmin || hasAnalyst {
		t.Fatalf("roles after replace: admin kept=%v, old custom role kept=%v", hasAdmin, hasAnalyst)
	}
}

// The label and the effective role agree after a demotion through the
// membership route (the label is what that route writes; the trigger moves the
// system role with it).
func TestIAM_MembershipDemotionKeepsLabelAndEffectiveRoleTogether(t *testing.T) {
	h := newGRBHarness(t)
	h.exec(`UPDATE tenant_members SET role='admin' WHERE user_id=$1 AND tenant_id=$2`, h.admin.String(), h.tenant.String())
	if l, e := h.labelAndEffective(h.admin); l != "admin" || e != "admin" {
		t.Fatalf("admin: label=%q effective=%q", l, e)
	}
	h.exec(`UPDATE tenant_members SET role='viewer' WHERE user_id=$1 AND tenant_id=$2`, h.admin.String(), h.tenant.String())
	l, e := h.labelAndEffective(h.admin)
	if l != e || e != "viewer" {
		t.Fatalf("after demotion label=%q effective=%q", l, e)
	}
}

// A co-owner cannot be planted: the Roles API refuses the owner role, and the
// database refuses an owner role row without the owner membership.
func TestIAM_OwnerRoleNeedsTheOwnerMembership(t *testing.T) {
	h := newGRBHarness(t)
	ctx := context.Background()
	h.exec(`UPDATE tenant_members SET role='admin' WHERE user_id=$1 AND tenant_id=$2`, h.admin.String(), h.tenant.String())

	// A direct write is refused with a check violation.
	_, err := h.db.Exec(`INSERT INTO user_roles (user_id, tenant_id, role_id) VALUES ($1, $2, $3)`, h.admin.String(), h.tenant.String(), roledom.OwnerRoleID.String())
	if err == nil {
		t.Fatal("the database let an admin member hold the owner role")
	}
	// Also when the row exists and is moved onto another user.
	if _, err := h.db.Exec(`UPDATE user_roles SET user_id = $1 WHERE tenant_id = $2 AND role_id = $3 AND user_id = $4`,
		h.admin.String(), h.tenant.String(), roledom.OwnerRoleID.String(), h.owner.String()); err == nil {
		t.Fatal("the database let the owner role row move to a non-owner")
	}
	// The label change is the way in, and out: the existing sync trigger adds and removes the row.
	h.exec(`UPDATE tenant_members SET role='owner' WHERE user_id=$1 AND tenant_id=$2`, h.admin.String(), h.tenant.String())
	if l, e := h.labelAndEffective(h.admin); l != "owner" || e != "owner" {
		t.Fatalf("owner membership: label=%q effective=%q", l, e)
	}
	h.exec(`UPDATE tenant_members SET role='member' WHERE user_id=$1 AND tenant_id=$2`, h.admin.String(), h.tenant.String())
	if l, e := h.labelAndEffective(h.admin); l != "member" || e != "member" {
		t.Fatalf("after leaving owner: label=%q effective=%q", l, e)
	}
	// The service refuses it too, for the actual owner.
	if err := h.roleSvc.AssignRole(ctx, accesscontrol.AssignRoleInput{TenantID: h.tenant.String(), UserID: h.admin.String(), RoleID: roledom.OwnerRoleID.String()}, h.owner.String(), h.actx(h.owner)); !errors.Is(err, accesscontrol.ErrSystemRoleViaRoles) {
		t.Fatalf("AssignRole(owner): %v", err)
	}
}

// Rows that already break the rule (a co-owner planted before the check) are
// left alone by the migration: other writes to them keep working, so the
// owner can decide, and the report query finds them.
func TestIAM_ExistingOwnerRoleDriftIsReportedNotStripped(t *testing.T) {
	h := newGRBHarness(t)
	admin := testdb.OpenAdmin(t)
	ctx := context.Background()
	h.exec(`UPDATE tenant_members SET role='admin' WHERE user_id=$1 AND tenant_id=$2`, h.admin.String(), h.tenant.String())
	// Plant the drift the way it existed before: the check bypassed.
	tx, err := admin.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`SET LOCAL session_replication_role = replica`); err != nil {
		_ = tx.Rollback()
		t.Skipf("cannot bypass triggers (needs a superuser): %v", err)
	}
	if _, err := tx.Exec(`INSERT INTO user_roles (user_id, tenant_id, role_id) VALUES ($1, $2, $3)`, h.admin.String(), h.tenant.String(), roledom.OwnerRoleID.String()); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	// An unrelated update of the drifted row still works.
	h.exec(`UPDATE user_roles SET assigned_at = now() WHERE user_id=$1 AND tenant_id=$2 AND role_id=$3`, h.admin.String(), h.tenant.String(), roledom.OwnerRoleID.String())
	// The documented report query lists exactly this user.
	var n int
	if err := h.db.QueryRow(driftReportSQL+` AND ur.tenant_id = $1`, h.tenant.String()).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("report query found %d drifted rows in the tenant, want 1", n)
	}
	// The real owner is not in the report.
	h.exec(`UPDATE tenant_members SET role='owner' WHERE user_id=$1 AND tenant_id=$2`, h.owner.String(), h.tenant.String())
	if err := h.db.QueryRow(driftReportSQL+` AND ur.tenant_id = $1`, h.tenant.String()).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("report query found %d drifted rows after the owner label was set, want 1", n)
	}
}

// driftReportSQL is the report query documented in
// docs/architecture/authorization-matrix.md.
const driftReportSQL = `SELECT count(*) FROM user_roles ur
	JOIN tenant_members tm ON tm.user_id = ur.user_id AND tm.tenant_id = ur.tenant_id
	WHERE ur.role_id = '00000000-0000-0000-0000-000000000001' AND tm.role <> 'owner'`

// With the production membership reader wired, the owner keeps the owner role
// and nothing on the Roles API removes it.
func TestIAM_OwnerKeepsTheOwnerRole(t *testing.T) {
	h := newGRBHarness(t)
	db := &postgres.DB{DB: h.db}
	tenants := postgres.NewTenantRepository(db)
	roleSvc := accesscontrol.NewRoleService(h.roles, postgres.NewPermissionRepository(db), loggerNop(), accesscontrol.WithRoleMembershipReader(tenants))
	h.exec(`UPDATE tenant_members SET role='owner' WHERE user_id=$1 AND tenant_id=$2`, h.owner.String(), h.tenant.String())
	// The owner keeps the owner role through the Roles API: nothing can take
	// it away there, and nothing can add a second one.
	if err := roleSvc.RemoveRole(context.Background(), h.tenant.String(), h.owner.String(), roledom.OwnerRoleID.String(), h.actx(h.owner)); !errors.Is(err, accesscontrol.ErrSystemRoleViaRoles) {
		t.Fatalf("RemoveRole(owner): %v", err)
	}
	if l, e := h.labelAndEffective(h.owner); l != "owner" || e != "owner" {
		t.Fatalf("owner: label=%q effective=%q", l, e)
	}
}

func loggerNop() *logger.Logger { return logger.NewNop() }

// Proof tests from the IAM authorization audit (research 170), adapted: each
// asserts the secure behavior.

// IAM-3 (system roles change only through the membership): an administrator demoted through the Roles API keeps the membership
// label 'admin'; API keys / MCP tokens then keep every scope.
func TestAuthz170_RBACDemotionLeavesAdminLabel(t *testing.T) {
	h := newGRBHarness(t)
	ctx := context.Background()
	db := &postgres.DB{DB: h.db}
	tenants := postgres.NewTenantRepository(db)
	// h.admin was seeded with label 'member'; make it a real admin (label + role).
	h.exec(`UPDATE tenant_members SET role='admin' WHERE user_id=$1 AND tenant_id=$2`, h.admin.String(), h.tenant.String())
	// The owner removes the admin role on the Roles page (DELETE /users/{id}/roles/{admin}).
	if err := h.roleSvc.RemoveRole(ctx, h.tenant.String(), h.admin.String(), roledom.AdminRoleID.String(), h.actx(h.owner)); !errors.Is(err, accesscontrol.ErrSystemRoleViaRoles) {
		t.Fatalf("the Roles API must refuse to remove a system role: %v", err)
	}
	// The way to demote is the membership route, which writes the label.
	h.exec(`UPDATE tenant_members SET role='viewer' WHERE user_id=$1 AND tenant_id=$2`, h.admin.String(), h.tenant.String())
	var label, effective string
	_ = h.db.QueryRow(`SELECT role FROM tenant_members WHERE user_id=$1 AND tenant_id=$2`, h.admin.String(), h.tenant.String()).Scan(&label)
	_ = h.db.QueryRow(`SELECT role FROM v_user_effective_role WHERE user_id=$1 AND tenant_id=$2`, h.admin.String(), h.tenant.String()).Scan(&effective)
	t.Logf("after RBAC demotion: tenant_members.role=%q v_user_effective_role=%q perms=%v", label, effective, h.perms(h.admin))
	holder := apikey.NewHolderPermissions(tenants, permSrc{h.roles})
	all, _, err := holder.HeldPermissions(ctx, h.tenant, h.admin)
	if err != nil {
		t.Fatal(err)
	}
	// HeldPermissions reads the effective role (good). The raw label is what
	// the approver/notification queries read.
	var rawAdmins int
	_ = h.db.QueryRow(`SELECT count(*) FROM tenant_members tm WHERE tm.tenant_id=$1 AND tm.status='active' AND tm.role IN ('owner','admin') AND tm.user_id=$2`, h.tenant.String(), h.admin.String()).Scan(&rawAdmins)
	if label != effective {
		t.Fatalf("IAM-3 (system roles change only through the membership): after RBAC demotion label=%q effective=%q; holder all=%v; raw-label approver/notification queries still count this user as owner/admin: %d", label, effective, all, rawAdmins)
	}
}

type permSrc struct{ r *postgres.RoleRepository }

func (p permSrc) GetPermissionsWithFallback(ctx context.Context, tenantID, userID string) ([]string, error) {
	return p.r.GetUserPermissions(ctx, roledom.MustParseID(tenantID), roledom.MustParseID(userID))
}

// IAM-4: the owner role is grantable through the Roles API; it survives a
// membership demotion and its holder can mint further owners.
func TestAuthz170_OwnerRoleViaRBACSurvivesDemotion(t *testing.T) {
	h := newGRBHarness(t)
	ctx := context.Background()
	h.exec(`UPDATE tenant_members SET role='admin' WHERE user_id=$1 AND tenant_id=$2`, h.admin.String(), h.tenant.String())
	err := h.roleSvc.AssignRole(ctx, accesscontrol.AssignRoleInput{TenantID: h.tenant.String(), UserID: h.admin.String(), RoleID: roledom.OwnerRoleID.String()}, h.owner.String(), h.actx(h.owner))
	if err != nil {
		t.Logf("owner role not grantable via RBAC (good): %v", err)
		return
	}
	var effective, label string
	_ = h.db.QueryRow(`SELECT role FROM v_user_effective_role WHERE user_id=$1 AND tenant_id=$2`, h.admin.String(), h.tenant.String()).Scan(&effective)
	_ = h.db.QueryRow(`SELECT role FROM tenant_members WHERE user_id=$1 AND tenant_id=$2`, h.admin.String(), h.tenant.String()).Scan(&label)
	// The new co-owner mints a third owner from a viewer, no consent, no transfer.
	err2 := h.roleSvc.AssignRole(ctx, accesscontrol.AssignRoleInput{TenantID: h.tenant.String(), UserID: h.member.String(), RoleID: roledom.OwnerRoleID.String()}, h.admin.String(), h.actx(h.admin))
	var owners, rawOwners int
	_ = h.db.QueryRow(`SELECT count(*) FROM user_roles WHERE tenant_id=$1 AND role_id=$2`, h.tenant.String(), roledom.OwnerRoleID.String()).Scan(&owners)
	_ = h.db.QueryRow(`SELECT count(*) FROM tenant_members WHERE tenant_id=$1 AND role='owner'`, h.tenant.String()).Scan(&rawOwners)
	t.Fatalf("IAM-4: owner role granted via POST /users/{id}/roles: effective=%q label=%q; co-owner grants owner to a viewer: err=%v; owner-role holders=%d, raw-label owners=%d", effective, label, err2, owners, rawOwners)
}

// IAM-4b: with the production membership reader wired, the real owner cannot
// take back an owner role planted through the Roles API.
func TestAuthz170_PlantedOwnerIsIrremovable(t *testing.T) {
	h := newGRBHarness(t)
	ctx := context.Background()
	db := &postgres.DB{DB: h.db}
	tenants := postgres.NewTenantRepository(db)
	roleSvc := accesscontrol.NewRoleService(h.roles, postgres.NewPermissionRepository(db), loggerNop(), accesscontrol.WithRoleMembershipReader(tenants))
	// The real owner: label owner too.
	h.exec(`UPDATE tenant_members SET role='owner' WHERE user_id=$1 AND tenant_id=$2`, h.owner.String(), h.tenant.String())
	h.exec(`UPDATE tenant_members SET role='admin' WHERE user_id=$1 AND tenant_id=$2`, h.admin.String(), h.tenant.String())
	if err := roleSvc.AssignRole(ctx, accesscontrol.AssignRoleInput{TenantID: h.tenant.String(), UserID: h.admin.String(), RoleID: roledom.OwnerRoleID.String()}, h.owner.String(), h.actx(h.owner)); err != nil {
		t.Logf("owner role not grantable (good): %v", err)
		return
	}
	errRemove := roleSvc.RemoveRole(ctx, h.tenant.String(), h.admin.String(), roledom.OwnerRoleID.String(), h.actx(h.owner))
	errSet := roleSvc.SetUserRoles(ctx, accesscontrol.SetUserRolesInput{TenantID: h.tenant.String(), UserID: h.admin.String(), RoleIDs: []string{roledom.MemberRoleID.String()}}, h.owner.String(), h.actx(h.owner))
	m, _ := tenants.GetMembership(ctx, h.admin, h.tenant)
	t.Fatalf("IAM-4b: planted co-owner: effective role %q; real owner RemoveRole(owner) err=%v; SetUserRoles([member]) err=%v", m.Role(), errRemove, errSet)
}
