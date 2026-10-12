package routes

// Team role bindings (decisions G1-G12) against a migrated database: a custom role
// bound to a team is held by its active members (v_user_role_grants), and
// every way of handing it out is a grant under the same rules as giving the
// role directly.

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/accesscontrol"
	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/group"
	roledom "github.com/openctemio/openctem/api/pkg/domain/role"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type grbHarness struct {
	t                                        *testing.T
	db                                       *sql.DB
	roles                                    *postgres.RoleRepository
	groups                                   *accesscontrol.GroupService
	roleSvc                                  *accesscontrol.RoleService
	tenant, other                            shared.ID
	owner, admin, lead, member, outsider     shared.ID
	team, otherTeam                          shared.ID
	analyst, secretReader, fullData, foreign shared.ID
}

func (h *grbHarness) exec(q string, args ...any) {
	h.t.Helper()
	if _, err := h.db.ExecContext(context.Background(), q, args...); err != nil {
		h.t.Fatalf("seed %q: %v", q, err)
	}
}

func (h *grbHarness) user(tenant shared.ID, kind string, systemRole string) shared.ID {
	id := shared.NewID()
	h.exec(`INSERT INTO users (id, email) VALUES ($1, $2)`, id.String(), "grb-"+id.String()+"@example.com")
	if kind == "external" {
		h.exec(`INSERT INTO tenant_members (user_id, tenant_id, role, kind, expires_at) VALUES ($1, $2, 'viewer', 'external', now() + interval '30 days')`, id.String(), tenant.String())
	} else {
		h.exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, 'member')`, id.String(), tenant.String())
	}
	// The membership trigger grants the label role; start from no role.
	h.exec(`DELETE FROM user_roles WHERE user_id = $1 AND tenant_id = $2`, id.String(), tenant.String())
	if systemRole != "" {
		h.exec(`INSERT INTO user_roles (user_id, tenant_id, role_id) VALUES ($1, $2, $3)`, id.String(), tenant.String(), systemRole)
	}
	h.t.Cleanup(func() { _, _ = h.db.Exec(`DELETE FROM users WHERE id = $1`, id.String()) })
	return id
}

func (h *grbHarness) customRole(tenant shared.ID, slug string, fullData bool, perms ...string) shared.ID {
	id := shared.NewID()
	h.exec(`INSERT INTO roles (id, tenant_id, slug, name, is_system, hierarchy_level, has_full_data_access) VALUES ($1, $2, $3, $3, false, 10, $4)`,
		id.String(), tenant.String(), slug, fullData)
	for _, p := range perms {
		h.exec(`INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)`, id.String(), p)
	}
	return id
}

func (h *grbHarness) newTeam(tenant shared.ID) shared.ID {
	id := shared.NewID()
	h.exec(`INSERT INTO groups (id, tenant_id, name, slug, group_type) VALUES ($1, $2, $3, $3, 'team')`, id.String(), tenant.String(), "team-"+id.String())
	return id
}

func newGRBHarness(t *testing.T) *grbHarness {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping team role binding DB test")
	}
	sqldb, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skipf("open db: %v", err)
	}
	t.Cleanup(func() { _ = sqldb.Close() })
	if err := sqldb.PingContext(context.Background()); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	h := &grbHarness{t: t, db: sqldb, tenant: shared.NewID(), other: shared.NewID()}
	for _, tid := range []shared.ID{h.tenant, h.other} {
		h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, tid.String(), "grb-"+tid.String())
		tid := tid
		t.Cleanup(func() { _, _ = sqldb.Exec(`DELETE FROM tenants WHERE id = $1`, tid.String()) })
	}
	h.owner = h.user(h.tenant, "internal", roledom.OwnerRoleID.String())
	h.admin = h.user(h.tenant, "internal", roledom.AdminRoleID.String())
	h.member = h.user(h.tenant, "internal", roledom.ViewerRoleID.String())
	h.outsider = h.user(h.tenant, "external", roledom.ViewerRoleID.String())
	// A delegated team lead: manages teams and roles, holds findings:read only.
	leadRole := h.customRole(h.tenant, "team-lead", false,
		"team:groups:read", "team:groups:write", "team:groups:members", "team:roles:read", "team:roles:assign", "findings:read")
	h.lead = h.user(h.tenant, "internal", "")
	h.exec(`INSERT INTO user_roles (user_id, tenant_id, role_id) VALUES ($1, $2, $3)`, h.lead.String(), h.tenant.String(), leadRole.String())

	h.analyst = h.customRole(h.tenant, "analyst", false, "findings:read", "findings:verify")
	h.secretReader = h.customRole(h.tenant, "secret-reader", false, "scans:secret_store:read")
	h.fullData = h.customRole(h.tenant, "full-reader", true, "assets:read")
	h.foreign = h.customRole(h.other, "foreign", false, "findings:read")
	h.team = h.newTeam(h.tenant)
	h.otherTeam = h.newTeam(h.other)

	db := &postgres.DB{DB: sqldb}
	log := logger.NewNop()
	h.roles = postgres.NewRoleRepository(db)
	roleSvc := accesscontrol.NewRoleService(h.roles, postgres.NewPermissionRepository(db), log)
	h.groups = accesscontrol.NewGroupService(postgres.NewGroupRepository(db), log)
	h.groups.SetRoleBindings(postgres.NewGroupRoleBindingRepository(db), roleSvc)
	h.roleSvc = roleSvc
	return h
}

func (h *grbHarness) actx(actor shared.ID) auditapp.AuditContext {
	return auditapp.AuditContext{TenantID: h.tenant.String(), ActorID: actor.String()}
}

func (h *grbHarness) perms(user shared.ID) []string {
	h.t.Helper()
	p, err := h.roles.GetUserPermissions(context.Background(), rid(h.tenant), rid(user))
	if err != nil {
		h.t.Fatal(err)
	}
	return p
}

func (h *grbHarness) addMember(actor, user shared.ID) error {
	_, err := h.groups.AddMember(context.Background(), accesscontrol.AddGroupMemberInput{
		GroupID: h.team.String(), UserID: user, Role: "member",
	}, h.actx(actor))
	return err
}

func TestTeamRoleBinding_MembersHoldTheRole(t *testing.T) {
	h := newGRBHarness(t)
	ctx := context.Background()
	if err := h.addMember(h.owner, h.member); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(h.perms(h.member), "findings:verify") {
		t.Fatal("verify before the binding")
	}
	if err := h.groups.BindRole(ctx, h.team.String(), h.analyst.String(), h.actx(h.owner)); err != nil {
		t.Fatalf("owner binds analyst: %v", err)
	}
	if !slices.Contains(h.perms(h.member), "findings:verify") {
		t.Fatal("a team member does not hold the bound role")
	}
	if slices.Contains(h.perms(h.outsider), "findings:verify") {
		t.Fatal("a non-member holds the bound role")
	}

	// An ended membership stops granting at once (before the sweep).
	h.exec(`UPDATE group_members SET expires_at = now() - interval '1 second' WHERE group_id = $1 AND user_id = $2`, h.team.String(), h.member.String())
	if slices.Contains(h.perms(h.member), "findings:verify") {
		t.Fatal("an expired member still holds the team role")
	}
	h.exec(`UPDATE group_members SET expires_at = NULL WHERE group_id = $1 AND user_id = $2`, h.team.String(), h.member.String())

	// A deactivated team grants nothing.
	h.exec(`UPDATE groups SET is_active = false WHERE id = $1`, h.team.String())
	if slices.Contains(h.perms(h.member), "findings:verify") {
		t.Fatal("a deactivated team still grants its role")
	}
	h.exec(`UPDATE groups SET is_active = true WHERE id = $1`, h.team.String())

	// A bound role cannot be deleted.
	if err := h.roles.Delete(ctx, rid(h.tenant), rid(h.analyst)); !errors.Is(err, roledom.ErrRoleInUse) {
		t.Fatalf("deleting a bound role: %v", err)
	}
	// Unbinding takes it away.
	if err := h.groups.UnbindRole(ctx, h.team.String(), h.analyst.String(), h.actx(h.owner)); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(h.perms(h.member), "findings:verify") {
		t.Fatal("the role survived the unbinding")
	}
}

func TestTeamRoleBinding_OnlyCustomRolesOfTheTenant(t *testing.T) {
	h := newGRBHarness(t)
	ctx := context.Background()
	for _, sys := range []roledom.ID{roledom.OwnerRoleID, roledom.AdminRoleID, roledom.MemberRoleID, roledom.ViewerRoleID} {
		if err := h.groups.BindRole(ctx, h.team.String(), sys.String(), h.actx(h.owner)); !errors.Is(err, group.ErrSystemRoleBinding) {
			t.Errorf("binding system role %s: %v", sys, err)
		}
	}
	// Another tenant's role and another tenant's team are not found.
	if err := h.groups.BindRole(ctx, h.team.String(), h.foreign.String(), h.actx(h.owner)); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("binding a foreign role: %v", err)
	}
	if err := h.groups.BindRole(ctx, h.otherTeam.String(), h.analyst.String(), h.actx(h.owner)); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("binding to a foreign team: %v", err)
	}
	// The schema refuses a cross-tenant row even if the service were bypassed.
	if _, err := h.db.Exec(`INSERT INTO group_role_bindings (tenant_id, group_id, role_id) VALUES ($1, $2, $3)`,
		h.tenant.String(), h.team.String(), h.foreign.String()); err == nil {
		t.Error("the schema accepted a foreign role")
	}
	if _, err := h.db.Exec(`INSERT INTO group_role_bindings (tenant_id, group_id, role_id) VALUES ($1, $2, $3)`,
		h.tenant.String(), h.team.String(), roledom.AdminRoleID.String()); err == nil {
		t.Error("the schema accepted the admin role")
	}
}

func TestTeamRoleBinding_IsAGrant(t *testing.T) {
	h := newGRBHarness(t)
	ctx := context.Background()

	// The lead manages teams and roles but holds no findings:verify, so
	// cannot hand out the analyst role through a team.
	if err := h.groups.BindRole(ctx, h.team.String(), h.analyst.String(), h.actx(h.lead)); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("lead binds a role above their grants: %v", err)
	}
	if err := h.groups.BindRole(ctx, h.team.String(), h.analyst.String(), h.actx(h.owner)); err != nil {
		t.Fatal(err)
	}
	// ...nor add someone to (or remove someone from) the team that carries it.
	if err := h.addMember(h.lead, h.member); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("lead adds a member to a role-bearing team: %v", err)
	}
	if err := h.addMember(h.owner, h.member); err != nil {
		t.Fatal(err)
	}
	if err := h.groups.RemoveMember(ctx, h.team.String(), h.member, h.actx(h.lead)); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("lead removes a member of a role-bearing team: %v", err)
	}
	// The administrator holds every permission, so may; nobody but the owner
	// adds themselves.
	if err := h.addMember(h.admin, h.admin); !errors.Is(err, accesscontrol.ErrSelfJoinRoleTeam) {
		t.Fatalf("admin adds themselves: %v", err)
	}
	if err := h.addMember(h.admin, h.outsider); err != nil {
		t.Fatalf("admin adds a member: %v", err)
	}
}

func TestTeamRoleBinding_PrivilegedRolesAreOwnerOnly(t *testing.T) {
	h := newGRBHarness(t)
	ctx := context.Background()
	for _, r := range []shared.ID{h.secretReader, h.fullData} {
		if err := h.groups.BindRole(ctx, h.team.String(), r.String(), h.actx(h.admin)); !errors.Is(err, accesscontrol.ErrPrivilegedTeamOwnerOnly) {
			t.Errorf("admin binds privileged role %s: %v", r, err)
		}
	}
	if err := h.groups.BindRole(ctx, h.team.String(), h.secretReader.String(), h.actx(h.owner)); err != nil {
		t.Fatalf("owner binds a privileged role: %v", err)
	}
	// Changing the membership of a privileged team is owner-only too.
	if err := h.addMember(h.admin, h.member); !errors.Is(err, accesscontrol.ErrPrivilegedTeamOwnerOnly) {
		t.Fatalf("admin adds to a privileged team: %v", err)
	}
	if err := h.addMember(h.owner, h.member); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(h.perms(h.member), "scans:secret_store:read") {
		t.Fatal("the owner-added member lacks the team role")
	}
}

func TestTeamRoleBinding_ExternalsNeverGetFullDataThroughATeam(t *testing.T) {
	h := newGRBHarness(t)
	ctx := context.Background()
	if err := h.groups.BindRole(ctx, h.team.String(), h.fullData.String(), h.actx(h.owner)); err != nil {
		t.Fatal(err)
	}
	if err := h.addMember(h.owner, h.outsider); !errors.Is(err, accesscontrol.ErrExternalRoleCeiling) {
		t.Fatalf("external member joins a full-data team: %v", err)
	}
	// And a full-data role is not bound to a team that has an external member.
	other := h.newTeam(h.tenant)
	if _, err := h.groups.AddMember(ctx, accesscontrol.AddGroupMemberInput{GroupID: other.String(), UserID: h.outsider, Role: "member"}, h.actx(h.owner)); err != nil {
		t.Fatal(err)
	}
	if err := h.groups.BindRole(ctx, other.String(), h.fullData.String(), h.actx(h.owner)); !errors.Is(err, accesscontrol.ErrExternalRoleCeiling) {
		t.Fatalf("full-data role bound to a team with an external member: %v", err)
	}
	full, err := h.roles.HasFullDataAccess(ctx, rid(h.tenant), rid(h.outsider))
	if err != nil || full {
		t.Fatalf("external member has full data: %v %v", full, err)
	}
}

func rid(id shared.ID) roledom.ID { return roledom.MustParseID(id.String()) }

// Editing a bound role so that it becomes privileged is a privileged binding
// change: only the owner makes it.
func TestTeamRoleBinding_MakingABoundRolePrivilegedIsOwnerOnly(t *testing.T) {
	h := newGRBHarness(t)
	ctx := context.Background()
	if err := h.groups.BindRole(ctx, h.team.String(), h.analyst.String(), h.actx(h.owner)); err != nil {
		t.Fatal(err)
	}
	widen := []string{"findings:read", "findings:verify", "scans:secret_store:read"}
	if _, err := h.roleSvc.UpdateRole(ctx, h.tenant.String(), h.analyst.String(),
		accesscontrol.UpdateRoleInput{Permissions: widen}, h.actx(h.admin)); !errors.Is(err, accesscontrol.ErrPrivilegedTeamOwnerOnly) {
		t.Fatalf("admin makes a bound role privileged: %v", err)
	}
	if _, err := h.roleSvc.UpdateRole(ctx, h.tenant.String(), h.analyst.String(),
		accesscontrol.UpdateRoleInput{Permissions: widen}, h.actx(h.owner)); err != nil {
		t.Fatalf("owner makes a bound role privileged: %v", err)
	}
}
