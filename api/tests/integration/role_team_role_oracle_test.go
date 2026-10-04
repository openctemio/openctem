package integration

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/accesscontrol"
	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Team-role oracle regression tests (audit F1/H1 and F5).
//
// The team role (JWT role + admin flag, RequireTeamAdmin/Owner, IsOwner) used to
// be the slug of the user's highest-hierarchy_level role in user_roles, which
// could be a custom role. A holder of team:roles:write + team:roles:assign
// created a custom role with slug "owner" and hierarchy_level 100, assigned it
// to themselves, and became owner. These tests pin the fixed model: owner/admin
// come only from the system role IDs, custom roles can neither take a system
// slug nor rank at or above admin, removing a role is bounded like granting
// one, and a user with no system role is never owner/admin.

const (
	sysOwnerRole  = "00000000-0000-0000-0000-000000000001"
	sysAdminRole  = "00000000-0000-0000-0000-000000000002"
	sysMemberRole = "00000000-0000-0000-0000-000000000003"
	sysViewerRole = "00000000-0000-0000-0000-000000000004"
)

type roleFixture struct {
	t        *testing.T
	ctx      context.Context
	db       *sql.DB
	tenantID string
	users    []string
	tenants  *postgres.TenantRepository
	svc      *accesscontrol.RoleService
}

func newRoleFixture(t *testing.T) *roleFixture {
	t.Helper()
	dsn := testdb.URL()
	if dsn == "" {
		t.Skip("DATABASE_URL not set; skipping team-role oracle DB test")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Skipf("database not available: %v", err)
	}
	f := &roleFixture{t: t, ctx: context.Background(), db: db, tenantID: uuid.NewString()}
	f.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'Team role oracle IT', $2)`,
		f.tenantID, "role-oracle-"+strings.ReplaceAll(f.tenantID[:13], "-", ""))
	t.Cleanup(func() {
		_, _ = db.ExecContext(f.ctx, `DELETE FROM user_roles WHERE tenant_id = $1`, f.tenantID)
		_, _ = db.ExecContext(f.ctx, `DELETE FROM roles WHERE tenant_id = $1`, f.tenantID)
		_, _ = db.ExecContext(f.ctx, `DELETE FROM tenant_members WHERE tenant_id = $1`, f.tenantID)
		if len(f.users) > 0 {
			_, _ = db.ExecContext(f.ctx, `DELETE FROM users WHERE id = ANY($1)`, "{"+strings.Join(f.users, ",")+"}")
		}
		_, _ = db.ExecContext(f.ctx, `DELETE FROM tenants WHERE id = $1`, f.tenantID)
		_ = db.Close()
	})
	pg := &postgres.DB{DB: db}
	f.tenants = postgres.NewTenantRepository(pg)
	f.svc = accesscontrol.NewRoleService(postgres.NewRoleRepository(pg), postgres.NewPermissionRepository(pg), logger.NewNop(),
		accesscontrol.WithRoleMembershipReader(f.tenants))
	return f
}

func (f *roleFixture) exec(q string, args ...any) {
	f.t.Helper()
	if _, err := f.db.ExecContext(f.ctx, q, args...); err != nil {
		f.t.Fatalf("%s: %v", q, err)
	}
}

// member inserts a user with membership label `label`. The tenant_members
// trigger grants the matching system role.
func (f *roleFixture) member(label string) string {
	f.t.Helper()
	id := uuid.NewString()
	f.users = append(f.users, id)
	f.exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'Team role oracle IT')`, id, "tro-"+id[:8]+"@it.test")
	f.exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, $3)`, id, f.tenantID, label)
	return id
}

// customRole inserts a custom role straight into the database.
func (f *roleFixture) customRole(slug string, level int, perms ...string) string {
	f.t.Helper()
	id := uuid.NewString()
	f.exec(`INSERT INTO roles (id, tenant_id, slug, name, is_system, hierarchy_level) VALUES ($1, $2, $3, $3, FALSE, $4)`,
		id, f.tenantID, slug, level)
	for _, p := range perms {
		f.exec(`INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)`, id, p)
	}
	return id
}

func (f *roleFixture) setRoles(uid string, roleIDs ...string) {
	f.t.Helper()
	f.exec(`DELETE FROM user_roles WHERE user_id = $1 AND tenant_id = $2`, uid, f.tenantID)
	for _, r := range roleIDs {
		f.exec(`INSERT INTO user_roles (user_id, tenant_id, role_id) VALUES ($1, $2, $3)`, uid, f.tenantID, r)
	}
}

// teamRole is the role every oracle reads, through each repository path.
func (f *roleFixture) teamRole(uid string) string {
	f.t.Helper()
	u, _ := shared.IDFromString(uid)
	tid, _ := shared.IDFromString(f.tenantID)
	m, err := f.tenants.GetMembership(f.ctx, u, tid)
	if err != nil {
		f.t.Fatalf("GetMembership: %v", err)
	}
	byID, err := f.tenants.GetMembershipByID(f.ctx, tid, m.ID())
	if err != nil {
		f.t.Fatalf("GetMembershipByID: %v", err)
	}
	ums, err := f.tenants.GetUserMemberships(f.ctx, u)
	if err != nil {
		f.t.Fatalf("GetUserMemberships: %v", err)
	}
	withStatus, err := f.tenants.GetUserMembershipsWithStatus(f.ctx, u)
	if err != nil {
		f.t.Fatalf("GetUserMembershipsWithStatus: %v", err)
	}
	got := []string{m.Role().String(), byID.Role().String()}
	for _, um := range ums {
		if um.TenantID == f.tenantID {
			got = append(got, um.Role)
		}
	}
	for _, um := range withStatus.Active {
		if um.TenantID == f.tenantID {
			got = append(got, um.Role)
		}
	}
	if len(got) != 4 {
		f.t.Fatalf("membership not visible on every path: %v", got)
	}
	for _, g := range got[1:] {
		if g != got[0] {
			f.t.Fatalf("team-role paths disagree: %v", got)
		}
	}
	return got[0]
}

func adminRole(role string) bool { return role == "owner" || role == "admin" }

// The exploit from the audit, end to end through RoleService against the real
// database: a non-admin role manager tries to mint and self-assign an
// owner-looking custom role. Every step that would confer owner/admin is refused
// or inert.
func TestTeamRoleOracle_CustomRoleCannotBecomeOwner(t *testing.T) {
	f := newRoleFixture(t)
	manager := f.member("viewer")
	mgrRole := f.customRole("cr-roleadmin", 50,
		"team:roles:read", "team:roles:write", "team:roles:assign", "team:roles:delete", "assets:read")
	f.setRoles(manager, mgrRole)

	if got := f.teamRole(manager); got != "viewer" {
		t.Fatalf("custom-only role manager: team role = %q, want viewer", got)
	}

	actx := auditapp.AuditContext{ActorID: manager, TenantID: f.tenantID}
	for _, slug := range []string{"owner", "admin", "member", "viewer"} {
		_, err := f.svc.CreateRole(f.ctx, accesscontrol.CreateRoleInput{
			TenantID: f.tenantID, Slug: slug, Name: "Spoof " + slug, HierarchyLevel: 10,
			Permissions: []string{"assets:read"},
		}, manager, actx)
		if !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("CreateRole slug %q: want validation error, got %v", slug, err)
		}
	}
	for _, level := range []int{80, 100} {
		_, err := f.svc.CreateRole(f.ctx, accesscontrol.CreateRoleInput{
			TenantID: f.tenantID, Slug: "cr-high", Name: "High", HierarchyLevel: level,
			Permissions: []string{"assets:read"},
		}, manager, actx)
		if !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("CreateRole hierarchy_level %d: want validation error, got %v", level, err)
		}
	}

	// The highest a custom role may rank is just below admin.
	top, err := f.svc.CreateRole(f.ctx, accesscontrol.CreateRoleInput{
		TenantID: f.tenantID, Slug: "cr-top", Name: "Top", HierarchyLevel: 79,
		Permissions: []string{"assets:read"},
	}, manager, actx)
	if err != nil {
		t.Fatalf("CreateRole level 79: %v", err)
	}
	tooHigh := 100
	if _, err := f.svc.UpdateRole(f.ctx, f.tenantID, top.ID().String(),
		accesscontrol.UpdateRoleInput{HierarchyLevel: &tooHigh}, actx); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("UpdateRole hierarchy_level 100: want validation error, got %v", err)
	}

	if err := f.svc.AssignRole(f.ctx, accesscontrol.AssignRoleInput{
		TenantID: f.tenantID, UserID: manager, RoleID: top.ID().String(),
	}, manager, actx); err != nil {
		t.Fatalf("self-assign cr-top: %v", err)
	}
	if got := f.teamRole(manager); adminRole(got) {
		t.Fatalf("custom roles made the manager %q", got)
	}

	// Custom-role permissions still resolve exactly as before.
	perms, err := f.svc.GetUserPermissions(f.ctx, f.tenantID, manager)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(perms, "team:roles:assign") || !slices.Contains(perms, "assets:read") || slices.Contains(perms, "team:delete") {
		t.Fatalf("custom-role permissions changed: %v", perms)
	}
}

// The database refuses what the service refuses, so no other write path (or a
// future one) can store an owner-looking custom role.
func TestTeamRoleOracle_DatabaseConstraints(t *testing.T) {
	f := newRoleFixture(t)
	insert := func(slug string, level int) error {
		_, err := f.db.ExecContext(f.ctx,
			`INSERT INTO roles (id, tenant_id, slug, name, is_system, hierarchy_level) VALUES ($1, $2, $3, $3, FALSE, $4)`,
			uuid.NewString(), f.tenantID, slug, level)
		return err
	}
	for _, slug := range []string{"owner", "admin", "member", "viewer", "OWNER"} {
		if err := insert(slug, 10); err == nil {
			t.Fatalf("custom role with reserved slug %q was stored", slug)
		}
	}
	for _, level := range []int{80, 100} {
		if err := insert("cr-level-"+uuid.NewString()[:6], level); err == nil {
			t.Fatalf("custom role with hierarchy_level %d was stored", level)
		}
	}
	if err := insert("cr-ok", 79); err != nil {
		t.Fatalf("custom role at level 79: %v", err)
	}
}

// Owner/admin come only from the system role IDs, whatever else the user holds,
// and a user without any system role is never owner/admin, whatever the
// membership label says.
func TestTeamRoleOracle_DerivedFromSystemRoleIDsOnly(t *testing.T) {
	f := newRoleFixture(t)
	high := f.customRole("cr-high", 79, "assets:read")
	low := f.customRole("cr-low", 1, "assets:read")

	cases := []struct {
		name  string
		label string
		roles []string
		want  string
	}{
		{"owner keeps owner", "owner", []string{sysOwnerRole}, "owner"},
		{"system admin with a custom role", "member", []string{sysAdminRole, high}, "admin"},
		{"system admin with a low custom role", "member", []string{low, sysAdminRole}, "admin"},
		{"member with a high custom role", "member", []string{sysMemberRole, high}, "member"},
		{"viewer and member", "viewer", []string{sysViewerRole, sysMemberRole}, "member"},
		{"custom only, member label", "member", []string{high}, "member"},
		{"custom only, viewer label", "viewer", []string{high}, "viewer"},
		{"admin label, custom roles only", "admin", []string{high}, "viewer"},
		{"admin label, zero roles", "admin", nil, "viewer"},
		{"owner label, zero roles", "owner", nil, "viewer"},
		{"member label, zero roles", "member", nil, "member"},
	}
	for _, tc := range cases {
		uid := f.member(tc.label)
		f.setRoles(uid, tc.roles...)
		if got := f.teamRole(uid); got != tc.want {
			t.Errorf("%s: team role = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// Middleware layer: the URL-tenant team gates read the real membership, so a
// user whose only claim to ownership is a custom role is refused by
// RequireTeamOwner/RequireTeamAdmin, and the system owner passes.
func TestTeamRoleOracle_TeamGatesRefuseCustomRoleHolders(t *testing.T) {
	f := newRoleFixture(t)
	owner := f.member("owner")
	holder := f.member("viewer")
	f.setRoles(holder, f.customRole("cr-everything", 79, "team:roles:write", "team:roles:assign", "assets:read"))

	tid, _ := shared.IDFromString(f.tenantID)
	users := postgres.NewUserRepository(&postgres.DB{DB: f.db})
	gate := func(uid string, required func() func(http.Handler) http.Handler) int {
		id, _ := shared.IDFromString(uid)
		u, err := users.GetByID(f.ctx, id)
		if err != nil {
			t.Fatalf("load user: %v", err)
		}
		h := middleware.RequireMembership(f.tenants)(required()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})))
		req := httptest.NewRequest(http.MethodPatch, "/api/v1/tenants/x/settings/security", nil)
		ctx := context.WithValue(req.Context(), middleware.LocalUserKey, u)
		ctx = context.WithValue(ctx, middleware.TeamIDKey, tid)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req.WithContext(ctx))
		return rec.Code
	}
	if code := gate(holder, middleware.RequireTeamOwner); code != http.StatusForbidden {
		t.Fatalf("custom-role holder through RequireTeamOwner: %d, want 403", code)
	}
	if code := gate(holder, middleware.RequireTeamAdmin); code != http.StatusForbidden {
		t.Fatalf("custom-role holder through RequireTeamAdmin: %d, want 403", code)
	}
	if code := gate(owner, middleware.RequireTeamOwner); code != http.StatusNoContent {
		t.Fatalf("owner through RequireTeamOwner: %d, want 204", code)
	}
}

// Removing a role is bounded like granting it (F5): a delegated role manager
// may not strip a role they could not grant, neither one at a time nor by
// replacing the role set. An administrator stripped of every role (by someone
// allowed to) is no longer an administrator.
func TestTeamRoleOracle_RemovalCeiling(t *testing.T) {
	f := newRoleFixture(t)
	owner := f.member("owner")
	admin := f.member("admin")
	victim := f.member("member")
	manager := f.member("viewer")
	sub := f.customRole("cr-sub", 10, "assets:read")
	f.setRoles(manager, f.customRole("cr-roleadmin", 50,
		"team:roles:read", "team:roles:write", "team:roles:assign", "assets:read"))

	forbidden := func(what string, err error) {
		t.Helper()
		if !errors.Is(err, shared.ErrForbidden) {
			t.Fatalf("%s: want forbidden, got %v", what, err)
		}
	}
	mctx := auditapp.AuditContext{ActorID: manager, TenantID: f.tenantID}
	forbidden("manager removes admin's admin role",
		f.svc.RemoveRole(f.ctx, f.tenantID, admin, sysAdminRole, mctx))
	forbidden("manager removes member's member role",
		f.svc.RemoveRole(f.ctx, f.tenantID, victim, sysMemberRole, mctx))
	forbidden("manager replaces member's roles",
		f.svc.SetUserRoles(f.ctx, accesscontrol.SetUserRolesInput{
			TenantID: f.tenantID, UserID: victim, RoleIDs: []string{sub},
		}, manager, mctx))
	forbidden("manager replaces admin's roles",
		f.svc.SetUserRoles(f.ctx, accesscontrol.SetUserRolesInput{
			TenantID: f.tenantID, UserID: admin, RoleIDs: []string{sub},
		}, manager, mctx))
	if got := f.teamRole(admin); got != "admin" {
		t.Fatalf("admin was demoted by the manager: %q", got)
	}
	if got := f.teamRole(victim); got != "member" {
		t.Fatalf("member was changed by the manager: %q", got)
	}

	// The manager may still remove what they could grant.
	if err := f.svc.AssignRole(f.ctx, accesscontrol.AssignRoleInput{
		TenantID: f.tenantID, UserID: victim, RoleID: sub,
	}, manager, mctx); err != nil {
		t.Fatalf("manager assigns cr-sub: %v", err)
	}
	if err := f.svc.RemoveRole(f.ctx, f.tenantID, victim, sub, mctx); err != nil {
		t.Fatalf("manager removes cr-sub: %v", err)
	}

	// The owner strips the admin of every role: no admin powers remain.
	octx := auditapp.AuditContext{ActorID: owner, TenantID: f.tenantID}
	if err := f.svc.RemoveRole(f.ctx, f.tenantID, admin, sysAdminRole, octx); err != nil {
		t.Fatalf("owner removes admin role: %v", err)
	}
	if got := f.teamRole(admin); adminRole(got) {
		t.Fatalf("admin with zero roles still resolves to %q", got)
	}
}

// The migration that closes F1 renames custom roles that took a reserved slug
// and clamps custom hierarchy levels below admin, leaving system roles and
// legitimate custom roles alone. It runs inside a rolled-back transaction with
// the new constraints dropped, so the pre-migration rows can be recreated.
func TestTeamRoleOracle_MigrationRepairsExistingRows(t *testing.T) {
	f := newRoleFixture(t)
	up, err := os.ReadFile("../../migrations/000245_team_role_from_system_roles.up.sql")
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	tx, err := testdb.OpenMigrator(t).BeginTx(f.ctx, nil) // the migration is DDL: schema owner
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	txExec := func(q string, args ...any) {
		t.Helper()
		if _, err := tx.ExecContext(f.ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	// The migration alters roles and replaces v_user_effective_role, which
	// other packages read concurrently; lock both before any DDL so it
	// cannot deadlock with them.
	testdb.LockForDDL(t, f.ctx, tx, "roles", "v_user_effective_role")
	txExec(`ALTER TABLE roles DROP CONSTRAINT IF EXISTS roles_custom_slug_not_reserved`)
	txExec(`ALTER TABLE roles DROP CONSTRAINT IF EXISTS roles_custom_level_below_admin`)

	ids := map[string]string{}
	add := func(key, slug string, level int) {
		ids[key] = uuid.NewString()
		txExec(`INSERT INTO roles (id, tenant_id, slug, name, is_system, hierarchy_level) VALUES ($1, $2, $3, $3, FALSE, $4)`,
			ids[key], f.tenantID, slug, level)
	}
	add("owner", "owner", 100)
	add("admin", "admin", 80)
	add("taken", "custom-owner", 10) // the rename target already exists
	add("fine", "analyst", 40)
	add("edge", "edgy", 79)
	if _, err := tx.ExecContext(f.ctx, string(up)); err != nil {
		t.Fatalf("apply migration: %v", err)
	}

	row := func(key string) (slug string, level int) {
		t.Helper()
		if err := tx.QueryRowContext(f.ctx, `SELECT slug, hierarchy_level FROM roles WHERE id = $1`, ids[key]).Scan(&slug, &level); err != nil {
			t.Fatal(err)
		}
		return slug, level
	}
	if s, l := row("owner"); s == "owner" || !strings.HasPrefix(s, "custom-owner") || l != 79 {
		t.Fatalf("custom 'owner' role after migration: slug=%q level=%d", s, l)
	}
	if s, l := row("admin"); s != "custom-admin" || l != 79 {
		t.Fatalf("custom 'admin' role after migration: slug=%q level=%d", s, l)
	}
	if s, l := row("taken"); s != "custom-owner" || l != 10 {
		t.Fatalf("existing custom-owner role changed: slug=%q level=%d", s, l)
	}
	if s, l := row("fine"); s != "analyst" || l != 40 {
		t.Fatalf("legitimate custom role changed: slug=%q level=%d", s, l)
	}
	if s, l := row("edge"); s != "edgy" || l != 79 {
		t.Fatalf("level-79 custom role changed: slug=%q level=%d", s, l)
	}
	var sysOwnerLevel int
	if err := tx.QueryRowContext(f.ctx, `SELECT hierarchy_level FROM roles WHERE id = $1`, sysOwnerRole).Scan(&sysOwnerLevel); err != nil {
		t.Fatal(err)
	}
	if sysOwnerLevel != 100 {
		t.Fatalf("system owner role level changed: %d", sysOwnerLevel)
	}
}
