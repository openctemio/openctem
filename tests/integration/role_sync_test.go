package integration

import (
	"context"
	"database/sql"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/openctemio/api/internal/infra/controller"
)

// The hourly role-sync reconciler used to re-grant the system role named in
// tenant_members.role whenever the user did not hold it. tenant_members.role
// is a coarse label (MembershipRoleForRoleIDs), not the role set: a user
// created with only a custom role, or an administrator who removed a system
// role, got that role back within the hour. The RBAC role set an
// administrator chose must survive the reconciler; it only repairs data that
// is genuinely inconsistent (the owner must hold the owner role).

const (
	sysOwner  = "00000000-0000-0000-0000-000000000001"
	sysAdmin  = "00000000-0000-0000-0000-000000000002"
	sysMember = "00000000-0000-0000-0000-000000000003"
	sysViewer = "00000000-0000-0000-0000-000000000004"
)

type roleSyncFixture struct {
	db     *sql.DB
	tenant string
}

func newRoleSyncFixture(t *testing.T) *roleSyncFixture {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set; skipping role-sync DB test")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Skipf("database not available: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	f := &roleSyncFixture{db: db, tenant: uuid.NewString()}
	slug := "role-sync-" + strings.ReplaceAll(f.tenant[:13], "-", "")
	f.exec(t, `INSERT INTO tenants (id, name, slug) VALUES ($1, 'Role sync IT', $2)`, f.tenant, slug)
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = db.ExecContext(ctx, `DELETE FROM user_roles WHERE tenant_id = $1`, f.tenant)
		_, _ = db.ExecContext(ctx, `DELETE FROM tenant_members WHERE tenant_id = $1`, f.tenant)
		_, _ = db.ExecContext(ctx, `DELETE FROM roles WHERE tenant_id = $1`, f.tenant)
		_, _ = db.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, f.tenant)
	})
	return f
}

func (f *roleSyncFixture) exec(t *testing.T, q string, args ...any) {
	t.Helper()
	if _, err := f.db.ExecContext(t.Context(), q, args...); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}

// member creates a user and a membership with the given coarse role. The
// tenant_members trigger grants the matching system role, as in production.
func (f *roleSyncFixture) member(t *testing.T, membershipRole string) string {
	t.Helper()
	id := uuid.NewString()
	f.exec(t, `INSERT INTO users (id, email, name) VALUES ($1, $2, 'Role sync IT')`, id, "rs-"+id[:8]+"@it.test")
	t.Cleanup(func() { _, _ = f.db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, id) })
	f.exec(t, `INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, $3)`, id, f.tenant, membershipRole)
	return id
}

// setRoles makes roleIDs the user's exact role set, as SetUserRoles does.
func (f *roleSyncFixture) setRoles(t *testing.T, userID string, roleIDs ...string) {
	t.Helper()
	f.exec(t, `DELETE FROM user_roles WHERE user_id = $1 AND tenant_id = $2`, userID, f.tenant)
	for _, r := range roleIDs {
		f.exec(t, `INSERT INTO user_roles (user_id, tenant_id, role_id) VALUES ($1, $2, $3)`, userID, f.tenant, r)
	}
}

func (f *roleSyncFixture) roles(t *testing.T, userID string) []string {
	t.Helper()
	rows, err := f.db.QueryContext(t.Context(),
		`SELECT role_id::text FROM user_roles WHERE user_id = $1 AND tenant_id = $2`, userID, f.tenant)
	if err != nil {
		t.Fatalf("roles: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	slices.Sort(out)
	return out
}

func (f *roleSyncFixture) customRole(t *testing.T) string {
	t.Helper()
	id := uuid.NewString()
	f.exec(t, `INSERT INTO roles (id, tenant_id, slug, name, is_system) VALUES ($1, $2, $3, 'Analyst', FALSE)`,
		id, f.tenant, "analyst-"+id[:8])
	return id
}

func reconcileRoles(t *testing.T, db *sql.DB) {
	t.Helper()
	c := controller.NewRoleSyncController(db, &controller.RoleSyncControllerConfig{Interval: time.Hour})
	if _, err := c.Reconcile(t.Context()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
}

func sorted(ids ...string) []string {
	out := slices.Clone(ids)
	slices.Sort(out)
	return out
}

func TestRoleSync_CustomRoleOnlyUserIsNotReGrantedViewer(t *testing.T) {
	f := newRoleSyncFixture(t)
	analyst := f.customRole(t)
	// Created with only the custom role: membership label 'viewer', roles {analyst}.
	u := f.member(t, "viewer")
	f.setRoles(t, u, analyst)

	reconcileRoles(t, f.db)

	if got, want := f.roles(t, u), sorted(analyst); !slices.Equal(got, want) {
		t.Fatalf("roles after reconcile: got %v, want %v (viewer must not come back)", got, want)
	}
}

func TestRoleSync_AdminDoesNotGainMembershipLabelRole(t *testing.T) {
	f := newRoleSyncFixture(t)
	u := f.member(t, "member")
	f.setRoles(t, u, sysAdmin)

	reconcileRoles(t, f.db)

	if got, want := f.roles(t, u), sorted(sysAdmin); !slices.Equal(got, want) {
		t.Fatalf("roles after reconcile: got %v, want %v (no extra member row)", got, want)
	}
}

func TestRoleSync_RemovedSystemRoleStaysRemoved(t *testing.T) {
	f := newRoleSyncFixture(t)
	analyst := f.customRole(t)
	u := f.member(t, "member")
	f.setRoles(t, u, sysMember, analyst)
	// An administrator removes the member role, keeping the custom one.
	f.exec(t, `DELETE FROM user_roles WHERE user_id = $1 AND tenant_id = $2 AND role_id = $3`, u, f.tenant, sysMember)

	reconcileRoles(t, f.db)

	if got, want := f.roles(t, u), sorted(analyst); !slices.Equal(got, want) {
		t.Fatalf("roles after reconcile: got %v, want %v", got, want)
	}
}

// A member whose every role was removed has no access; the reconciler must
// not hand the membership label's role back.
func TestRoleSync_MemberWithNoRolesIsNotReGranted(t *testing.T) {
	f := newRoleSyncFixture(t)
	u := f.member(t, "member")
	f.setRoles(t, u)

	reconcileRoles(t, f.db)

	if got := f.roles(t, u); len(got) != 0 {
		t.Fatalf("roles after reconcile: got %v, want none", got)
	}
}

// The one genuine inconsistency it repairs: the tenant's owner must hold the
// owner role (ownership itself is tenant_members.role = 'owner').
func TestRoleSync_OwnerKeepsOwnerRole(t *testing.T) {
	f := newRoleSyncFixture(t)
	analyst := f.customRole(t)
	u := f.member(t, "owner")
	f.setRoles(t, u, analyst)

	reconcileRoles(t, f.db)

	if got, want := f.roles(t, u), sorted(sysOwner, analyst); !slices.Equal(got, want) {
		t.Fatalf("roles after reconcile: got %v, want %v", got, want)
	}
}

// Untouched memberships are left alone and a second run changes nothing.
func TestRoleSync_ConsistentDataUnchangedAndIdempotent(t *testing.T) {
	f := newRoleSyncFixture(t)
	viewer := f.member(t, "viewer")
	owner := f.member(t, "owner")

	reconcileRoles(t, f.db)
	reconcileRoles(t, f.db)

	if got, want := f.roles(t, viewer), sorted(sysViewer); !slices.Equal(got, want) {
		t.Fatalf("viewer: got %v, want %v", got, want)
	}
	if got, want := f.roles(t, owner), sorted(sysOwner); !slices.Equal(got, want) {
		t.Fatalf("owner: got %v, want %v", got, want)
	}
}
