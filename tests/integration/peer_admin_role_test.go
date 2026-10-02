package integration

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/infra/postgres"
	"github.com/openctemio/api/internal/testdb"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// Peer administrators are managed by the owner (owner decision 2026-10-02,
// AUTHZ B3). Through the RBAC role paths an administrator could strip a peer
// administrator's admin role; now only the owner may change another
// administrator's role set. Administrators still manage members, and may
// change their own role set.
func TestPeerAdminRoleChange_OwnerOnly(t *testing.T) {
	dsn := testdb.URL()
	if dsn == "" {
		t.Skip("DATABASE_URL not set; skipping peer admin DB test")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Skipf("database not available: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()

	tenantID := uuid.NewString()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'Peer admin IT', $2)`,
		tenantID, "peer-admin-"+strings.ReplaceAll(tenantID[:13], "-", ""))
	var users []string
	member := func(role string) string {
		id := uuid.NewString()
		users = append(users, id)
		exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'Peer admin IT')`, id, "pa-"+id[:8]+"@it.test")
		exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, $3)`, id, tenantID, role)
		return id
	}
	owner, admin, peer, viewer := member("owner"), member("admin"), member("admin"), member("viewer")
	t.Cleanup(func() {
		_, _ = db.ExecContext(ctx, `DELETE FROM user_roles WHERE tenant_id = $1`, tenantID)
		_, _ = db.ExecContext(ctx, `DELETE FROM tenant_members WHERE tenant_id = $1`, tenantID)
		_, _ = db.ExecContext(ctx, `DELETE FROM users WHERE id = ANY($1)`, "{"+strings.Join(users, ",")+"}")
		_, _ = db.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID)
	})

	pg := &postgres.DB{DB: db}
	svc := app.NewRoleService(postgres.NewRoleRepository(pg), postgres.NewPermissionRepository(pg), logger.NewNop(),
		app.WithRoleMembershipReader(postgres.NewTenantRepository(pg)))
	const (
		adminRole  = "00000000-0000-0000-0000-000000000002"
		memberRole = "00000000-0000-0000-0000-000000000003"
		viewerRole = "00000000-0000-0000-0000-000000000004"
	)
	rolesOf := func(uid string) []string {
		rows, err := db.QueryContext(ctx, `SELECT r.slug FROM user_roles ur JOIN roles r ON r.id = ur.role_id
			WHERE ur.user_id = $1 AND ur.tenant_id = $2 ORDER BY r.slug`, uid, tenantID)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var s string
			_ = rows.Scan(&s)
			out = append(out, s)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}
	forbidden := func(what string, err error) {
		t.Helper()
		if !errors.Is(err, shared.ErrForbidden) {
			t.Fatalf("%s: want forbidden, got %v", what, err)
		}
	}

	// An administrator cannot change a peer administrator's role set.
	forbidden("SetUserRoles peer -> [viewer]", svc.SetUserRoles(ctx,
		app.SetUserRolesInput{TenantID: tenantID, UserID: peer, RoleIDs: []string{viewerRole}}, admin, app.AuditContext{}))
	forbidden("RemoveRole admin from peer", svc.RemoveRole(ctx, tenantID, peer, adminRole, app.AuditContext{ActorID: admin}))
	forbidden("AssignRole member to peer", svc.AssignRole(ctx,
		app.AssignRoleInput{TenantID: tenantID, UserID: peer, RoleID: memberRole}, admin, app.AuditContext{}))
	if got := rolesOf(peer); !slices.Equal(got, []string{"admin"}) {
		t.Fatalf("peer admin's roles changed: %v", got)
	}

	// An administrator still manages members and viewers.
	if err := svc.SetUserRoles(ctx, app.SetUserRolesInput{TenantID: tenantID, UserID: viewer, RoleIDs: []string{memberRole}},
		admin, app.AuditContext{}); err != nil {
		t.Fatalf("admin re-roles a viewer: %v", err)
	}

	// The owner changes an administrator's role set.
	if err := svc.SetUserRoles(ctx, app.SetUserRolesInput{TenantID: tenantID, UserID: peer, RoleIDs: []string{memberRole}},
		owner, app.AuditContext{}); err != nil {
		t.Fatalf("owner demotes an admin: %v", err)
	}
	if got := rolesOf(peer); !slices.Equal(got, []string{"member"}) {
		t.Fatalf("peer roles after owner demotion: %v", got)
	}
}
