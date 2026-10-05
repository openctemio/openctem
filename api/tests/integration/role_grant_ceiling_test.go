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
	"github.com/openctemio/openctem/api/internal/app/accesscontrol"
	"github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// An administrator set their own role set to [owner] and then passed the
// owner-only routes. Against the real repositories: the self-escalation is
// refused through every role-setting path and the database is unchanged, while
// the owner can still grant the owner role.
func TestRoleGrantCeiling_AdminSelfEscalationRefused(t *testing.T) {
	dsn := testdb.URL()
	if dsn == "" {
		t.Skip("DATABASE_URL not set; skipping role grant ceiling DB test")
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
	exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'Grant ceiling IT', $2)`,
		tenantID, "grant-ceiling-"+strings.ReplaceAll(tenantID[:13], "-", ""))
	member := func(role string) string {
		id := uuid.NewString()
		exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'Grant ceiling IT')`, id, "gc-"+id[:8]+"@it.test")
		exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, $3)`, id, tenantID, role)
		return id
	}
	owner, admin, viewer := member("owner"), member("admin"), member("viewer")
	t.Cleanup(func() {
		_, _ = db.ExecContext(ctx, `DELETE FROM user_roles WHERE tenant_id = $1`, tenantID)
		_, _ = db.ExecContext(ctx, `DELETE FROM tenant_members WHERE tenant_id = $1`, tenantID)
		_, _ = db.ExecContext(ctx, `DELETE FROM users WHERE id = ANY($1)`, "{"+owner+","+admin+","+viewer+"}")
		_, _ = db.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID)
	})

	pg := &postgres.DB{DB: db}
	svc := accesscontrol.NewRoleService(postgres.NewRoleRepository(pg), postgres.NewPermissionRepository(pg), logger.NewNop(),
		accesscontrol.WithRoleMembershipReader(postgres.NewTenantRepository(pg)))
	const ownerRole = "00000000-0000-0000-0000-000000000001"
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
	forbidden("SetUserRoles admin -> [owner]", svc.SetUserRoles(ctx,
		accesscontrol.SetUserRolesInput{TenantID: tenantID, UserID: admin, RoleIDs: []string{ownerRole}}, admin, audit.AuditContext{}))
	forbidden("AssignRole admin + owner", svc.AssignRole(ctx,
		accesscontrol.AssignRoleInput{TenantID: tenantID, UserID: admin, RoleID: ownerRole}, admin, audit.AuditContext{}))
	_, err = svc.BulkAssignRoleToUsers(ctx,
		accesscontrol.BulkAssignRoleToUsersInput{TenantID: tenantID, RoleID: ownerRole, UserIDs: []string{admin, viewer}}, admin, audit.AuditContext{})
	forbidden("BulkAssign owner", err)
	forbidden("RemoveRole owner from the owner", svc.RemoveRole(ctx, tenantID, owner, ownerRole, audit.AuditContext{ActorID: admin}))

	if got := rolesOf(admin); !slices.Equal(got, []string{"admin"}) {
		t.Fatalf("admin's roles changed: %v", got)
	}
	if got := rolesOf(owner); !slices.Equal(got, []string{"owner"}) {
		t.Fatalf("owner's roles changed: %v", got)
	}

	// The owner may grant the owner role.
	if err := svc.AssignRole(ctx, accesscontrol.AssignRoleInput{TenantID: tenantID, UserID: viewer, RoleID: ownerRole}, owner, audit.AuditContext{}); err != nil {
		t.Fatalf("owner grants owner: %v", err)
	}
	if got := rolesOf(viewer); !slices.Contains(got, "owner") {
		t.Fatalf("viewer roles after owner grant: %v", got)
	}
}
