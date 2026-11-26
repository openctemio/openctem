package integration

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/server/internal/app/accesscontrol"
	"github.com/openctemio/openctem/server/internal/app/audit"
	"github.com/openctemio/openctem/server/internal/infra/postgres"
	"github.com/openctemio/openctem/server/internal/testdb"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// Every role write (create, update, bulk assignment, removal, delete) leaves
// an audit row in the organization's log, with the acting user, against the
// real repositories. The routes for these writes also need step-up
// (routes/step_up_routes_test.go).
func TestRoleWrites_AreAudited(t *testing.T) {
	dsn := testdb.URL()
	if dsn == "" {
		t.Skip("DATABASE_URL not set; skipping role write audit DB test")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("database not available: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	tenantID := uuid.NewString()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'Role audit IT', $2)`,
		tenantID, "role-audit-"+strings.ReplaceAll(tenantID[:13], "-", ""))
	member := func(role string) string {
		id := uuid.NewString()
		exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'Role audit IT')`, id, "ra-"+id[:8]+"@it.test")
		exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, $3)`, id, tenantID, role)
		return id
	}
	owner, m1, m2 := member("owner"), member("member"), member("member")
	t.Cleanup(func() {
		_, _ = db.ExecContext(ctx, `DELETE FROM audit_logs WHERE tenant_id = $1`, tenantID)
		_, _ = db.ExecContext(ctx, `DELETE FROM user_roles WHERE tenant_id = $1`, tenantID)
		_, _ = db.ExecContext(ctx, `DELETE FROM roles WHERE tenant_id = $1`, tenantID)
		_, _ = db.ExecContext(ctx, `DELETE FROM tenant_members WHERE tenant_id = $1`, tenantID)
		_, _ = db.ExecContext(ctx, `DELETE FROM users WHERE id = ANY($1)`, "{"+owner+","+m1+","+m2+"}")
		_, _ = db.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID)
	})

	pg := &postgres.DB{DB: db}
	log := logger.NewNop()
	svc := accesscontrol.NewRoleService(postgres.NewRoleRepository(pg), postgres.NewPermissionRepository(pg), log,
		accesscontrol.WithRoleMembershipReader(postgres.NewTenantRepository(pg)),
		accesscontrol.WithRoleAuditService(audit.NewAuditService(postgres.NewAuditRepository(pg), log)))
	actx := audit.AuditContext{TenantID: tenantID, ActorID: owner, ActorEmail: "owner@it.test"}

	r, err := svc.CreateRole(ctx, accesscontrol.CreateRoleInput{TenantID: tenantID, Slug: "audit-readers",
		Name: "Audit readers", HierarchyLevel: 10, Permissions: []string{"assets:read"}}, owner, actx)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	roleID := r.ID().String()
	name := "Audit readers 2"
	if _, err := svc.UpdateRole(ctx, tenantID, roleID, accesscontrol.UpdateRoleInput{Name: &name}, actx); err != nil {
		t.Fatalf("update: %v", err)
	}
	if _, err := svc.BulkAssignRoleToUsers(ctx, accesscontrol.BulkAssignRoleToUsersInput{TenantID: tenantID,
		RoleID: roleID, UserIDs: []string{m1, m2}}, owner, actx); err != nil {
		t.Fatalf("bulk assign: %v", err)
	}
	for _, u := range []string{m1, m2} {
		if err := svc.RemoveRole(ctx, tenantID, u, roleID, actx); err != nil {
			t.Fatalf("remove: %v", err)
		}
	}
	if err := svc.DeleteRole(ctx, tenantID, roleID, actx); err != nil {
		t.Fatalf("delete: %v", err)
	}

	for action, want := range map[string]int{
		"role.created": 1, "role.updated": 1, "role.assigned": 1, "role.unassigned": 2, "role.deleted": 1,
	} {
		var n int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM audit_logs
			WHERE tenant_id = $1 AND action = $2 AND resource_id = $3 AND actor_id = $4`,
			tenantID, action, roleID, owner).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != want {
			t.Errorf("%s: %d audit rows by the acting user, want %d", action, n, want)
		}
	}
}
