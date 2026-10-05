package integration

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
)

// Migration 000945 (settings decision B1) strips admin-only permissions from
// custom roles, reports what it removed, and installs a trigger that refuses
// to put them back. The down migration restores the stripped rows. The test
// replays down -> up -> down -> up inside a rolled-back transaction as the
// migrator (the migration is DDL).
func TestMigration000945_StripsAdminOnlyPermissionsFromCustomRoles(t *testing.T) {
	ctx := context.Background()
	up, err := os.ReadFile("../../migrations/000945_custom_roles_admin_only_permissions.up.sql")
	if err != nil {
		t.Fatalf("read up: %v", err)
	}
	down, err := os.ReadFile("../../migrations/000945_custom_roles_admin_only_permissions.down.sql")
	if err != nil {
		t.Fatalf("read down: %v", err)
	}
	tx, err := testdb.OpenMigrator(t).BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	testdb.LockForDDL(t, ctx, tx, "roles", "role_permissions")
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := tx.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	has := func(roleID, perm string) bool {
		t.Helper()
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM role_permissions WHERE role_id = $1 AND permission_id = $2`,
			roleID, perm).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n > 0
	}

	// Back to the pre-migration schema (the test database is fully migrated).
	exec(string(down))

	tenantID, roleID, userID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'B1 migration IT', $2)`,
		tenantID, "b1-mig-"+strings.ReplaceAll(tenantID[:13], "-", ""))
	exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'B1 migration IT')`, userID, "b1-"+userID[:8]+"@it.test")
	exec(`INSERT INTO roles (id, tenant_id, slug, name, is_system, hierarchy_level) VALUES ($1, $2, 'sensor-ops', 'Sensor ops', FALSE, 10)`,
		roleID, tenantID)
	for _, p := range []string{"sensors:read", "sensors:write", "sensors:zones:delete"} {
		exec(`INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)`, roleID, p)
	}
	exec(`INSERT INTO user_roles (user_id, tenant_id, role_id) VALUES ($1, $2, $3)`, userID, tenantID, roleID)

	exec(string(up))
	if has(roleID, "sensors:write") || has(roleID, "sensors:zones:delete") {
		t.Fatal("admin-only permissions are still on the custom role")
	}
	if !has(roleID, "sensors:read") {
		t.Fatal("sensors:read was removed from the custom role")
	}
	const sysAdmin = "00000000-0000-0000-0000-000000000002"
	if !has(sysAdmin, "sensors:write") {
		t.Fatal("the system admin role lost sensors:write")
	}
	var holders int
	if err := tx.QueryRowContext(ctx, `SELECT holders FROM role_permissions_admin_only_stripped
		WHERE role_id = $1 AND permission_id = 'sensors:write'`, roleID).Scan(&holders); err != nil {
		t.Fatalf("report row: %v", err)
	}
	if holders != 1 {
		t.Fatalf("report holders = %d, want 1", holders)
	}

	// The trigger refuses to put one back.
	exec(`SAVEPOINT readd`)
	_, err = tx.ExecContext(ctx, `INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, 'sensors:delete')`, roleID)
	var pqErr *pq.Error
	if err == nil || !errors.As(err, &pqErr) || pqErr.Code != "23514" {
		t.Fatalf("re-adding sensors:delete to a custom role: want check_violation, got %v", err)
	}
	exec(`ROLLBACK TO SAVEPOINT readd`)

	// Down restores the stripped rows; up again strips them again.
	exec(string(down))
	if !has(roleID, "sensors:write") || !has(roleID, "sensors:zones:delete") {
		t.Fatal("down did not restore the stripped permissions")
	}
	exec(string(up))
	if has(roleID, "sensors:write") {
		t.Fatal("second up did not strip sensors:write")
	}
}
