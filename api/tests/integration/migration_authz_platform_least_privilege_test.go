package integration

// Migration authz_platform_least_privilege: Researcher copies lose
// sensors:read (template v2), the built-in Member role loses
// scans:secret_store:write, and new notification channels default to the
// minimal message. The down migration restores all three.

import (
	"testing"

	"github.com/openctemio/openctem/api/internal/testdb"
)

func TestMigrationAuthzPlatformLeastPrivilege(t *testing.T) {
	const dir = "../../migrations"
	v := testdb.MigrationVersion(t, dir, "authz_platform_least_privilege")
	db := testdb.PrivateDatabase(t, "migapl", dir) // at head: the migration is applied
	const (
		tenant = "a1111111-1111-4111-8111-111111111111"
		role   = "b1111111-1111-4111-8111-111111111111"
		member = "00000000-0000-0000-0000-000000000003"
	)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	has := func(roleID, perm string) bool {
		t.Helper()
		var n int
		if err := db.QueryRow(`SELECT count(*) FROM role_permissions WHERE role_id = $1 AND permission_id = $2`, roleID, perm).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n == 1
	}
	exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'a', 'mig-apl-a')`, tenant)

	// State before the migration: a Researcher copy at v1 with sensors:read.
	testdb.Migrate(t, db, dir, v, v, true)
	exec(`INSERT INTO roles (id, tenant_id, slug, name, is_system, hierarchy_level, template_id, template_version, template_permissions)
		VALUES ($1, $2, 'researcher', 'Researcher', false, 30, 'researcher', 1, ARRAY['assets:read','sensors:read'])`, role, tenant)
	exec(`INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, 'assets:read'), ($1, 'sensors:read')`, role)
	if !has(member, "scans:secret_store:write") {
		t.Fatal("before: Member does not hold scans:secret_store:write")
	}

	testdb.Migrate(t, db, dir, v, v, false)
	if has(role, "sensors:read") || !has(role, "assets:read") {
		t.Errorf("up: Researcher copy grants wrong (sensors:read=%v)", has(role, "sensors:read"))
	}
	var version int
	if err := db.QueryRow(`SELECT template_version FROM roles WHERE id = $1`, role).Scan(&version); err != nil || version != 2 {
		t.Errorf("up: template_version = %d (%v), want 2", version, err)
	}
	if has(member, "scans:secret_store:write") || !has(member, "scans:secret_store:read") {
		t.Errorf("up: Member secret store grants wrong")
	}
	var def string
	if err := db.QueryRow(`SELECT column_default FROM information_schema.columns
		WHERE table_name = 'integration_notification_extensions' AND column_name = 'include_details'`).Scan(&def); err != nil || def != "false" {
		t.Errorf("up: include_details default = %q (%v), want false", def, err)
	}

	testdb.Migrate(t, db, dir, v, v, true)
	if !has(role, "sensors:read") || !has(member, "scans:secret_store:write") {
		t.Errorf("down: grants not restored")
	}
	testdb.Migrate(t, db, dir, v, v, false)
	if has(role, "sensors:read") {
		t.Errorf("up again: sensors:read back")
	}
}
