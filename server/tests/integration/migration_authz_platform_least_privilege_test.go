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

	// Notification channels that exist before the migration: one with a NULL
	// value, one with no extension row, one that stored false, one new-style.
	const (
		chNull, chNone, chFalse = "c1111111-1111-4111-8111-111111111111", "c2222222-2222-4222-8222-222222222222", "c3333333-3333-4333-8333-333333333333"
	)
	for i, id := range []string{chNull, chNone, chFalse} {
		exec(`INSERT INTO integrations (id, tenant_id, name, category, provider, status, auth_type)
			VALUES ($1, $2, $3, 'notification', 'slack', 'connected', 'token')`, id, tenant, "ch"+string(rune('a'+i)))
	}
	exec(`ALTER TABLE integration_notification_extensions ALTER COLUMN include_details DROP NOT NULL`)
	exec(`INSERT INTO integration_notification_extensions (integration_id, include_details) VALUES ($1, NULL), ($2, false)`, chNull, chFalse)

	testdb.Migrate(t, db, dir, v, v, false)
	details := func(id string) (bool, bool) {
		t.Helper()
		var d bool
		err := db.QueryRow(`SELECT include_details FROM integration_notification_extensions WHERE integration_id = $1`, id).Scan(&d)
		return d, err == nil
	}
	if d, ok := details(chNull); !ok || !d {
		t.Errorf("up: NULL channel include_details = %v (row=%v), want true", d, ok)
	}
	if d, ok := details(chNone); !ok || !d {
		t.Errorf("up: channel without a row include_details = %v (row=%v), want true", d, ok)
	}
	if d, ok := details(chFalse); !ok || d {
		t.Errorf("up: channel that stored false include_details = %v (row=%v), want false", d, ok)
	}
	if _, err := db.Exec(`UPDATE integration_notification_extensions SET include_details = NULL WHERE integration_id = $1`, chNull); err == nil {
		t.Errorf("up: include_details accepts NULL")
	}
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
