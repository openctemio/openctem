package integration

// Migration automations_permissions: findings:workflows:{read,write} become
// automations:{read,write} one to one (roles, template snapshots, API key
// scopes); every holder of automations:write also gets automations:publish;
// a role that only read keeps only read. Down gives the old ids back.

import (
	"testing"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
)

func TestMigrationAutomationsPermissions(t *testing.T) {
	const dir = "../../migrations"
	db := testdb.PrivateDatabase(t, "migautoperm", dir)
	v := testdb.MigrationVersion(t, dir, "automations_permissions")
	testdb.Migrate(t, db, dir, v, v, true)

	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	const (
		tenant = "a1111111-1111-4111-8111-111111111161"
		editor = "e1111111-1111-4111-8111-111111111161"
		reader = "e1111111-1111-4111-8111-111111111162"
	)
	exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'a', 'mig-autoperm-a')`, tenant)
	exec(`INSERT INTO roles (id, tenant_id, slug, name, is_system, hierarchy_level) VALUES ($1, $3, 'ed', 'ed', false, 10), ($2, $3, 'rd', 'rd', false, 10)`, editor, reader, tenant)
	exec(`INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, 'findings:workflows:read'), ($1, 'findings:workflows:write'), ($2, 'findings:workflows:read')`, editor, reader)

	testdb.Migrate(t, db, dir, v, v, false)

	perms := func(role string) []string {
		var p pq.StringArray
		if err := db.QueryRow(`SELECT array_agg(permission_id ORDER BY permission_id) FROM role_permissions WHERE role_id = $1`, role).Scan(&p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if got := perms(editor); len(got) != 3 || got[0] != "automations:publish" || got[1] != "automations:read" || got[2] != "automations:write" {
		t.Fatalf("editor = %v", got)
	}
	if got := perms(reader); len(got) != 1 || got[0] != "automations:read" {
		t.Fatalf("reader = %v", got)
	}
	for _, sys := range []string{"00000000-0000-0000-0000-000000000001", "00000000-0000-0000-0000-000000000002"} {
		var n int
		_ = db.QueryRow(`SELECT count(*) FROM role_permissions WHERE role_id = $1 AND permission_id = 'automations:publish'`, sys).Scan(&n)
		if n != 1 {
			t.Errorf("system role %s has no automations:publish", sys)
		}
	}
	var old int
	_ = db.QueryRow(`SELECT count(*) FROM permissions WHERE id LIKE 'findings:workflows:%'`).Scan(&old)
	if old != 0 {
		t.Fatal("old permission ids remain")
	}

	testdb.Migrate(t, db, dir, v, v, true)
	if got := perms(editor); len(got) != 2 || got[0] != "findings:workflows:read" || got[1] != "findings:workflows:write" {
		t.Fatalf("editor after down = %v", got)
	}
	testdb.Migrate(t, db, dir, v, v, false)
}
