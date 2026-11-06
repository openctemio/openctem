package integration

// Migration role_template_library: the built-in Researcher role becomes the
// "researcher" template. An organization that uses it (a member holds it or a
// pending invitation offers it) gets its own custom Researcher role with the
// same grants, and every assignment and invitation moves to it; organizations
// that never used it get nothing; the global row goes. The down migration
// moves everything back.
//
// Runs on a private database: everything up, the migration down, seed, then
// up, down and up again.

import (
	"database/sql"
	"slices"
	"sort"
	"testing"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
)

func TestMigrationRoleTemplateLibrary(t *testing.T) {
	const dir = "../../migrations"
	v := testdb.MigrationVersion(t, dir, "role_template_library")
	db := testdb.PrivateDatabase(t, "migrtl", dir)
	testdb.Migrate(t, db, dir, v, v, true)

	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	const (
		researcher = "00000000-0000-0000-0000-000000000005"
		viewer     = "00000000-0000-0000-0000-000000000004"
		tenantA    = "a1111111-1111-4111-8111-111111111111" // a member holds Researcher
		tenantB    = "b2222222-2222-4222-8222-222222222222" // never used it
		tenantC    = "c3333333-3333-4333-8333-333333333333" // an invitation offers it; has an old custom "researcher"
		userA      = "d1111111-1111-4111-8111-111111111111"
		userB      = "d2222222-2222-4222-8222-222222222222"
		inviter    = "d3333333-3333-4333-8333-333333333333"
		invA       = "e1111111-1111-4111-8111-111111111111"
		invC       = "e3333333-3333-4333-8333-333333333333"
		legacyC    = "f3333333-3333-4333-8333-333333333333"
	)
	exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'a', 'mig-rtl-a'), ($2, 'b', 'mig-rtl-b'), ($3, 'c', 'mig-rtl-c')`,
		tenantA, tenantB, tenantC)
	exec(`INSERT INTO users (id, email, name) VALUES ($1, 'a@migrtl.test', 'a'), ($2, 'b@migrtl.test', 'b'), ($3, 'i@migrtl.test', 'i')`,
		userA, userB, inviter)
	exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $3, 'viewer'), ($2, $4, 'viewer')`, userA, userB, tenantA, tenantB)
	exec(`INSERT INTO user_roles (user_id, tenant_id, role_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, userA, tenantA, researcher)
	exec(`INSERT INTO tenant_invitations (id, tenant_id, email, role, role_ids, token, invited_by, expires_at) VALUES
		($1, $3, 'x@migrtl.test', 'member', ARRAY[$5, $6]::uuid[], 'tok-a', $7, now() + interval '7 days'),
		($2, $4, 'y@migrtl.test', 'member', ARRAY[$5]::uuid[], 'tok-c', $7, now() + interval '7 days')`,
		invA, invC, tenantA, tenantC, researcher, viewer, inviter)
	// A custom role slugged "researcher" from before the slug was reserved.
	exec(`ALTER TABLE roles DROP CONSTRAINT roles_custom_slug_not_reserved`)
	exec(`INSERT INTO roles (id, tenant_id, slug, name, is_system, hierarchy_level) VALUES ($1, $2, 'researcher', 'Old researcher', false, 10)`,
		legacyC, tenantC)
	exec(`ALTER TABLE roles ADD CONSTRAINT roles_custom_slug_not_reserved
		CHECK (is_system OR lower(btrim(slug)) !~ '^(owner|admin|member|viewer|researcher)$') NOT VALID`)

	copyOf := func(tenant string) (id, slug string, perms []string, tplPerms []string, ok bool) {
		t.Helper()
		var tp pq.StringArray
		err := db.QueryRow(`SELECT id, slug, template_permissions FROM roles
			WHERE tenant_id = $1 AND template_id = 'researcher' AND template_version = 1 AND NOT is_system`, tenant).Scan(&id, &slug, &tp)
		if err == sql.ErrNoRows {
			return "", "", nil, nil, false
		}
		if err != nil {
			t.Fatal(err)
		}
		rows, err := db.Query(`SELECT permission_id FROM role_permissions WHERE role_id = $1 ORDER BY 1`, id)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		for rows.Next() {
			var p string
			if err := rows.Scan(&p); err != nil {
				t.Fatal(err)
			}
			perms = append(perms, p)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return id, slug, perms, []string(tp), true
	}
	count := func(q string, args ...any) int {
		t.Helper()
		var n int
		if err := db.QueryRow(q, args...).Scan(&n); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		return n
	}
	tpl, _ := permission.RoleTemplateByID("researcher")
	// The migration copies the built-in role as it was at this version, which
	// still held sensors:read; template v2 dropped it (later migration).
	want := append(permission.ToStrings(tpl.Permissions), "sensors:read")
	sort.Strings(want)

	checkUp := func() {
		t.Helper()
		if n := count(`SELECT count(*) FROM roles WHERE id = $1`, researcher); n != 0 {
			t.Fatalf("the built-in Researcher role is still there")
		}
		idA, slugA, permsA, tplPermsA, ok := copyOf(tenantA)
		if !ok || slugA != "researcher" {
			t.Fatalf("tenant A: no Researcher copy (ok=%v slug=%q)", ok, slugA)
		}
		if !slices.Equal(permsA, want) || !slices.Equal(tplPermsA, want) {
			t.Errorf("tenant A copy grants %v (template snapshot %v), want the template's %v", permsA, tplPermsA, want)
		}
		if n := count(`SELECT count(*) FROM user_roles WHERE user_id = $1 AND tenant_id = $2 AND role_id = $3`, userA, tenantA, idA); n != 1 {
			t.Errorf("tenant A member lost the Researcher assignment")
		}
		var roleIDs pq.StringArray
		if err := db.QueryRow(`SELECT role_ids FROM tenant_invitations WHERE id = $1`, invA).Scan(&roleIDs); err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(roleIDs, idA) || !slices.Contains(roleIDs, viewer) || slices.Contains(roleIDs, researcher) {
			t.Errorf("tenant A invitation role ids = %v, want the copy and viewer", roleIDs)
		}
		if _, _, _, _, ok := copyOf(tenantB); ok {
			t.Errorf("tenant B never used Researcher but got a copy")
		}
		idC, slugC, _, _, ok := copyOf(tenantC)
		if !ok || slugC != "researcher-role" {
			t.Errorf("tenant C copy slug = %q (ok=%v), want researcher-role next to its own researcher role", slugC, ok)
		}
		if err := db.QueryRow(`SELECT role_ids FROM tenant_invitations WHERE id = $1`, invC).Scan(&roleIDs); err != nil {
			t.Fatal(err)
		}
		if len(roleIDs) != 1 || roleIDs[0] != idC {
			t.Errorf("tenant C invitation role ids = %v, want [%s]", roleIDs, idC)
		}
		if n := count(`SELECT count(*) FROM roles WHERE id = $1`, legacyC); n != 1 {
			t.Errorf("tenant C's own researcher role was touched")
		}
		// The copy is an ordinary custom role: never another tenant's.
		if n := count(`SELECT count(*) FROM user_roles ur JOIN roles r ON r.id = ur.role_id
			WHERE r.template_id = 'researcher' AND r.tenant_id <> ur.tenant_id`); n != 0 {
			t.Errorf("%d assignments point at another organization's copy", n)
		}
	}

	testdb.Migrate(t, db, dir, v, v, false)
	checkUp()

	testdb.Migrate(t, db, dir, v, v, true)
	if n := count(`SELECT count(*) FROM user_roles WHERE user_id = $1 AND tenant_id = $2 AND role_id = $3`, userA, tenantA, researcher); n != 1 {
		t.Errorf("down: tenant A member is not back on the built-in role")
	}
	if n := count(`SELECT count(*) FROM roles WHERE NOT is_system AND name = 'Researcher'`); n != 0 {
		t.Errorf("down: %d copies left", n)
	}
	if n := count(`SELECT count(*) FROM tenant_invitations WHERE $1::uuid = ANY (role_ids)`, researcher); n != 2 {
		t.Errorf("down: %d invitations name the built-in role, want 2", n)
	}

	testdb.Migrate(t, db, dir, v, v, false)
	checkUp()
}
