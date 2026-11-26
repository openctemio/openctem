package integration

// Migration attack_paths_read_permission: attack_surface:paths:read is added
// and given to everyone who could read attack paths through assets:read (the
// owner, administrator and member system roles and every custom role holding
// assets:read), never to the viewer role or to a custom role without
// assets:read. API key scopes are not widened. Down removes it; up again
// gives the same grants.
//
// Runs on a private database: everything up to the migration before, seed,
// up, down, up.

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/server/internal/testdb"
)

func TestMigrationAttackPathsReadPermission(t *testing.T) {
	const dir = "../../migrations"
	v := testdb.MigrationVersion(t, dir, "attack_paths_read_permission")
	db := testdb.PrivateDatabase(t, "migpaths", dir)
	testdb.Migrate(t, db, dir, v, v, true)
	ctx := context.Background()

	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	const (
		owner      = "00000000-0000-0000-0000-000000000001"
		admin      = "00000000-0000-0000-0000-000000000002"
		member     = "00000000-0000-0000-0000-000000000003"
		viewer     = "00000000-0000-0000-0000-000000000004"
		tenantA    = "a1111111-1111-4111-8111-111111111111"
		roleReader = "e1111111-1111-4111-8111-111111111111" // custom role with assets:read
		roleOther  = "e2222222-2222-4222-8222-222222222222" // custom role without it
		keyID      = "f1111111-1111-4111-8111-111111111111"
		keyUser    = "d1111111-1111-4111-8111-111111111111"
	)
	exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'a', 'mig-paths-a')`, tenantA)
	exec(`INSERT INTO roles (id, tenant_id, slug, name, hierarchy_level) VALUES ($1, $3, 'inventory', 'Inventory', 20), ($2, $3, 'findings-only', 'Findings only', 20)`,
		roleReader, roleOther, tenantA)
	exec(`INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, 'assets:read'), ($2, 'findings:read')`, roleReader, roleOther)
	exec(`INSERT INTO users (id, email, name) VALUES ($1, 'key@migpaths.test', 'Key owner')`, keyUser)
	exec(`INSERT INTO api_keys (id, tenant_id, user_id, name, key_hash, key_prefix, scopes)
		VALUES ($1, $2, $3, 'reader', 'h-migpaths', 'oct_mp', ARRAY['assets:read'])`, keyID, tenantA, keyUser)

	holds := func(role string) bool {
		t.Helper()
		var n int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM role_permissions WHERE role_id = $1 AND permission_id = 'attack_surface:paths:read'`, role).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n == 1
	}
	check := func(round string) {
		t.Helper()
		for _, r := range []string{owner, admin, member, roleReader} {
			if !holds(r) {
				t.Errorf("%s: role %s lost attack paths", round, r)
			}
		}
		for _, r := range []string{viewer, roleOther} {
			if holds(r) {
				t.Errorf("%s: role %s was given attack paths", round, r)
			}
		}
		var scopes string
		if err := db.QueryRowContext(ctx, `SELECT array_to_string(scopes, ',') FROM api_keys WHERE id = $1`, keyID).Scan(&scopes); err != nil {
			t.Fatal(err)
		}
		if scopes != "assets:read" {
			t.Errorf("%s: API key scopes = %q, want them unchanged", round, scopes)
		}
	}

	testdb.Migrate(t, db, dir, v, v, false)
	check("up")
	testdb.Migrate(t, db, dir, v, v, true)
	var n int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM permissions WHERE id = 'attack_surface:paths:read'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("down left the permission: %d %v", n, err)
	}
	testdb.Migrate(t, db, dir, v, v, false)
	check("up again")
}
