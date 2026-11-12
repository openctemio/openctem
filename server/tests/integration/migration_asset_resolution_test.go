package integration

// Migration asset_resolution: the state table up and down and up again, and
// the wildcard-only marks (which held no proof of a wildcard record) cleared.

import (
	"testing"

	"github.com/openctemio/openctem/api/internal/testdb"
)

func TestMigrationAssetResolution(t *testing.T) {
	const dir = "../../migrations"
	db := testdb.PrivateDatabase(t, "migassetres", dir)
	v := testdb.MigrationVersion(t, dir, "asset_resolution")
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	const (
		tenant = "a1111111-1111-4111-8111-111111111181"
		asset  = "e5555555-5555-4555-8555-555555555581"
	)
	testdb.Migrate(t, db, dir, v, v, true)
	exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'a', 'mig-assetres-a')`, tenant)
	exec(`INSERT INTO assets (id, tenant_id, name, asset_type, status) VALUES ($1, $2, 'gone.example.com', 'subdomain', 'active')`, asset, tenant)
	exec(`INSERT INTO asset_wildcard_dns (tenant_id, asset_id, observed_at) VALUES ($1, $2, now())`, tenant, asset)

	testdb.Migrate(t, db, dir, v, v, false)
	var marks int
	if err := db.QueryRow(`SELECT count(*) FROM asset_wildcard_dns`).Scan(&marks); err != nil || marks != 0 {
		t.Fatalf("%d wildcard marks left (%v), want none", marks, err)
	}
	exec(`INSERT INTO asset_resolution (tenant_id, asset_id, state, checked_at, failures) VALUES ($1, $2, 'not_resolving', now(), 2)`, tenant, asset)
	if _, err := db.Exec(`INSERT INTO asset_resolution (tenant_id, asset_id, state, checked_at) VALUES ($1, $2, 'bogus', now())`, tenant, "e5555555-5555-4555-8555-555555555582"); err == nil {
		t.Fatal("an unknown state was accepted")
	}
	// Down drops the table; up again creates it.
	testdb.Migrate(t, db, dir, v, v, true)
	testdb.Migrate(t, db, dir, v, v, false)
}
