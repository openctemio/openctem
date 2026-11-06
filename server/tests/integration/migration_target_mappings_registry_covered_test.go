package integration

// Migration target_mappings_registry_covered_seed_rows: the seeded target
// mappings the asset type registry already declares are removed; seed rows
// that go beyond the registry and every row an administrator created stay.
// Up, down (the removed rows come back with their ids) and up again.

import (
	"testing"

	"github.com/openctemio/openctem/api/internal/testdb"
)

func TestMigrationTargetMappingsRegistryCovered(t *testing.T) {
	const dir = "../../migrations"
	db := testdb.PrivateDatabase(t, "migtargetmap", dir)
	v := testdb.MigrationVersion(t, dir, "target_mappings_registry_covered_seed_rows")

	count := func(where string) int {
		t.Helper()
		var n int
		if err := db.QueryRow(`SELECT count(*) FROM target_asset_type_mappings ` + where).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	// After up: only the seed rows that go beyond the registry are left.
	kept := count("")
	if kept == 0 || kept >= 38 {
		t.Fatalf("after up: %d rows, want the few seed rows beyond the registry", kept)
	}
	if n := count(`WHERE target_type = 'url' AND asset_type = 'website'`); n != 0 {
		t.Fatal("a registry pair (url -> website) must be removed")
	}
	if n := count(`WHERE target_type = 'host' AND asset_type = 'host'`); n != 1 {
		t.Fatal("a seed row beyond the registry (host -> host) must stay")
	}

	// Down restores all 38 seed rows.
	testdb.Migrate(t, db, dir, v, v, true)
	if n := count(""); n != 38 {
		t.Fatalf("after down: %d rows, want 38", n)
	}

	// A row an administrator created or took over is never removed.
	if _, err := db.Exec(`UPDATE target_asset_type_mappings SET created_by = gen_random_uuid()
		WHERE target_type = 'url' AND asset_type = 'website'`); err != nil {
		t.Fatal(err)
	}
	testdb.Migrate(t, db, dir, v, v, false)
	if n := count(`WHERE target_type = 'url' AND asset_type = 'website'`); n != 1 {
		t.Fatal("an administrator's row must survive the migration")
	}
	if n := count(""); n != kept+1 {
		t.Fatalf("after up again: %d rows, want %d", n, kept+1)
	}
}
