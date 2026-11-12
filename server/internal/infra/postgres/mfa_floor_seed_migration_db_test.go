package postgres

import (
	"encoding/json"
	"testing"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The two-factor floor seed: an instance that already has users keeps "none"
// (source migration, with the upgrade time as effective_from) so an upgrade
// never locks anyone out; an instance without users gets no row and falls to
// the code default.
func TestMFAFloorUpgradeSeedMigration_DB(t *testing.T) {
	dir := "../../../migrations"

	t.Run("populated instance gets the none row", func(t *testing.T) {
		db := testdb.PrivateDatabase(t, "mfa_floor_seed_pop", dir)
		ver := testdb.MigrationVersion(t, dir, "mfa_floor_upgrade_seed")
		testdb.Migrate(t, db, dir, ver, ver, true) // before the seed
		if _, err := db.Exec(`INSERT INTO users (id, email, name) VALUES ($1, 'seed-user@example.com', 'Seed')`, shared.NewID().String()); err != nil {
			t.Fatal(err)
		}
		testdb.Migrate(t, db, dir, ver, ver, false)

		var raw []byte
		var source string
		var version int
		if err := db.QueryRow(`SELECT value, source, version FROM platform_settings WHERE key = 'auth.mfa'`).Scan(&raw, &source, &version); err != nil {
			t.Fatalf("seed row: %v", err)
		}
		var got struct {
			Floor         string `json:"floor"`
			EffectiveFrom string `json:"effective_from"`
		}
		if err := json.Unmarshal(raw, &got); err != nil || got.Floor != "none" || got.EffectiveFrom == "" || source != "migration" || version != 1 {
			t.Fatalf("row %s source %q version %d err %v", raw, source, version, err)
		}

		// down removes it and up restores it.
		testdb.Migrate(t, db, dir, ver, ver, true)
		var n int
		if err := db.QueryRow(`SELECT count(*) FROM platform_settings WHERE key = 'auth.mfa'`).Scan(&n); err != nil || n != 0 {
			t.Fatalf("after down: %d rows, err %v", n, err)
		}
		testdb.Migrate(t, db, dir, ver, ver, false)
		if err := db.QueryRow(`SELECT count(*) FROM platform_settings WHERE key = 'auth.mfa'`).Scan(&n); err != nil || n != 1 {
			t.Fatalf("after up again: %d rows, err %v", n, err)
		}
	})

	t.Run("fresh instance gets no row", func(t *testing.T) {
		db := testdb.PrivateDatabase(t, "mfa_floor_seed_new", dir)
		var n int
		if err := db.QueryRow(`SELECT count(*) FROM platform_settings WHERE key = 'auth.mfa'`).Scan(&n); err != nil || n != 0 {
			t.Fatalf("fresh install: %d rows, err %v", n, err)
		}
	})
}
