package postgres

import (
	"testing"

	"github.com/openctemio/openctem/api/internal/testdb"
)

// The large jsonb/text/bytea columns store new values with lz4 (migration
// toast_lz4_large_columns), and the down migration returns them to the default.
func TestToastLZ4Migration_DB(t *testing.T) {
	dir := "../../../migrations"
	db := testdb.PrivateDatabase(t, "toast_lz4", dir)
	var lz4 bool
	if err := db.QueryRow(`SELECT EXISTS (SELECT 1 FROM pg_settings WHERE name = 'default_toast_compression' AND enumvals @> ARRAY['lz4'])`).Scan(&lz4); err != nil || !lz4 {
		t.Skip("this server was built without lz4")
	}
	count := func() int {
		t.Helper()
		var n int
		if err := db.QueryRow(`SELECT count(*) FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid
			WHERE a.attcompression = 'l' AND c.relnamespace = 'public'::regnamespace`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := count(); n != 11 {
		t.Fatalf("%d columns use lz4, want 11", n)
	}
	var stored string
	if err := db.QueryRow(`SELECT attcompression::text FROM pg_attribute WHERE attrelid = 'findings'::regclass AND attname = 'scanner_output'`).Scan(&stored); err != nil || stored != "l" {
		t.Fatalf("findings.scanner_output compression = %q (%v), want l", stored, err)
	}
	v := testdb.MigrationVersion(t, dir, "toast_lz4_large_columns")
	testdb.Migrate(t, db, dir, v, v, true)
	if n := count(); n != 0 {
		t.Fatalf("after down: %d columns still lz4", n)
	}
}
