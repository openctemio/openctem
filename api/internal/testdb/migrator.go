package testdb

import (
	"database/sql"
	"testing"

	_ "github.com/lib/pq" // postgres driver
)

// OpenMigrator opens MigratorURL for a test that runs DDL, and closes it when
// the test ends. It skips the test when no test database is configured.
//
// Production connects the API as a role that may only read and write rows
// (deploy/postgres/least-privilege-roles.sql); only the migrator owns the
// schema. A test that replays a migration or alters a constraint therefore
// needs the migrator, while everything else keeps using URL (the app role).
func OpenMigrator(t testing.TB) *sql.DB {
	t.Helper()
	url := MigratorURL()
	if url == "" {
		t.Skip("DATABASE_URL / DATABASE_MIGRATE_URL not set to a test database")
	}
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Fatalf("testdb.OpenMigrator: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}
