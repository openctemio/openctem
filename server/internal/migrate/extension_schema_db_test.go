package migrate_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/internal/adminbootstrap"
	"github.com/openctemio/openctem/server/internal/migrate"
	"github.com/openctemio/openctem/server/internal/testdb"
)

// A database that ran an extension build (docs/development/editions.md) has
// the extension's own schema next to the core one, with its own migration
// tracker. A Community build on that database (a rollback, or a database
// restored from an extension install) must migrate up and down and start
// exactly as on a clean database, and must leave the extension schema alone.
// The extension tables here deliberately reuse core table names, with
// incompatible columns, so a probe that is not limited to the core schema
// fails this test.
func TestCommunityIgnoresAnExtensionSchema_DB(t *testing.T) {
	db := testdb.EmptyDatabase(t, "extschema")
	ctx := context.Background()
	for _, s := range []string{
		`CREATE SCHEMA acme_ext`,
		`CREATE TABLE acme_ext.schema_migrations (version bigint PRIMARY KEY, dirty boolean NOT NULL)`,
		`INSERT INTO acme_ext.schema_migrations VALUES (99990101000000, true)`,
		`CREATE TABLE acme_ext.schema_migrations_applied (version bigint PRIMARY KEY, name text NOT NULL)`,
		`INSERT INTO acme_ext.schema_migrations_applied VALUES (99990101000000, 'extension_only')`,
		`CREATE TABLE acme_ext.admin_users (id int PRIMARY KEY, api_key_hash text NOT NULL)`,
		`CREATE TABLE acme_ext.tenants (id int PRIMARY KEY, secret text)`,
		`INSERT INTO acme_ext.tenants VALUES (1, 'extension data')`,
	} {
		if _, err := db.ExecContext(ctx, s); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}

	dir := filepath.Join("..", "..", "migrations")
	ms, err := migrate.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	rels, err := migrate.LoadReleases(dir)
	if err != nil {
		t.Fatal(err)
	}
	r := &migrate.Runner{DB: db, Migrations: ms, Takeover: migrate.Takeover{Releases: rels}, LockTimeout: 30 * time.Second}

	if _, err := r.Up(ctx); err != nil {
		t.Fatalf("core up on a database with an extension schema: %v", err)
	}
	// What the server checks at start: every shipped migration applied,
	// read from the core tracker, not the extension's (dirty) one.
	rep, err := migrate.Inspect(ctx, db, ms, migrate.Takeover{Releases: rels})
	if err != nil || len(rep.Pending) != 0 || rep.Dirty || len(rep.Unknown) != 0 {
		t.Fatalf("start-up schema check: pending %d dirty %v unknown %v err %v", len(rep.Pending), rep.Dirty, rep.Unknown, err)
	}
	// The administrator bootstrap probes the core admin_users, not the
	// extension's table of the same name.
	if err := adminbootstrap.CheckSchema(ctx, db); err != nil {
		t.Fatalf("admin bootstrap schema check: %v", err)
	}

	if _, err := r.Down(ctx, 1); err != nil {
		t.Fatalf("core down 1: %v", err)
	}
	if _, err := r.Up(ctx); err != nil {
		t.Fatalf("core up again: %v", err)
	}

	var secret string
	var dirty bool
	if err := db.QueryRowContext(ctx, `SELECT secret FROM acme_ext.tenants WHERE id = 1`).Scan(&secret); err != nil || secret != "extension data" {
		t.Fatalf("extension data changed: %q %v", secret, err)
	}
	if err := db.QueryRowContext(ctx, `SELECT dirty FROM acme_ext.schema_migrations`).Scan(&dirty); err != nil || !dirty {
		t.Fatalf("extension tracker changed: %v %v", dirty, err)
	}
}
