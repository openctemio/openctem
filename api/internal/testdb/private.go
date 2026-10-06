package testdb

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	_ "github.com/lib/pq" // the "postgres" driver
)

// PrivateDatabase creates a database for this test alone, applies every
// *.up.sql in migrationsDir to it in order, and drops it when the test ends.
//
// `go test ./...` runs every package at once against the one test database.
// A test that reasons about a whole table (every administrator, every row of
// the schema) or empties one to start clean must use a private database:
// otherwise it removes rows that another package's test is still using, and
// that test fails at random (a deleted administrator turns its next write into
// a foreign key violation).
//
// The name ends in _test, so URL's guard accepts it. Skipped unless
// DATABASE_URL names a test database and the role may create databases
// (with OPENCTEM_TEST_DB_REQUIRED on, those preconditions fail instead).
//
// Creating a database and applying migrations needs more than the API's
// least-privilege role, so when DATABASE_ADMIN_URL is set (the least-privilege
// CI job sets it to the superuser) the private database is created, migrated
// and used through it; otherwise through DATABASE_URL as before.
func PrivateDatabase(t testing.TB, prefix, migrationsDir string) *sql.DB {
	t.Helper()
	base := AdminURL()
	if base == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed test")
	}
	server, err := sql.Open("postgres", base)
	if err != nil {
		t.Fatalf("testdb: open: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	if err := server.Ping(); err != nil {
		Skipf(t, "testdb: cannot reach DATABASE_URL: %v", err)
	}

	suffix := make([]byte, 6)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatal(err)
	}
	name := prefix + "_" + hex.EncodeToString(suffix) + "_test"
	if _, err := server.Exec(`CREATE DATABASE ` + name); err != nil {
		Skipf(t, "testdb: cannot create a private test database: %v", err)
	}
	t.Cleanup(func() { _, _ = server.Exec(`DROP DATABASE IF EXISTS ` + name + ` WITH (FORCE)`) })

	u, err := url.Parse(base)
	if err != nil {
		t.Fatalf("testdb: parse DATABASE_URL: %v", err)
	}
	u.Path = "/" + name
	db, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatalf("testdb: open private database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	Migrate(t, db, migrationsDir, 0, math.MaxInt, false)
	return db
}

// Migrate applies, one file per statement batch as golang-migrate does, the
// migrations of migrationsDir whose version lies in [from, to]: the up files
// in ascending order, or with down the down files in descending order.
func Migrate(t testing.TB, db *sql.DB, migrationsDir string, from, to int, down bool) {
	t.Helper()
	suffix := ".up.sql"
	if down {
		suffix = ".down.sql"
	}
	files, err := filepath.Glob(filepath.Join(migrationsDir, "*"+suffix))
	if err != nil || len(files) == 0 {
		t.Fatalf("testdb: no migrations in %s: %v", migrationsDir, err)
	}
	sort.Strings(files)
	if down {
		slices.Reverse(files)
	}
	applied := 0
	for _, f := range files {
		name := filepath.Base(f)
		version, err := strconv.Atoi(name[:strings.IndexByte(name, '_')])
		if err != nil {
			t.Fatalf("testdb: migration %s has no numeric version: %v", name, err)
		}
		if version < from || version > to {
			continue
		}
		body, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(string(body)); err != nil {
			t.Fatalf("testdb: migrate %s: %v", name, err)
		}
		applied++
	}
	if applied == 0 {
		t.Fatalf("testdb: no %s migration in [%d, %d] in %s", suffix, from, to, migrationsDir)
	}
}
