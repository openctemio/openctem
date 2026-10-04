// Package testdb hands DB-backed tests their connection string, but only
// when it points at a disposable test database.
//
// Tests used to read DATABASE_URL directly. That is also the variable the
// running API uses, so `go test ./...` inside the API container, or in a
// shell that had it exported, ran every DB-backed test against the live
// database and left hundreds of test-* tenants and e2e-* users behind.
package testdb

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
)

// allowOverrideEnv names a database that may be used even though its name
// does not look like a test database. It must equal the database name, so
// a stale value cannot unlock a different database.
const allowOverrideEnv = "OPENCTEM_TEST_DB_ALLOW"

var warnOnce sync.Once

// URL returns DATABASE_URL when it names a test database, and "" otherwise.
// Callers keep their existing `if url == "" { t.Skip(...) }`, so an unsafe
// target skips the test instead of writing to it.
func URL() string {
	return guard(os.Getenv("DATABASE_URL"))
}

// MigratorURL is the connection for a test that runs DDL (replays a migration,
// alters a constraint) and so needs the schema owner. It is
// DATABASE_MIGRATE_URL when set, and URL otherwise. CI runs the DB tests as
// the least-privilege app role (deploy/postgres/least-privilege-roles.sql) with
// DATABASE_MIGRATE_URL pointing at the migrator, the way production splits
// them; a plain single-role setup keeps working unchanged.
func MigratorURL() string {
	if raw := os.Getenv("DATABASE_MIGRATE_URL"); raw != "" {
		return guard(raw)
	}
	return URL()
}

// RLSURL is URL for DATABASE_URL_RLS_TEST.
func RLSURL() string {
	return guard(os.Getenv("DATABASE_URL_RLS_TEST"))
}

func guard(raw string) string {
	if raw == "" {
		return ""
	}
	name := databaseName(raw)
	if IsTestDatabase(name) || (name != "" && os.Getenv(allowOverrideEnv) == name) {
		return raw
	}
	warnOnce.Do(func() {
		fmt.Fprintf(os.Stderr,
			"testdb: refusing database %q: DB-backed tests only run against a database whose name ends in _test or _compat (set %s=%s to override); skipping\n",
			name, allowOverrideEnv, name)
	})
	return ""
}

// IsTestDatabase reports whether name is a disposable test database.
func IsTestDatabase(name string) bool {
	return strings.HasSuffix(name, "_test") || strings.HasSuffix(name, "_compat")
}

// databaseName extracts the database name from a postgres URL or a
// key=value DSN. It returns "" when none is present.
func databaseName(raw string) string {
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil {
			return ""
		}
		if name := strings.TrimPrefix(u.Path, "/"); name != "" {
			return name
		}
		return u.Query().Get("dbname")
	}
	for _, field := range strings.Fields(raw) {
		if v, ok := strings.CutPrefix(field, "dbname="); ok {
			return strings.Trim(v, `'"`)
		}
	}
	return ""
}
