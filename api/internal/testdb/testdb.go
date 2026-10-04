// Package testdb hands DB-backed tests their connection string, but only
// when it points at a disposable test database.
//
// Tests used to read DATABASE_URL directly. That is also the variable the
// running API uses, so `go test ./...` inside the API container, or in a
// shell that had it exported, ran every DB-backed test against the live
// database and left hundreds of test-* tenants and e2e-* users behind.
//
// Three outcomes, and none of them is a quiet one:
//
//   - DATABASE_URL names a test database (*_test, *_compat, or the exact name
//     in OPENCTEM_TEST_DB_ALLOW): URL returns it and the DB-backed tests run.
//   - DATABASE_URL is set to anything else: URL panics with the reason. The
//     destructive tests never get the URL, and the run fails instead of
//     reporting a green that skipped every DB test.
//   - DATABASE_URL is unset: URL returns "" and callers skip, which is how
//     the plain unit run works. With OPENCTEM_TEST_DB_REQUIRED=1 (set in CI's
//     Postgres job and by `make test-db`) URL panics instead, and Skipf fails
//     the test, so a run that was meant to hit the database never skips it.
package testdb

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
)

// allowOverrideEnv names a database that may be used even though its name
// does not look like a test database. It must equal the database name, so
// a stale value cannot unlock a different database.
const allowOverrideEnv = "OPENCTEM_TEST_DB_ALLOW"

// requiredEnv, when "1" or "true", means the DB-backed tests were asked for:
// a missing DATABASE_URL or an unreachable database fails instead of skipping.
const requiredEnv = "OPENCTEM_TEST_DB_REQUIRED"

// URL returns DATABASE_URL when it names a test database, and "" when it is
// unset. It panics when DATABASE_URL is set to a database that is not a test
// database, and when it is unset but OPENCTEM_TEST_DB_REQUIRED is on.
// Callers keep their existing `if url == "" { t.Skip(...) }`.
func URL() string {
	raw := os.Getenv("DATABASE_URL")
	if raw == "" && Required() {
		panic("testdb: " + requiredEnv + " is set but DATABASE_URL is empty: " +
			"point DATABASE_URL at a migrated database whose name ends in _test")
	}
	return mustGuard("DATABASE_URL", raw)
}

// MigratorURL is the connection for a test that runs DDL (replays a migration,
// alters a constraint) and so needs the schema owner. It is
// DATABASE_MIGRATE_URL when set, and URL otherwise. CI runs the DB tests as
// the least-privilege app role (deploy/postgres/least-privilege-roles.sql) with
// DATABASE_MIGRATE_URL pointing at the migrator, the way production splits
// them; a plain single-role setup keeps working unchanged.
func MigratorURL() string {
	if raw := os.Getenv("DATABASE_MIGRATE_URL"); raw != "" {
		return mustGuard("DATABASE_MIGRATE_URL", raw)
	}
	return URL()
}

// RLSURL is URL for DATABASE_URL_RLS_TEST. That database is optional even
// when the DB tests are required (CI does not create the RLS test role), so an
// unset value still skips; a set value that is not a test database panics.
func RLSURL() string {
	return mustGuard("DATABASE_URL_RLS_TEST", os.Getenv("DATABASE_URL_RLS_TEST"))
}

// Required reports whether OPENCTEM_TEST_DB_REQUIRED asks for the DB-backed
// tests to run (never skip).
func Required() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(requiredEnv))) {
	case "1", "true", "yes":
		return true
	}
	return false
}

// Skipf skips a DB-backed test whose database is unusable (unreachable, or
// the role cannot create a database), unless the DB tests are required, in
// which case it fails the test with the same message. New tests should use it
// in place of t.Skipf for database preconditions.
func Skipf(t testing.TB, format string, args ...any) {
	t.Helper()
	if Required() {
		t.Fatalf("testdb: DB-backed test cannot run but %s is set: "+format, append([]any{requiredEnv}, args...)...)
		return
	}
	t.Skipf(format, args...)
}

func mustGuard(envName, raw string) string {
	u, err := guard(raw)
	if err != nil {
		panic(fmt.Sprintf("testdb: %s: %v", envName, err))
	}
	return u
}

// guard returns raw when it names a test database, "" when raw is empty, and
// an error when raw names any other database. It never returns a non-test URL.
func guard(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	name := databaseName(raw)
	if IsTestDatabase(name) || (name != "" && os.Getenv(allowOverrideEnv) == name) {
		return raw, nil
	}
	if name == "" {
		return "", fmt.Errorf("refusing a connection string with no database name: " +
			"DB-backed tests only run against a database whose name ends in _test or _compat " +
			"(unset it to run only the unit tests)")
	}
	return "", fmt.Errorf("refusing database %q: DB-backed tests only run against a database whose name "+
		"ends in _test or _compat, and they write and delete rows. Unset it to run only the unit tests, "+
		"point it at a scratch *_test database, or set %s=%s if this database really is disposable",
		name, allowOverrideEnv, name)
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
