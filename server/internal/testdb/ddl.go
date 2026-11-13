package testdb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// ddlAdvisoryKey serializes the tests that run DDL inside a rolled-back
// transaction. Any fixed bigint works; this is "octddl" in ASCII.
const ddlAdvisoryKey int64 = 0x6f6374646466

// lockNotAvailable is SQLSTATE 55P03, what LOCK returns when lock_timeout
// expires.
const lockNotAvailable = "55P03"

// ddlLockTimeout bounds how long a test waits for its tables to be free.
const ddlLockTimeout = 2 * time.Minute

// LockForDDL takes ACCESS EXCLUSIVE locks on tables inside tx, for a test
// that runs DDL (ALTER TABLE, CREATE OR REPLACE VIEW, a migration file) in a
// transaction it rolls back. It must be the first statement in tx. List the
// tables parent first (tenants before assets), the order the API's own
// writes take them in.
//
// `go test ./...` runs every package at once against the one test database,
// so other tests hold locks on hot tables like tenants and assets all the
// time. An ALTER TABLE that waits for one table while already holding
// another closes a lock cycle with a test that inserted a tenant and now
// wants to insert an asset, and after deadlock_timeout Postgres aborts one of
// the two with "deadlock detected" (40P01), which may be either test.
//
// LockForDDL never stays in such a cycle long enough to be detected:
//
//   - a transaction-scoped advisory lock first queues the DDL tests behind
//     each other, while this transaction holds nothing yet;
//   - then it locks all of tables in one LOCK statement under a lock_timeout
//     of half the server's deadlock_timeout. Waiting in the lock queue (not
//     NOWAIT) keeps it from being starved by a steady stream of short
//     transactions; giving up before deadlock_timeout means a cycle it is
//     part of is broken by its own timeout, before Postgres would pick a
//     victim. The savepoint rollback releases whatever that attempt got and
//     it tries again.
//
// Once it returns, the DDL on tables needs no further lock that another test
// could be holding. Other tests touching tables just wait until tx ends.
func LockForDDL(t testing.TB, ctx context.Context, tx *sql.Tx, tables ...string) {
	t.Helper()
	if len(tables) == 0 {
		t.Fatal("testdb.LockForDDL: no tables given")
	}
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, ddlAdvisoryKey); err != nil {
		t.Fatalf("testdb.LockForDDL: advisory lock: %v", err)
	}
	var origLockTimeout string
	var deadlockTimeoutMS int64
	if err := tx.QueryRowContext(ctx, `SELECT current_setting('lock_timeout'),
		(SELECT setting::bigint FROM pg_settings WHERE name = 'deadlock_timeout')`).Scan(&origLockTimeout, &deadlockTimeoutMS); err != nil {
		t.Fatalf("testdb.LockForDDL: read timeouts: %v", err)
	}
	attemptTimeout := max(deadlockTimeoutMS/2, 10)

	quoted := make([]string, len(tables))
	for i, name := range tables {
		quoted[i] = quoteQualified(name)
	}
	lockStmt := "LOCK TABLE " + strings.Join(quoted, ", ") + " IN ACCESS EXCLUSIVE MODE"

	deadline := time.Now().Add(ddlLockTimeout)
	for attempt := 1; ; attempt++ {
		if _, err := tx.ExecContext(ctx, `SAVEPOINT testdb_lock_for_ddl`); err != nil {
			t.Fatalf("testdb.LockForDDL: savepoint: %v", err)
		}
		if _, err := tx.ExecContext(ctx, `SELECT set_config('lock_timeout', $1, true)`, fmt.Sprintf("%dms", attemptTimeout)); err != nil {
			t.Fatalf("testdb.LockForDDL: set lock_timeout: %v", err)
		}
		_, err := tx.ExecContext(ctx, lockStmt)
		if err == nil {
			if _, err := tx.ExecContext(ctx, `RELEASE SAVEPOINT testdb_lock_for_ddl`); err != nil {
				t.Fatalf("testdb.LockForDDL: release savepoint: %v", err)
			}
			if _, err := tx.ExecContext(ctx, `SELECT set_config('lock_timeout', $1, true)`, origLockTimeout); err != nil {
				t.Fatalf("testdb.LockForDDL: restore lock_timeout: %v", err)
			}
			return
		}
		// Also undoes the lock_timeout change and releases what this
		// attempt locked.
		if _, rbErr := tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT testdb_lock_for_ddl`); rbErr != nil {
			t.Fatalf("testdb.LockForDDL: rollback to savepoint after %v: %v", err, rbErr)
		}
		if sqlState(err) != lockNotAvailable {
			t.Fatalf("testdb.LockForDDL: %s: %v", lockStmt, err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("testdb.LockForDDL: %s still busy after %d attempts over %s; a test is holding one of them open",
				strings.Join(tables, ", "), attempt, ddlLockTimeout)
		}
		if err := ctx.Err(); err != nil {
			t.Fatalf("testdb.LockForDDL: %v", err)
		}
	}
}

// sqlState returns the SQLSTATE of a lib/pq or pgx error, or "".
func sqlState(err error) string {
	var s interface{ SQLState() string }
	if errors.As(err, &s) {
		return s.SQLState()
	}
	return ""
}

// quoteQualified quotes a table name, keeping an optional schema prefix.
func quoteQualified(name string) string {
	parts := strings.Split(name, ".")
	for i, p := range parts {
		parts[i] = `"` + strings.ReplaceAll(p, `"`, `""`) + `"`
	}
	return strings.Join(parts, ".")
}
