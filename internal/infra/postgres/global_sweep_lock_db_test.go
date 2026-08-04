package postgres

import (
	"context"
	"database/sql"
	"testing"
)

// Several repository sweeps are deliberately GLOBAL — RecoverStuckJobs,
// ExpireOldPlatformJobs, MarkStaleAsOffline and the recover_stuck_* SQL
// functions all operate across every tenant, because that is what a background
// reaper does.
//
// That makes them untestable in parallel against a shared database, and two
// packages share one: internal/infra/postgres and tests/integration. `go test
// ./...` runs their binaries concurrently.
//
// The collision is mechanically certain but has NOT been observed failing.
// platform_job_lifecycle_db_test seeds a non-platform command, acknowledged, 120
// minutes old, with a tenant agent, and asserts the PLATFORM sweep leaves it
// alone. `recover_stuck_tenant_commands(10, 3)`, called from
// tests/integration/command_recovery_test, selects on exactly those columns:
// is_platform_job = FALSE, status = 'acknowledged', agent_id IS NOT NULL,
// acknowledged_at older than the threshold, dispatch_attempts under the cap. Run
// against that row by hand it returns 1 and rewrites it to pending/1 — precisely
// what the assertion forbids.
//
// What has not happened is the two landing together by chance: 120 concurrent
// rounds of both packages produced no failure, because each test seeds, sweeps
// and asserts inside ~20-80ms. So this is a latent hazard, not a flake anyone is
// currently suffering. It is worth closing anyway — the window widens with -race
// (which CI uses), with a loaded runner, and with every test added to either
// package — but it should not be sold as a fix for observed CI noise.
//
// A serializing lock is the honest fix. Weakening the assertions would remove
// the thing they exist to catch, and `-p 1` would serialize 91 packages to
// discipline two.
//
// The same helper exists in tests/integration. Keeping a copy rather than
// introducing a shared testutil package is deliberate: it is nine lines, and the
// lock key is the contract between them — that must be identical, and it is
// easier to see that when both files state it.
const globalSweepLockKey = 8_845_120_301 // arbitrary, must match tests/integration

// lockGlobalSweep serializes a test that runs a cross-tenant sweep against every
// other such test, in this package and in tests/integration. Call it once at the
// top of the test and defer the returned release:
//
//	defer lockGlobalSweep(ctx, t, db)()
//
// It must wrap the WHOLE test, not just the sweep call. The race is between one
// package's seed and its assertion: a sweep from the other package landing in
// that window recovers the row out from under it. Locking only the sweep call
// would leave exactly that window open.
func lockGlobalSweep(ctx context.Context, t *testing.T, db *sql.DB) func() {
	t.Helper()

	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatalf("global sweep lock: acquire connection: %v", err)
	}

	// Session-level, not transaction-level: the sweeps under test run their own
	// statements on other pool connections, so the lock must outlive any single
	// transaction.
	if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", globalSweepLockKey); err != nil {
		_ = conn.Close()
		t.Fatalf("global sweep lock: %v", err)
	}

	return func() {
		// context.Background(): the test's context may already be canceled, and
		// failing to unlock would block every later sweep test in the run.
		if _, err := conn.ExecContext(context.Background(),
			"SELECT pg_advisory_unlock($1)", globalSweepLockKey); err != nil {
			t.Errorf("global sweep unlock: %v — later tests in this run may block", err)
		}
		_ = conn.Close()
	}
}
