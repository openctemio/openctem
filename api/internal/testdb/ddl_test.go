package testdb

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

// The lock cycle that made TestAssetStateHistory_AuditTriggers fail in CI
// with "deadlock detected": a writer holds assets and then needs tenants,
// while the DDL test holds tenants and waits for assets. LockForDDL must back
// off before Postgres picks a victim, so the writer finishes cleanly and the
// DDL test still gets both locks.
func TestLockForDDL_BacksOffBeforeADeadlock(t *testing.T) {
	dbURL := URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed test")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Ping(); err != nil {
		t.Skipf("cannot reach test DB: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	// The DDL transaction takes LockForDDL's advisory lock BEFORE the writer
	// locks assets. Other test packages run in parallel and serialise their
	// DDL on that advisory lock; if the writer held assets first, one of them
	// could hold the advisory lock while waiting for assets, and this test's
	// DDL would wait for the advisory lock: nobody moves until the timeout.
	// Advisory locks stack, so LockForDDL below takes it again without waiting.
	ddl, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ddl.Rollback() }()
	if _, err := ddl.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, ddlAdvisoryKey); err != nil {
		t.Fatal(err)
	}

	writer, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = writer.Rollback() }()
	if _, err := writer.ExecContext(ctx, `LOCK TABLE assets IN ROW EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	var ddlPID int
	if err := ddl.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&ddlPID); err != nil {
		t.Fatal(err)
	}

	// Once the DDL transaction holds tenants and waits for assets, the
	// writer asks for tenants: a lock cycle.
	writerErr := make(chan error, 1)
	go func() {
		err := func() error {
			for {
				var waiting bool
				if err := db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM pg_locks
					WHERE pid = $1 AND relation = 'assets'::regclass AND NOT granted)`, ddlPID).Scan(&waiting); err != nil {
					return err
				}
				if waiting {
					break
				}
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(10 * time.Millisecond):
				}
			}
			if _, err := writer.ExecContext(ctx, `LOCK TABLE tenants IN ROW EXCLUSIVE MODE`); err != nil {
				return err
			}
			return writer.Rollback()
		}()
		writerErr <- err
	}()

	LockForDDL(t, ctx, ddl, "tenants", "assets")

	if err := <-writerErr; err != nil {
		t.Fatalf("the concurrent writer failed: %v", err)
	}
	var held int
	if err := ddl.QueryRowContext(ctx, `SELECT count(*) FROM pg_locks
		WHERE pid = pg_backend_pid() AND mode = 'AccessExclusiveLock' AND granted
		  AND relation IN ('tenants'::regclass, 'assets'::regclass)`).Scan(&held); err != nil {
		t.Fatal(err)
	}
	if held != 2 {
		t.Fatalf("LockForDDL returned holding %d of the 2 table locks", held)
	}
	var lockTimeout string
	if err := ddl.QueryRowContext(ctx, `SELECT current_setting('lock_timeout')`).Scan(&lockTimeout); err != nil {
		t.Fatal(err)
	}
	if lockTimeout != "0" {
		t.Fatalf("lock_timeout left at %q, want the session's own 0", lockTimeout)
	}
}
