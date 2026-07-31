package postgres

import (
	"context"
	"database/sql"
	"os"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/shared"
)

// A scan with a schedule but no next_run_at is unreachable by the scheduler:
// ListDueForExecution requires `next_run_at IS NOT NULL`, so the row is never
// selected, never runs, and never errors — while every screen keeps calling it
// "daily". Four such rows were found on a live database, the oldest dormant
// since April.
//
// These tests pin the query that makes that state reportable, and pin the
// boundary conditions so it does not start flagging healthy rows.

func openInertDB(t *testing.T) *sql.DB {
	t.Helper()

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping inert-schedule tests")
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skipf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if err := db.PingContext(context.Background()); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	return db
}

// seedScheduleScan inserts a scan with the given schedule/status/next_run_at.
// nextRun nil means the column is left NULL — the state under test.
func seedScheduleScan(ctx context.Context, t *testing.T, db *sql.DB, tenantID shared.ID,
	scheduleType, status string, withNextRun bool,
) (shared.ID, string) {
	t.Helper()

	id := shared.NewID()
	name := "inert probe " + id.String()
	next := "NULL"
	if withNextRun {
		next = "NOW() + INTERVAL '1 day'"
	}

	//nolint:gosec // G201: scheduleType/status are test-local literals, and `next`
	// is one of two fixed strings above — no external input reaches this string.
	q := `INSERT INTO scans (id, tenant_id, name, scan_type, scanner_name, targets,
	                         status, schedule_type, agent_preference, timeout_seconds, next_run_at)
	      VALUES ($1, $2, $3, 'single', 'probe-scanner', ARRAY['example.test'],
	              $4, $5, 'tenant', 3600, ` + next + `)`
	if _, err := db.ExecContext(ctx, q, id.String(), tenantID.String(), name, status, scheduleType); err != nil {
		t.Fatalf("seed scan (%s/%s): %v", scheduleType, status, err)
	}
	return id, name
}

// contains reports whether the reported name list includes name.
func contains(names []string, name string) bool {
	for _, n := range names {
		if n == name {
			return true
		}
	}
	return false
}

// The case that actually happened: active, scheduled, no next_run_at.
func TestCountScheduledWithoutNextRun_FlagsInertScan(t *testing.T) {
	db := openInertDB(t)
	ctx := context.Background()
	repo := NewScanRepository(&DB{DB: db})

	tenantID := seedTestTenant(ctx, t, db)
	_, name := seedScheduleScan(ctx, t, db, tenantID, "daily", "active", false)

	count, names, err := repo.CountScheduledWithoutNextRun(ctx)
	if err != nil {
		t.Fatalf("CountScheduledWithoutNextRun: %v", err)
	}
	if count < 1 || !contains(names, name) {
		t.Errorf("a daily scan with next_run_at IS NULL must be reported; got count=%d names=%v — "+
			"unreported, it never runs and nothing says so", count, names)
	}
}

// A healthy scheduled scan must not be flagged, or the warning becomes noise
// and gets ignored exactly like the condition it is meant to surface.
func TestCountScheduledWithoutNextRun_IgnoresHealthyScan(t *testing.T) {
	db := openInertDB(t)
	ctx := context.Background()
	repo := NewScanRepository(&DB{DB: db})

	tenantID := seedTestTenant(ctx, t, db)
	_, name := seedScheduleScan(ctx, t, db, tenantID, "daily", "active", true)

	_, names, err := repo.CountScheduledWithoutNextRun(ctx)
	if err != nil {
		t.Fatalf("CountScheduledWithoutNextRun: %v", err)
	}
	if contains(names, name) {
		t.Error("a scan with next_run_at set is scheduled correctly and must not be reported")
	}
}

// A manual scan has no next_run_at by design — SetSchedule nils it deliberately.
// Flagging it would report the normal case as a fault.
func TestCountScheduledWithoutNextRun_IgnoresManualScan(t *testing.T) {
	db := openInertDB(t)
	ctx := context.Background()
	repo := NewScanRepository(&DB{DB: db})

	tenantID := seedTestTenant(ctx, t, db)
	_, name := seedScheduleScan(ctx, t, db, tenantID, "manual", "active", false)

	_, names, err := repo.CountScheduledWithoutNextRun(ctx)
	if err != nil {
		t.Fatalf("CountScheduledWithoutNextRun: %v", err)
	}
	if contains(names, name) {
		t.Error("manual scans have no next run by design and must not be reported")
	}
}

// A paused scan is not expected to run, so its missing next_run_at is not a
// fault either.
func TestCountScheduledWithoutNextRun_IgnoresPausedScan(t *testing.T) {
	db := openInertDB(t)
	ctx := context.Background()
	repo := NewScanRepository(&DB{DB: db})

	tenantID := seedTestTenant(ctx, t, db)
	_, name := seedScheduleScan(ctx, t, db, tenantID, "weekly", "paused", false)

	_, names, err := repo.CountScheduledWithoutNextRun(ctx)
	if err != nil {
		t.Fatalf("CountScheduledWithoutNextRun: %v", err)
	}
	if contains(names, name) {
		t.Error("a paused scan is not due to run; reporting it would be noise")
	}
}

// The condition this reports must genuinely be invisible to the scheduler —
// otherwise the warning describes a problem that does not exist. This asserts
// the two queries disagree in exactly the intended way.
func TestInertScanIsInvisibleToListDueForExecution(t *testing.T) {
	db := openInertDB(t)
	ctx := context.Background()
	repo := NewScanRepository(&DB{DB: db})

	tenantID := seedTestTenant(ctx, t, db)
	inertID, inertName := seedScheduleScan(ctx, t, db, tenantID, "daily", "active", false)

	// Even far in the future, the scheduler cannot see it.
	var far sql.NullTime
	if err := db.QueryRowContext(ctx, `SELECT NOW() + INTERVAL '10 years'`).Scan(&far); err != nil {
		t.Fatalf("compute future time: %v", err)
	}
	due, err := repo.ListDueForExecution(ctx, far.Time)
	if err != nil {
		t.Fatalf("ListDueForExecution: %v", err)
	}
	for _, s := range due {
		if s.ID == inertID {
			t.Fatal("precondition failed: the scheduler can see this scan, so it is not inert " +
				"and the warning would be wrong")
		}
	}

	_, names, err := repo.CountScheduledWithoutNextRun(ctx)
	if err != nil {
		t.Fatalf("CountScheduledWithoutNextRun: %v", err)
	}
	if !contains(names, inertName) {
		t.Error("the scan is invisible to the scheduler but not reported — the exact gap this closes")
	}
}
