package postgres

import (
	"context"
	"database/sql"
	"os"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/shared"
)

// A scheduled scan that can never start — NO_AGENT_AVAILABLE, which recurred
// silently for three nights on the live demo deployment — was
// indistinguishable from one that simply had not run yet: the scheduler
// advanced next_run_at (correctly, to avoid re-trigger storms) but recorded
// nothing about the failure, so last_run_at/last_run_status stayed NULL.
//
// RecordTriggerFailure makes that failure visible in the scan's own state.
// This test drives the real SQL and pins the two properties that matter: the
// failure IS recorded (last_run_status/last_run_at), and the run counters are
// NOT touched (no run existed — inflating total_runs would be a second lie).

func openScanDB(t *testing.T) *sql.DB {
	t.Helper()

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping scan trigger-failure DB test")
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

func seedScanTriggerTenant(ctx context.Context, t *testing.T, db *sql.DB) shared.ID {
	t.Helper()
	id := shared.NewID()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)`,
		id.String(), "scan trigger test", "scantrig-"+id.String()); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, id.String())
	})
	return id
}

func TestRecordTriggerFailure_RecordsFailureWithoutTouchingCounters(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	repo := NewScanRepository(&DB{DB: db})
	tenantID := seedScanTriggerTenant(ctx, t, db)

	scanID := shared.NewID()
	// Seed a scan with a known counter baseline so we can prove the counters
	// don't move.
	if _, err := db.ExecContext(ctx,
		`INSERT INTO scans (id, tenant_id, name, scan_type, scanner_name, total_runs, successful_runs, failed_runs)
		 VALUES ($1, $2, 'nightly probe', 'single', 'gitleaks', 5, 4, 1)`,
		scanID.String(), tenantID.String()); err != nil {
		t.Fatalf("seed scan: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM scans WHERE id = $1`, scanID.String())
	})

	if err := repo.RecordTriggerFailure(ctx, scanID, "failed"); err != nil {
		t.Fatalf("RecordTriggerFailure: %v", err)
	}

	var (
		lastRunStatus sql.NullString
		lastRunAt     sql.NullTime
		lastRunID     sql.NullString
		total, ok, ko int
	)
	if err := db.QueryRowContext(ctx,
		`SELECT last_run_status, last_run_at, last_run_id, total_runs, successful_runs, failed_runs
		   FROM scans WHERE id = $1`, scanID.String(),
	).Scan(&lastRunStatus, &lastRunAt, &lastRunID, &total, &ok, &ko); err != nil {
		t.Fatalf("read back: %v", err)
	}

	// The failure is now visible.
	if !lastRunStatus.Valid || lastRunStatus.String != "failed" {
		t.Errorf("last_run_status = %v, want \"failed\": a scan that failed to "+
			"dispatch must not read as never-run", lastRunStatus)
	}
	if !lastRunAt.Valid {
		t.Error("last_run_at is NULL after a recorded trigger failure — the failure " +
			"is still invisible in the scan's own state")
	}
	// No run existed, so there is no run id and the counters must be untouched.
	if lastRunID.Valid {
		t.Errorf("last_run_id = %q; a trigger that never created a run must not "+
			"point at one", lastRunID.String)
	}
	if total != 5 || ok != 4 || ko != 1 {
		t.Errorf("counters moved: total=%d ok=%d failed=%d, want 5/4/1 — a failed "+
			"trigger created no run and must not inflate the run counters", total, ok, ko)
	}
}
