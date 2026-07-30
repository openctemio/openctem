package postgres

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/shared"
)

// MarkTimedOutRuns is the only thing that ends a pipeline run nobody reports
// back on, so a run it cannot reach never ends at all. It used to reach runs by
// joining pipeline_runs to scans, which silently excluded every run whose
// scan_id was NULL — and fk_pipeline_runs_scan is ON DELETE SET NULL, so
// deleting a scan while its run was in flight produced exactly that. Two runs
// were found stuck 'running' for 14 days on the live database.
//
// These tests pin both directions: the runs the old query missed are now
// reaped, and the ones it correctly handled still behave the same.

func openTimeoutDB(t *testing.T) *sql.DB {
	t.Helper()

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping MarkTimedOutRuns tests")
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

// seedTimeoutTemplate creates a throwaway pipeline template to hang runs off.
func seedTimeoutTemplate(ctx context.Context, t *testing.T, db *sql.DB, tenantID shared.ID) shared.ID {
	t.Helper()

	id := shared.NewID()
	_, err := db.ExecContext(ctx,
		`INSERT INTO pipeline_templates (id, tenant_id, name) VALUES ($1, $2, $3)`,
		id.String(), tenantID.String(), "timeout probe "+id.String())
	if err != nil {
		t.Fatalf("seed template: %v", err)
	}
	return id
}

// seedTimeoutScan creates a scan with the given timeout. `targets` satisfies
// chk_scan_has_targets and scanner_name satisfies scans_chk_single_has_scanner.
func seedTimeoutScan(ctx context.Context, t *testing.T, db *sql.DB, tenantID shared.ID, timeoutSeconds int) shared.ID {
	t.Helper()

	id := shared.NewID()
	_, err := db.ExecContext(ctx,
		`INSERT INTO scans (id, tenant_id, name, scan_type, scanner_name, targets, timeout_seconds)
		 VALUES ($1, $2, $3, 'single', 'probe-scanner', ARRAY['example.test'], $4)`,
		id.String(), tenantID.String(), "timeout probe "+id.String(), timeoutSeconds)
	if err != nil {
		t.Fatalf("seed scan (timeout=%d): %v", timeoutSeconds, err)
	}
	return id
}

// seedRun inserts a run started `startedAgo` in the past. scanID nil means the
// run has no scan — the case the old join could not see.
func seedRun(ctx context.Context, t *testing.T, db *sql.DB, tenantID, templateID shared.ID, scanID *shared.ID, status string, startedAgo time.Duration) shared.ID {
	t.Helper()

	id := shared.NewID()
	var scanArg any
	if scanID != nil {
		scanArg = scanID.String()
	}

	_, err := db.ExecContext(ctx,
		`INSERT INTO pipeline_runs (id, pipeline_id, tenant_id, scan_id, trigger_type, status, started_at)
		 VALUES ($1, $2, $3, $4, 'manual', $5, NOW() - make_interval(secs => $6))`,
		id.String(), templateID.String(), tenantID.String(), scanArg, status, startedAgo.Seconds())
	if err != nil {
		t.Fatalf("seed run: %v", err)
	}
	return id
}

func runStatus(ctx context.Context, t *testing.T, db *sql.DB, id shared.ID) (status string, errMsg sql.NullString) {
	t.Helper()
	if err := db.QueryRowContext(ctx,
		`SELECT status, error_message FROM pipeline_runs WHERE id = $1`, id.String()).
		Scan(&status, &errMsg); err != nil {
		t.Fatalf("read run status: %v", err)
	}
	return status, errMsg
}

// The regression that matters: a run with no scan, well past the absolute
// ceiling. The old query joined `FROM scans s WHERE pr.scan_id = s.id`, so this
// row was never a candidate and stayed 'running' indefinitely.
func TestMarkTimedOutRuns_ReapsRunWithNoScan(t *testing.T) {
	db := openTimeoutDB(t)
	ctx := context.Background()
	repo := NewPipelineRunRepository(&DB{DB: db})

	tenantID := seedTestTenant(ctx, t, db)
	templateID := seedTimeoutTemplate(ctx, t, db, tenantID)

	// 14 days, which is how long the real ones had been stuck.
	runID := seedRun(ctx, t, db, tenantID, templateID, nil, "running", 14*24*time.Hour)

	if _, err := repo.MarkTimedOutRuns(ctx); err != nil {
		t.Fatalf("MarkTimedOutRuns: %v", err)
	}

	status, errMsg := runStatus(ctx, t, db, runID)
	if status != "timeout" {
		t.Errorf("a scan-less run 14 days old must be reaped; got status %q — it would hang forever", status)
	}
	if !errMsg.Valid || errMsg.String == "" {
		t.Error("a reaped run must carry an error message explaining why it ended")
	}
}

// A scan deleted mid-flight is the actual production path to scan_id IS NULL,
// because fk_pipeline_runs_scan is ON DELETE SET NULL. Proving it here means the
// fix is tied to the real trigger, not just to a hand-written NULL.
func TestMarkTimedOutRuns_ReapsRunOrphanedByScanDeletion(t *testing.T) {
	db := openTimeoutDB(t)
	ctx := context.Background()
	repo := NewPipelineRunRepository(&DB{DB: db})

	tenantID := seedTestTenant(ctx, t, db)
	templateID := seedTimeoutTemplate(ctx, t, db, tenantID)
	scanID := seedTimeoutScan(ctx, t, db, tenantID, 3600)

	runID := seedRun(ctx, t, db, tenantID, templateID, &scanID, "running", 25*time.Hour)

	// Delete the scan the way a user would. The FK nulls the link.
	if _, err := db.ExecContext(ctx, `DELETE FROM scans WHERE id = $1`, scanID.String()); err != nil {
		t.Fatalf("delete scan: %v", err)
	}
	var orphaned bool
	if err := db.QueryRowContext(ctx,
		`SELECT scan_id IS NULL FROM pipeline_runs WHERE id = $1`, runID.String()).Scan(&orphaned); err != nil {
		t.Fatalf("check orphaned: %v", err)
	}
	if !orphaned {
		t.Fatal("precondition failed: deleting the scan should have nulled pipeline_runs.scan_id")
	}

	if _, err := repo.MarkTimedOutRuns(ctx); err != nil {
		t.Fatalf("MarkTimedOutRuns: %v", err)
	}

	if status, _ := runStatus(ctx, t, db, runID); status != "timeout" {
		t.Errorf("deleting a scan must not orphan its run forever; got status %q", status)
	}
}

// A scan-less run that has not yet reached the ceiling must be left alone —
// otherwise the fix would kill healthy long-running scans.
func TestMarkTimedOutRuns_LeavesYoungScanlessRunAlone(t *testing.T) {
	db := openTimeoutDB(t)
	ctx := context.Background()
	repo := NewPipelineRunRepository(&DB{DB: db})

	tenantID := seedTestTenant(ctx, t, db)
	templateID := seedTimeoutTemplate(ctx, t, db, tenantID)

	runID := seedRun(ctx, t, db, tenantID, templateID, nil, "running", 1*time.Hour)

	if _, err := repo.MarkTimedOutRuns(ctx); err != nil {
		t.Fatalf("MarkTimedOutRuns: %v", err)
	}

	if status, _ := runStatus(ctx, t, db, runID); status != "running" {
		t.Errorf("a 1-hour-old run is well inside the 24h ceiling; got status %q", status)
	}
}

// No regression: the case the old query did handle must still work.
func TestMarkTimedOutRuns_StillReapsRunPastItsScanTimeout(t *testing.T) {
	db := openTimeoutDB(t)
	ctx := context.Background()
	repo := NewPipelineRunRepository(&DB{DB: db})

	tenantID := seedTestTenant(ctx, t, db)
	templateID := seedTimeoutTemplate(ctx, t, db, tenantID)
	scanID := seedTimeoutScan(ctx, t, db, tenantID, 900)

	runID := seedRun(ctx, t, db, tenantID, templateID, &scanID, "running", 30*time.Minute)

	if _, err := repo.MarkTimedOutRuns(ctx); err != nil {
		t.Fatalf("MarkTimedOutRuns: %v", err)
	}

	if status, _ := runStatus(ctx, t, db, runID); status != "timeout" {
		t.Errorf("30m elapsed against a 900s scan timeout must be reaped; got %q", status)
	}
}

// A run inside its scan's timeout stays running, and the scan timeout — not the
// ceiling — is what governs while a scan is attached.
func TestMarkTimedOutRuns_RespectsScanTimeoutOverCeiling(t *testing.T) {
	db := openTimeoutDB(t)
	ctx := context.Background()
	repo := NewPipelineRunRepository(&DB{DB: db})

	tenantID := seedTestTenant(ctx, t, db)
	templateID := seedTimeoutTemplate(ctx, t, db, tenantID)
	scanID := seedTimeoutScan(ctx, t, db, tenantID, 7200)

	runID := seedRun(ctx, t, db, tenantID, templateID, &scanID, "running", 30*time.Minute)

	if _, err := repo.MarkTimedOutRuns(ctx); err != nil {
		t.Fatalf("MarkTimedOutRuns: %v", err)
	}

	if status, _ := runStatus(ctx, t, db, runID); status != "running" {
		t.Errorf("30m against a 2h scan timeout must keep running; got %q", status)
	}
}

// Terminal runs must never be rewritten. A completed run given a stale
// started_at would otherwise be flipped to timeout and lose its result.
func TestMarkTimedOutRuns_IgnoresTerminalRuns(t *testing.T) {
	db := openTimeoutDB(t)
	ctx := context.Background()
	repo := NewPipelineRunRepository(&DB{DB: db})

	tenantID := seedTestTenant(ctx, t, db)
	templateID := seedTimeoutTemplate(ctx, t, db, tenantID)

	for _, status := range []string{"completed", "failed", "canceled", "timeout"} {
		t.Run(status, func(t *testing.T) {
			runID := seedRun(ctx, t, db, tenantID, templateID, nil, status, 40*24*time.Hour)

			if _, err := repo.MarkTimedOutRuns(ctx); err != nil {
				t.Fatalf("MarkTimedOutRuns: %v", err)
			}

			if got, _ := runStatus(ctx, t, db, runID); got != status {
				t.Errorf("a %s run must be left alone, got %q", status, got)
			}
		})
	}
}

// A run that was never started has no elapsed time to measure, so it must not
// be reaped on the strength of created_at.
func TestMarkTimedOutRuns_IgnoresRunsNeverStarted(t *testing.T) {
	db := openTimeoutDB(t)
	ctx := context.Background()
	repo := NewPipelineRunRepository(&DB{DB: db})

	tenantID := seedTestTenant(ctx, t, db)
	templateID := seedTimeoutTemplate(ctx, t, db, tenantID)

	id := shared.NewID()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO pipeline_runs (id, pipeline_id, tenant_id, trigger_type, status, created_at)
		 VALUES ($1, $2, $3, 'manual', 'pending', NOW() - INTERVAL '40 days')`,
		id.String(), templateID.String(), tenantID.String()); err != nil {
		t.Fatalf("seed unstarted run: %v", err)
	}

	if _, err := repo.MarkTimedOutRuns(ctx); err != nil {
		t.Fatalf("MarkTimedOutRuns: %v", err)
	}

	if status, _ := runStatus(ctx, t, db, id); status != "pending" {
		t.Errorf("a run with started_at IS NULL must not be reaped; got %q", status)
	}
}

// The message must not assert a cause it does not know. It used to read "scan
// exceeded configured timeout", which was shown to users whose scanner had in
// fact failed immediately with a specific, actionable error.
func TestMarkTimedOutRuns_MessageDoesNotBlameTheScanTimeout(t *testing.T) {
	db := openTimeoutDB(t)
	ctx := context.Background()
	repo := NewPipelineRunRepository(&DB{DB: db})

	tenantID := seedTestTenant(ctx, t, db)
	templateID := seedTimeoutTemplate(ctx, t, db, tenantID)
	runID := seedRun(ctx, t, db, tenantID, templateID, nil, "running", 30*24*time.Hour)

	if _, err := repo.MarkTimedOutRuns(ctx); err != nil {
		t.Fatalf("MarkTimedOutRuns: %v", err)
	}

	_, errMsg := runStatus(ctx, t, db, runID)
	if errMsg.String == "scan exceeded configured timeout" {
		t.Error("the reaper must not claim the scan timed out; it only knows nothing was reported")
	}
	if !errMsg.Valid || errMsg.String == "" {
		t.Fatal("a reaped run needs an explanation")
	}
}
