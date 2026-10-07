package postgres

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/pipeline"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A scan's run summary is recomputed from its runs (scan_run_summary.go),
// against the real SQL. Live, a scan read "Last run: Oct 7 11:17" beside
// "Runs: 0" and no results: last_run_at was moved by a trigger with no
// finished run behind it, while the counter moved only on completion.

type runSummary struct {
	total, ok, failed, partial, blocked int
	status                              string
	lastRun                             sql.NullString
	lastAt                              sql.NullTime
}

func readRunSummary(ctx context.Context, t *testing.T, db *sql.DB, scanID shared.ID) runSummary {
	t.Helper()
	var s runSummary
	var st sql.NullString
	if err := db.QueryRowContext(ctx,
		`SELECT total_runs, successful_runs, failed_runs, partial_runs, blocked_runs,
		        last_run_status, last_run_id, last_run_at
		   FROM scans WHERE id = $1`, scanID.String()).
		Scan(&s.total, &s.ok, &s.failed, &s.partial, &s.blocked, &st, &s.lastRun, &s.lastAt); err != nil {
		t.Fatalf("read scan summary: %v", err)
	}
	s.status = st.String
	return s
}

// A running run is a run: it counts at once and is the last run.
func TestScanRunSummary_RunningRunCountsAtOnce(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	scans := NewScanRepository(&DB{DB: db})
	runs := NewPipelineRunRepository(&DB{DB: db})
	tenantID, scanID := seedCounterScan(ctx, t, db)
	run := seedCounterRun(ctx, t, runs, tenantID, scanID)

	if err := scans.RefreshRunSummary(ctx, tenantID, scanID); err != nil {
		t.Fatalf("RefreshRunSummary: %v", err)
	}
	got := readRunSummary(ctx, t, db, scanID)
	if got.total != 1 || got.status != "running" || got.lastRun.String != run.ID.String() || !got.lastAt.Valid {
		t.Fatalf("after start: %+v, want total 1, last run %s running", got, run.ID)
	}

	if err := runs.UpdateStatus(ctx, run.ID, pipeline.RunStatusCompleted, ""); err != nil {
		t.Fatal(err)
	}
	if err := scans.RefreshRunSummary(ctx, tenantID, scanID); err != nil {
		t.Fatal(err)
	}
	// Refreshing twice changes nothing (idempotent: one run counts once).
	if err := scans.RefreshRunSummary(ctx, tenantID, scanID); err != nil {
		t.Fatal(err)
	}
	got = readRunSummary(ctx, t, db, scanID)
	if got.total != 1 || got.ok != 1 || got.failed != 0 || got.status != "completed" {
		t.Fatalf("after completion: %+v, want 1/1/0 completed", got)
	}
}

// An older run finishing late does not relabel the newer, running one.
func TestScanRunSummary_LateOlderRunDoesNotRelabelNewerRun(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	scans := NewScanRepository(&DB{DB: db})
	runs := NewPipelineRunRepository(&DB{DB: db})
	tenantID, scanID := seedCounterScan(ctx, t, db)
	older := seedCounterRun(ctx, t, runs, tenantID, scanID)
	newer := seedCounterRun(ctx, t, runs, tenantID, scanID)
	if _, err := db.ExecContext(ctx, `UPDATE pipeline_runs SET created_at = created_at - interval '1 minute' WHERE id = $1`, older.ID.String()); err != nil {
		t.Fatal(err)
	}

	if err := runs.UpdateStatus(ctx, older.ID, pipeline.RunStatusFailed, "boom"); err != nil {
		t.Fatal(err)
	}
	if err := scans.RefreshRunSummary(ctx, tenantID, scanID); err != nil {
		t.Fatal(err)
	}
	got := readRunSummary(ctx, t, db, scanID)
	if got.total != 2 || got.ok != 0 || got.failed != 1 {
		t.Fatalf("%+v, want total 2, failed 1", got)
	}
	if got.status != "running" || got.lastRun.String != newer.ID.String() {
		t.Fatalf("last run = %s %q, want the newer run still running", got.lastRun.String, got.status)
	}
}

// A refused trigger is a blocked run: stored with its code, terminal,
// counted, and the scan's last run.
func TestScanRunSummary_BlockedRunIsCountedAndRead(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	scans := NewScanRepository(&DB{DB: db})
	runs := NewPipelineRunRepository(&DB{DB: db})
	tenantID, scanID := seedCounterScan(ctx, t, db)

	tpl, _ := shared.IDFromString(quickScanTemplate)
	run, err := pipeline.NewRun(tpl, tenantID, nil, pipeline.TriggerTypeManual, "", map[string]any{"scan_id": scanID.String()})
	if err != nil {
		t.Fatal(err)
	}
	run.ScanID = &scanID
	run.Block("ALL_TARGETS_EXCLUDED", "Every target of scan \"x\" is excluded by scope; nothing to scan.")
	if err := runs.Create(ctx, run); err != nil {
		t.Fatalf("create blocked run: %v", err)
	}
	if err := scans.RefreshRunSummary(ctx, tenantID, scanID); err != nil {
		t.Fatal(err)
	}

	got, err := runs.GetByTenantAndID(ctx, tenantID, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != pipeline.RunStatusBlocked || got.RefusalCode != "ALL_TARGETS_EXCLUDED" || !strings.Contains(got.ErrorMessage, "excluded by scope") {
		t.Fatalf("read back %s %q %q", got.Status, got.RefusalCode, got.ErrorMessage)
	}
	if got.DeadlineAt != nil || got.StartedAt != nil || got.CompletedAt == nil {
		t.Fatalf("a blocked run never starts: started=%v deadline=%v completed=%v", got.StartedAt, got.DeadlineAt, got.CompletedAt)
	}
	// Terminal: nothing moves it again.
	if err := runs.UpdateStatus(ctx, run.ID, pipeline.RunStatusRunning, ""); err == nil {
		t.Fatal("a blocked run was moved to running")
	}

	sum := readRunSummary(ctx, t, db, scanID)
	if sum.total != 1 || sum.blocked != 1 || sum.failed != 0 || sum.status != "blocked" || sum.lastRun.String != run.ID.String() {
		t.Fatalf("summary %+v, want 1 run, 1 blocked, last run blocked", sum)
	}
	sc, err := scans.GetByTenantAndID(ctx, tenantID, scanID)
	if err != nil {
		t.Fatal(err)
	}
	if sc.BlockedRuns != 1 {
		t.Fatalf("scan.BlockedRuns = %d, want 1", sc.BlockedRuns)
	}
}

// The live contradiction: last_run_at set, no run behind it. A refresh (and
// migration 001157, which runs the same statement) clears it.
func TestScanRunSummary_RepairsALastRunWithNoRun(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	scans := NewScanRepository(&DB{DB: db})
	tenantID, scanID := seedCounterScan(ctx, t, db)
	if _, err := db.ExecContext(ctx,
		`UPDATE scans SET last_run_at = $2, last_run_status = 'failed', total_runs = 0 WHERE id = $1`,
		scanID.String(), time.Now()); err != nil {
		t.Fatal(err)
	}

	if err := scans.RefreshRunSummary(ctx, tenantID, scanID); err != nil {
		t.Fatal(err)
	}
	got := readRunSummary(ctx, t, db, scanID)
	if got.lastAt.Valid || got.status != "" || got.lastRun.Valid || got.total != 0 {
		t.Fatalf("summary %+v, want no last run and no runs", got)
	}
}

// The migration's backfill is the repository's statement: same columns, same
// rules. A drift between the two would make the backfill and later refreshes
// disagree.
func TestScanRunSummary_MigrationBackfillMatchesRepository(t *testing.T) {
	raw, err := os.ReadFile("../../../migrations/001157_scan_run_summary_blocked_runs.up.sql")
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	norm := func(s string) string { return strings.Join(strings.Fields(s), " ") }
	mig := norm(string(raw))
	if !strings.Contains(mig, norm(scanRunSummaryUpdateSQL)) {
		t.Fatal("migration 001157's backfill differs from scanRunSummaryUpdateSQL")
	}
}

// The reapers refresh the summary of the scans whose runs they settle.
func TestScanRunSummary_ReaperRefreshesScan(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	runs := NewPipelineRunRepository(&DB{DB: db})
	tenantID, scanID := seedCounterScan(ctx, t, db)
	run := seedCounterRun(ctx, t, runs, tenantID, scanID)
	if _, err := db.ExecContext(ctx,
		`UPDATE pipeline_runs SET deadline_at = NOW() - interval '1 minute' WHERE id = $1`, run.ID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := runs.MarkTimedOutRuns(ctx); err != nil {
		t.Fatalf("MarkTimedOutRuns: %v", err)
	}
	got := readRunSummary(ctx, t, db, scanID)
	if got.total != 1 || got.failed != 1 || got.status != "timeout" || got.lastRun.String != run.ID.String() {
		t.Fatalf("summary %+v, want the timed-out run counted once as failed", got)
	}
}
