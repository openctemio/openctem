package postgres

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/pipeline"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Run outcome bookkeeping, against the real SQL.
//
// Before: UpdateStatus/Update were unconditional, so a cancel racing a
// completion (or two parallel final steps) moved a finished run again and the
// scan recorded (and counted) it twice; and a late older run relabelled the
// scan's newer, still-running run.

const quickScanTemplate = "00000000-0000-0000-0000-000000000001"

func seedCounterScan(ctx context.Context, t *testing.T, db *sql.DB) (tenantID, scanID shared.ID) {
	t.Helper()
	tenantID = seedScanTriggerTenant(ctx, t, db)
	scanID = shared.NewID()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO scans (id, tenant_id, name, scan_type, scanner_name) VALUES ($1, $2, 'counter probe', 'single', 'nuclei')`,
		scanID.String(), tenantID.String()); err != nil {
		t.Fatalf("seed scan: %v", err)
	}
	return tenantID, scanID
}

func seedCounterRun(ctx context.Context, t *testing.T, repo *PipelineRunRepository, tenantID, scanID shared.ID) *pipeline.Run {
	t.Helper()
	tpl, _ := shared.IDFromString(quickScanTemplate)
	run, err := pipeline.NewRun(tpl, tenantID, nil, pipeline.TriggerTypeManual, "", map[string]any{})
	if err != nil {
		t.Fatalf("new run: %v", err)
	}
	run.ScanID = &scanID
	run.SetTotalSteps(1)
	run.Start()
	if err := repo.Create(ctx, run); err != nil {
		t.Fatalf("create run: %v", err)
	}
	return run
}

func readCounters(ctx context.Context, t *testing.T, db *sql.DB, scanID shared.ID) (total, ok, failed int, status string, lastRun sql.NullString) {
	t.Helper()
	var st sql.NullString
	if err := db.QueryRowContext(ctx,
		`SELECT total_runs, successful_runs, failed_runs, last_run_status, last_run_id FROM scans WHERE id = $1`,
		scanID.String()).Scan(&total, &ok, &failed, &st, &lastRun); err != nil {
		t.Fatalf("read scan: %v", err)
	}
	return total, ok, failed, st.String, lastRun
}

func TestScanRunCounters_OneRunCountsOnce(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	scans := NewScanRepository(&DB{DB: db})
	runs := NewPipelineRunRepository(&DB{DB: db})
	tenantID, scanID := seedCounterScan(ctx, t, db)
	run := seedCounterRun(ctx, t, runs, tenantID, scanID)

	if err := scans.RecordRunStarted(ctx, tenantID, scanID, run.ID); err != nil {
		t.Fatalf("RecordRunStarted: %v", err)
	}
	total, _, _, status, _ := readCounters(ctx, t, db, scanID)
	if total != 0 || status != "running" {
		t.Fatalf("after start: total_runs=%d status=%q, want 0 running (counted when it finishes)", total, status)
	}

	if err := scans.RecordRun(ctx, tenantID, scanID, run.ID, "completed"); err != nil {
		t.Fatalf("RecordRun: %v", err)
	}
	total, ok, failed, status, _ := readCounters(ctx, t, db, scanID)
	if total != 1 || ok != 1 || failed != 0 || status != "completed" {
		t.Fatalf("after completion: total=%d ok=%d failed=%d status=%q, want 1/1/0 completed (one run counts once)",
			total, ok, failed, status)
	}
}

func TestScanRunCounters_LateOlderRunDoesNotRelabelNewerRun(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	scans := NewScanRepository(&DB{DB: db})
	runs := NewPipelineRunRepository(&DB{DB: db})
	tenantID, scanID := seedCounterScan(ctx, t, db)
	older := seedCounterRun(ctx, t, runs, tenantID, scanID)
	if err := scans.RecordRunStarted(ctx, tenantID, scanID, older.ID); err != nil {
		t.Fatal(err)
	}
	newer := seedCounterRun(ctx, t, runs, tenantID, scanID)
	if err := scans.RecordRunStarted(ctx, tenantID, scanID, newer.ID); err != nil {
		t.Fatal(err)
	}

	if err := scans.RecordRun(ctx, tenantID, scanID, older.ID, "failed"); err != nil {
		t.Fatal(err)
	}
	total, ok, failed, status, last := readCounters(ctx, t, db, scanID)
	if total != 1 || ok != 0 || failed != 1 {
		t.Fatalf("total=%d ok=%d failed=%d, want 1/0/1", total, ok, failed)
	}
	if status != "running" || last.String != newer.ID.String() {
		t.Fatalf("last run = %s %q, want the newer run still 'running'", last.String, status)
	}
}

func TestUpdateStatus_TerminalRunIsFinal(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	runs := NewPipelineRunRepository(&DB{DB: db})
	tenantID, scanID := seedCounterScan(ctx, t, db)
	run := seedCounterRun(ctx, t, runs, tenantID, scanID)

	if err := runs.UpdateStatus(ctx, run.ID, pipeline.RunStatusCompleted, ""); err != nil {
		t.Fatalf("first terminal transition: %v", err)
	}
	// A cancel (or a second parallel final step) arriving afterwards.
	err := runs.UpdateStatus(ctx, run.ID, pipeline.RunStatusCanceled, "Canceled by user")
	if !errors.Is(err, pipeline.ErrRunAlreadyFinished) {
		t.Fatalf("second terminal transition: err=%v, want ErrRunAlreadyFinished", err)
	}
	got, err := runs.GetByID(ctx, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != pipeline.RunStatusCompleted {
		t.Fatalf("status=%s, want completed to stay", got.Status)
	}

	// A stale full-row write (the copy read before completion) must not reopen it.
	run.Status = pipeline.RunStatusRunning
	if err := runs.Update(ctx, run); !errors.Is(err, pipeline.ErrRunAlreadyFinished) {
		t.Fatalf("stale Update: err=%v, want ErrRunAlreadyFinished", err)
	}
	got, _ = runs.GetByID(ctx, run.ID)
	if got.Status != pipeline.RunStatusCompleted {
		t.Fatalf("status after stale Update=%s, want completed", got.Status)
	}

	if err := runs.UpdateStatus(ctx, shared.NewID(), pipeline.RunStatusFailed, ""); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("missing run: err=%v, want ErrNotFound", err)
	}
}
