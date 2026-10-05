package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/pipeline"
)

// RFC-046 D5 (`partial`), against the real SQL and migration 000350.

func TestPartialRun_StoredFinalAndCountedOnItsOwn(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	scans := NewScanRepository(&DB{DB: db})
	runs := NewPipelineRunRepository(&DB{DB: db})
	steps := NewStepRunRepository(&DB{DB: db})
	tenantID, scanID := seedCounterScan(ctx, t, db)
	run := seedCounterRun(ctx, t, runs, tenantID, scanID)
	sr := seedStepRun(ctx, t, steps, run.ID)

	// The step and the run accept the new status (CHECK constraints).
	sr.Partial(4, "1 of 3 scan batches failed", "BATCH_FAILED")
	if err := steps.Update(ctx, sr); err != nil {
		t.Fatalf("step -> partial: %v", err)
	}
	if err := runs.UpdateStatus(ctx, run.ID, pipeline.RunStatusPartial, "partial"); err != nil {
		t.Fatalf("run -> partial: %v", err)
	}
	if err := scans.RecordRun(ctx, tenantID, scanID, run.ID, string(pipeline.RunStatusPartial)); err != nil {
		t.Fatalf("RecordRun: %v", err)
	}

	// partial is terminal for both.
	if err := runs.UpdateStatus(ctx, run.ID, pipeline.RunStatusCompleted, ""); !errors.Is(err, pipeline.ErrRunAlreadyFinished) {
		t.Fatalf("run after partial: err=%v, want ErrRunAlreadyFinished", err)
	}
	if err := steps.Complete(ctx, sr.ID, 9, nil); !errors.Is(err, pipeline.ErrStepRunAlreadyFinished) {
		t.Fatalf("step after partial: err=%v, want ErrStepRunAlreadyFinished", err)
	}

	total, ok, failed, status, _ := readCounters(ctx, t, db, scanID)
	var partial int
	if err := db.QueryRowContext(ctx, `SELECT partial_runs FROM scans WHERE id = $1`, scanID.String()).Scan(&partial); err != nil {
		t.Fatalf("read partial_runs: %v", err)
	}
	if total != 1 || ok != 0 || failed != 0 || partial != 1 || status != "partial" {
		t.Fatalf("counters total=%d ok=%d failed=%d partial=%d status=%q, want 1 0 0 1 partial", total, ok, failed, partial, status)
	}

	// The entity reads it back.
	sc, err := scans.GetByTenantAndID(ctx, tenantID, scanID)
	if err != nil {
		t.Fatalf("read scan: %v", err)
	}
	if sc.PartialRuns != 1 {
		t.Fatalf("scan.PartialRuns = %d, want 1", sc.PartialRuns)
	}
}

// A partial run is never retried as a whole (only failed and timeout are).
func TestPartialRun_NotAutoRetried(t *testing.T) {
	ctx := context.Background()
	db := openTimeoutDB(t)
	repo := NewPipelineRunRepository(&DB{DB: db})
	tenantID := seedTestTenant(ctx, t, db)

	partial := seedFinishedRun(ctx, t, db, tenantID, seedRetryScan(ctx, t, db, tenantID, 5), "partial", 0, "partial", "BATCH_FAILED")
	failed := seedFinishedRun(ctx, t, db, tenantID, seedRetryScan(ctx, t, db, tenantID, 5), "failed", 0, "failed", "COMMAND_FAILED")

	got := listedRuns(ctx, t, repo)
	if got[partial] {
		t.Error("a partial run was offered for a whole-run retry")
	}
	if !got[failed] {
		t.Error("a failed run with budget left must still be retried")
	}
}

func TestPartialRun_InOverviewStats(t *testing.T) {
	ctx := context.Background()
	db := openTimeoutDB(t)
	runs := NewPipelineRunRepository(&DB{DB: db})
	steps := NewStepRunRepository(&DB{DB: db})
	tenantID := seedTestTenant(ctx, t, db)
	scanID := seedRetryScan(ctx, t, db, tenantID, 0)

	seedFinishedRun(ctx, t, db, tenantID, scanID, "partial", 0, "partial", "BATCH_FAILED")
	seedFinishedRun(ctx, t, db, tenantID, scanID, "failed", 0, "failed", "COMMAND_FAILED")

	rs, err := runs.GetStatsByTenant(ctx, tenantID)
	if err != nil {
		t.Fatal(err)
	}
	if rs.Partial != 1 || rs.Failed != 1 || rs.Total != 2 {
		t.Fatalf("run stats = %+v, want partial 1 failed 1 total 2", rs)
	}
	ss, err := steps.GetStatsByTenant(ctx, tenantID)
	if err != nil {
		t.Fatal(err)
	}
	if ss.Partial != 1 || ss.Failed != 1 {
		t.Fatalf("step stats = %+v, want partial 1 failed 1", ss)
	}

	// Another tenant sees none of it.
	other := seedTestTenant(ctx, t, db)
	if os, err := runs.GetStatsByTenant(ctx, other); err != nil || os.Total != 0 || os.Partial != 0 {
		t.Fatalf("other tenant run stats = %+v (err %v), want empty", os, err)
	}
}
