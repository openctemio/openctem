package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A finished step run stays finished, against the real SQL.
//
// Before: every StepRunRepository write filtered only on id, so a duplicate
// or late result rewrote a completed step (its findings count and outcome),
// a failure arriving after a completion flipped it to failed, and a stale
// copy written back after a cancel or the timeout reaper re-queued it.

func seedStepRun(ctx context.Context, t *testing.T, steps *StepRunRepository, runID shared.ID) *scanrun.StepRun {
	t.Helper()
	stepID, _ := shared.IDFromString(quickScanStepID)
	sr := scanrun.NewStepRun(runID, stepID, "quick_scan", 1, 0)
	if err := steps.Create(ctx, sr); err != nil {
		t.Fatalf("create step run: %v", err)
	}
	return sr
}

func readStepRun(ctx context.Context, t *testing.T, steps *StepRunRepository, id shared.ID) *scanrun.StepRun {
	t.Helper()
	sr, err := steps.GetByID(ctx, id)
	if err != nil {
		t.Fatalf("read step run: %v", err)
	}
	return sr
}

func TestStepRun_LiveTransitionsStillWork(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	runs := NewScanRunRepository(&DB{DB: db})
	steps := NewStepRunRepository(&DB{DB: db})
	tenantID, scanID := seedCounterScan(ctx, t, db)
	run := seedCounterRun(ctx, t, runs, tenantID, scanID)
	sr := seedStepRun(ctx, t, steps, run.ID)

	sr.Queue()
	if err := steps.Update(ctx, sr); err != nil {
		t.Fatalf("pending -> queued: %v", err)
	}
	if err := steps.UpdateStatus(ctx, sr.ID, scanrun.StepRunStatusRunning, "", ""); err != nil {
		t.Fatalf("queued -> running: %v", err)
	}
	if err := steps.Complete(ctx, sr.ID, 3, map[string]any{"ok": true}); err != nil {
		t.Fatalf("running -> completed: %v", err)
	}
	got := readStepRun(ctx, t, steps, sr.ID)
	if got.Status != scanrun.StepRunStatusCompleted || got.FindingsCount != 3 || got.CompletedAt == nil {
		t.Fatalf("after complete: status=%s findings=%d completed_at=%v", got.Status, got.FindingsCount, got.CompletedAt)
	}
}

func TestStepRun_FinishedStepIsFinal(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	runs := NewScanRunRepository(&DB{DB: db})
	steps := NewStepRunRepository(&DB{DB: db})
	tenantID, scanID := seedCounterScan(ctx, t, db)
	run := seedCounterRun(ctx, t, runs, tenantID, scanID)
	sr := seedStepRun(ctx, t, steps, run.ID)

	if err := steps.Complete(ctx, sr.ID, 2, nil); err != nil {
		t.Fatalf("complete: %v", err)
	}

	// A duplicate completion must not recount findings.
	if err := steps.Complete(ctx, sr.ID, 9, nil); !errors.Is(err, scanrun.ErrStepRunAlreadyFinished) {
		t.Fatalf("second Complete: err=%v, want ErrStepRunAlreadyFinished", err)
	}
	// A late failure must not flip the outcome.
	if err := steps.UpdateStatus(ctx, sr.ID, scanrun.StepRunStatusFailed, "late", "COMMAND_FAILED"); !errors.Is(err, scanrun.ErrStepRunAlreadyFinished) {
		t.Fatalf("UpdateStatus after complete: err=%v, want ErrStepRunAlreadyFinished", err)
	}
	// A stale in-memory copy (still pending) written back must not re-queue it.
	sr.Queue()
	if err := steps.Update(ctx, sr); !errors.Is(err, scanrun.ErrStepRunAlreadyFinished) {
		t.Fatalf("stale Update: err=%v, want ErrStepRunAlreadyFinished", err)
	}

	got := readStepRun(ctx, t, steps, sr.ID)
	if got.Status != scanrun.StepRunStatusCompleted || got.FindingsCount != 2 || got.ErrorCode != "" {
		t.Fatalf("finished step changed: status=%s findings=%d error_code=%q", got.Status, got.FindingsCount, got.ErrorCode)
	}
}

func TestStepRun_EveryTerminalStatusIsFinal(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	runs := NewScanRunRepository(&DB{DB: db})
	steps := NewStepRunRepository(&DB{DB: db})
	tenantID, scanID := seedCounterScan(ctx, t, db)

	for _, terminal := range []scanrun.StepRunStatus{
		scanrun.StepRunStatusCompleted, scanrun.StepRunStatusFailed, scanrun.StepRunStatusSkipped,
		scanrun.StepRunStatusCanceled, scanrun.StepRunStatusTimeout,
	} {
		run := seedCounterRun(ctx, t, runs, tenantID, scanID)
		sr := seedStepRun(ctx, t, steps, run.ID)
		if err := steps.UpdateStatus(ctx, sr.ID, terminal, "", ""); err != nil {
			t.Fatalf("%s: settle: %v", terminal, err)
		}
		if err := steps.Complete(ctx, sr.ID, 1, nil); !errors.Is(err, scanrun.ErrStepRunAlreadyFinished) {
			t.Fatalf("%s: Complete: err=%v, want ErrStepRunAlreadyFinished", terminal, err)
		}
		if got := readStepRun(ctx, t, steps, sr.ID); got.Status != terminal {
			t.Fatalf("%s: became %s", terminal, got.Status)
		}
	}
}

func TestStepRun_MissingStepIsNotFound(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	steps := NewStepRunRepository(&DB{DB: db})

	missing := shared.NewID()
	if err := steps.Complete(ctx, missing, 1, nil); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("Complete(missing): err=%v, want ErrNotFound", err)
	}
	if err := steps.UpdateStatus(ctx, missing, scanrun.StepRunStatusFailed, "", ""); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("UpdateStatus(missing): err=%v, want ErrNotFound", err)
	}
}
