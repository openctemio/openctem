package pipeline

import (
	"context"
	"testing"

	pipelinedom "github.com/openctemio/openctem/api/pkg/domain/pipeline"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// A pipeline_run reaching a terminal state used to update only the run row; the
// scan it belonged to kept last_run_status NULL — reading "never run" straight
// after a scan that had just finished and produced findings (observed live
// 2026-08-10). recordScanRun writes the outcome back onto the scan.

type fakeScanRunRecorder struct {
	calls []recordCall
	err   error
}

type recordCall struct {
	scanID shared.ID
	runID  shared.ID
	status string
}

func (f *fakeScanRunRecorder) RecordRun(_ context.Context, _ shared.ID, scanID, runID shared.ID, status string) error {
	f.calls = append(f.calls, recordCall{scanID, runID, status})
	return f.err
}

func newRecorderService(rec ScanRunRecorder) *Service {
	return &Service{scanRunRecorder: rec, logger: logger.NewNop()}
}

func TestRecordScanRun_WritesOutcomeBackToScan(t *testing.T) {
	rec := &fakeScanRunRecorder{}
	s := newRecorderService(rec)

	scanID := shared.NewID()
	run := &pipelinedom.Run{ID: shared.NewID(), ScanID: &scanID}

	s.recordScanRun(context.Background(), run, "completed")

	if len(rec.calls) != 1 {
		t.Fatalf("recorder called %d times, want 1 — a completed run must record its "+
			"outcome on the scan", len(rec.calls))
	}
	got := rec.calls[0]
	if got.scanID != scanID || got.runID != run.ID || got.status != "completed" {
		t.Errorf("recorded {scan=%s run=%s status=%s}, want {%s %s completed}",
			got.scanID, got.runID, got.status, scanID, run.ID)
	}
}

// A workflow run with no ScanID must not attempt to record onto a scan.
func TestRecordScanRun_NoScanIDIsNoOp(t *testing.T) {
	rec := &fakeScanRunRecorder{}
	s := newRecorderService(rec)

	run := &pipelinedom.Run{ID: shared.NewID(), ScanID: nil}
	s.recordScanRun(context.Background(), run, "completed")

	if len(rec.calls) != 0 {
		t.Fatalf("recorder called for a run with no ScanID — a non-scan workflow " +
			"run has no scan to update")
	}
}

// No recorder wired (optional dependency absent) must not panic.
func TestRecordScanRun_NilRecorderIsSafe(t *testing.T) {
	s := newRecorderService(nil)
	scanID := shared.NewID()
	run := &pipelinedom.Run{ID: shared.NewID(), ScanID: &scanID}

	// Must not panic.
	s.recordScanRun(context.Background(), run, "failed")
}

// A recorder error must be swallowed — the run itself is already recorded, and
// a scan-summary write must never fail the completion path.
func TestRecordScanRun_RecorderErrorIsSwallowed(t *testing.T) {
	rec := &fakeScanRunRecorder{err: context.DeadlineExceeded}
	s := newRecorderService(rec)

	scanID := shared.NewID()
	run := &pipelinedom.Run{ID: shared.NewID(), ScanID: &scanID}

	// Must not panic or propagate — recordScanRun returns nothing.
	s.recordScanRun(context.Background(), run, "completed")

	if len(rec.calls) != 1 {
		t.Fatalf("recorder should still have been attempted once, got %d", len(rec.calls))
	}
}

// statusOnlyRunRepo answers UpdateStatus the way the repository does: the
// first terminal transition wins, every later one is refused.
type statusOnlyRunRepo struct {
	pipelinedom.RunRepository
	finished bool
}

func (r *statusOnlyRunRepo) UpdateStatus(_ context.Context, _ shared.ID, _ pipelinedom.RunStatus, _ string) error {
	if r.finished {
		return pipelinedom.ErrRunAlreadyFinished
	}
	r.finished = true
	return nil
}

// Two parallel final steps (or a completion racing a cancel) both reach the
// "run is complete" branch. Only the caller that actually moved the run may
// record it on the scan; before, both did and the scan counted the run twice.
func TestFinishRun_OnlyTheWinningTransitionRecordsTheRun(t *testing.T) {
	rec := &fakeScanRunRecorder{}
	s := &Service{scanRunRecorder: rec, runRepo: &statusOnlyRunRepo{}, logger: logger.NewNop()}
	scanID := shared.NewID()
	run := &pipelinedom.Run{ID: shared.NewID(), TenantID: shared.NewID(), ScanID: &scanID}

	if !s.finishRun(context.Background(), run, pipelinedom.RunStatusCompleted, "") {
		t.Fatal("first transition should win")
	}
	if s.finishRun(context.Background(), run, pipelinedom.RunStatusFailed, "late") {
		t.Fatal("second transition must lose: the run already finished")
	}
	if len(rec.calls) != 1 || rec.calls[0].status != "completed" {
		t.Fatalf("scan recordings = %+v, want exactly one 'completed'", rec.calls)
	}
}
