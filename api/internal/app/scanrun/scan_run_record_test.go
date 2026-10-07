package scanrun

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// A pipeline_run reaching a terminal state used to update only the run row; the
// scan it belonged to kept last_run_status NULL — reading "never run" straight
// after a scan that had just finished and produced findings (observed live
// 2026-08-10). recordScanRun refreshes the scan's run summary from its runs.

type fakeScanRunRecorder struct {
	calls []recordCall
	err   error
}

type recordCall struct {
	tenantID shared.ID
	scanID   shared.ID
}

func (f *fakeScanRunRecorder) RefreshRunSummary(_ context.Context, tenantID, scanID shared.ID) error {
	f.calls = append(f.calls, recordCall{tenantID, scanID})
	return f.err
}

func newRecorderService(rec ScanRunRecorder) *Service {
	return &Service{scanRunRecorder: rec, logger: logger.NewNop()}
}

func TestRecordScanRun_WritesOutcomeBackToScan(t *testing.T) {
	rec := &fakeScanRunRecorder{}
	s := newRecorderService(rec)

	scanID := shared.NewID()
	run := &scanrun.Run{ID: shared.NewID(), TenantID: shared.NewID(), ScanID: &scanID}

	s.recordScanRun(context.Background(), run, "completed")

	if len(rec.calls) != 1 {
		t.Fatalf("recorder called %d times, want 1 — a completed run must refresh "+
			"its scan's summary", len(rec.calls))
	}
	got := rec.calls[0]
	if got.scanID != scanID || got.tenantID != run.TenantID {
		t.Errorf("refreshed {tenant=%s scan=%s}, want {%s %s}", got.tenantID, got.scanID, run.TenantID, scanID)
	}
}

// A workflow run with no ScanID must not attempt to record onto a scan.
func TestRecordScanRun_NoScanIDIsNoOp(t *testing.T) {
	rec := &fakeScanRunRecorder{}
	s := newRecorderService(rec)

	run := &scanrun.Run{ID: shared.NewID(), ScanID: nil}
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
	run := &scanrun.Run{ID: shared.NewID(), ScanID: &scanID}

	// Must not panic.
	s.recordScanRun(context.Background(), run, "failed")
}

// A recorder error must be swallowed — the run itself is already recorded, and
// a scan-summary write must never fail the completion path.
func TestRecordScanRun_RecorderErrorIsSwallowed(t *testing.T) {
	rec := &fakeScanRunRecorder{err: context.DeadlineExceeded}
	s := newRecorderService(rec)

	scanID := shared.NewID()
	run := &scanrun.Run{ID: shared.NewID(), ScanID: &scanID}

	// Must not panic or propagate — recordScanRun returns nothing.
	s.recordScanRun(context.Background(), run, "completed")

	if len(rec.calls) != 1 {
		t.Fatalf("recorder should still have been attempted once, got %d", len(rec.calls))
	}
}

// statusOnlyRunRepo answers UpdateStatus the way the repository does: the
// first terminal transition wins, every later one is refused.
type statusOnlyRunRepo struct {
	scanrun.RunRepository
	finished bool
}

func (r *statusOnlyRunRepo) UpdateStatus(_ context.Context, _ shared.ID, _ scanrun.RunStatus, _ string) error {
	if r.finished {
		return scanrun.ErrRunAlreadyFinished
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
	run := &scanrun.Run{ID: shared.NewID(), TenantID: shared.NewID(), ScanID: &scanID}

	if !s.finishRun(context.Background(), run, scanrun.RunStatusCompleted, "") {
		t.Fatal("first transition should win")
	}
	if s.finishRun(context.Background(), run, scanrun.RunStatusFailed, "late") {
		t.Fatal("second transition must lose: the run already finished")
	}
	if len(rec.calls) != 1 {
		t.Fatalf("scan refreshes = %+v, want exactly one", rec.calls)
	}
}
