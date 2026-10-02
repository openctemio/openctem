package pipeline

import (
	"context"
	"testing"

	pipelinedom "github.com/openctemio/api/pkg/domain/pipeline"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
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

func (f *fakeScanRunRecorder) RecordRun(_ context.Context, scanID, runID shared.ID, status string) error {
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
