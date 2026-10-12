package validation

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fakeRunRecorder struct {
	runID, stepID shared.ID
	startedBy     string
	finished      []string
}

func (r *fakeRunRecorder) StartValidationRun(_ context.Context, _, _ shared.ID, by string) (shared.ID, shared.ID, error) {
	r.startedBy = by
	return r.runID, r.stepID, nil
}

func (r *fakeRunRecorder) FinishValidationRun(_ context.Context, _, _ shared.ID, ok bool, _, code string) error {
	if ok {
		r.finished = append(r.finished, "ok")
	} else {
		r.finished = append(r.finished, code)
	}
	return nil
}

// research/62 P0-3: a finding validation is a run of kind validation. The
// command carries the run and its step (tasks and logs in Runs), and the run
// names who asked.
func TestValidateFinding_RecordsARun(t *testing.T) {
	assetID := shared.NewID()
	f := newTestFinding(t, assetID)
	disp := &fakeJobDispatcher{id: shared.NewID()}
	rec := &fakeRunRecorder{runID: shared.NewID(), stepID: shared.NewID()}
	svc := NewRunService(fakeFindingLookup{f: f}, fakeAssetLookup{a: newTestAsset(t, "example.com")}, disp,
		DefaultSelector{}, []ExecutorKind{KindSafeCheck}, logger.NewNop())
	svc.SetRunRecorder(rec)

	user := shared.NewID().String()
	if _, err := svc.ValidateFinding(WithRequester(context.Background(), user), shared.NewID(), f.ID()); err != nil {
		t.Fatal(err)
	}
	if disp.got.ScanRunID != rec.runID || disp.got.ScanRunStepID != rec.stepID {
		t.Fatalf("job not tagged with the run: %+v", disp.got)
	}
	if rec.startedBy != user {
		t.Errorf("run requested by %q, want the user", rec.startedBy)
	}
	if len(rec.finished) != 0 {
		t.Errorf("run settled at dispatch: %v", rec.finished)
	}
}

// A validation that cannot be queued ends its run at once.
func TestValidateFinding_DispatchFailureEndsTheRun(t *testing.T) {
	f := newTestFinding(t, shared.NewID())
	disp := &fakeJobDispatcher{err: errors.New("queue down")}
	rec := &fakeRunRecorder{runID: shared.NewID(), stepID: shared.NewID()}
	svc := NewRunService(fakeFindingLookup{f: f}, fakeAssetLookup{a: newTestAsset(t, "example.com")}, disp,
		DefaultSelector{}, []ExecutorKind{KindSafeCheck}, logger.NewNop())
	svc.SetRunRecorder(rec)

	if _, err := svc.ValidateFinding(context.Background(), shared.NewID(), f.ID()); err == nil {
		t.Fatal("dispatch error not returned")
	}
	if len(rec.finished) != 1 || rec.finished[0] != "DISPATCH_FAILED" {
		t.Fatalf("run settled as %v, want [DISPATCH_FAILED]", rec.finished)
	}
}
