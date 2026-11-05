package ingest

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fakeStepDispositions struct {
	tenant, step  shared.ID
	held, refused int
	calls         int
}

func (f *fakeStepDispositions) AddStepFindingDispositions(_ context.Context, tenantID, stepRunID shared.ID, held, refused int) error {
	f.tenant, f.step, f.calls = tenantID, stepRunID, f.calls+1
	f.held += held
	f.refused += refused
	return nil
}

// A command-bound segment tells its step run what became of the findings the
// sensor reported but ingest did not store.
func TestRecordStepDispositions(t *testing.T) {
	rec := &fakeStepDispositions{}
	s := &Service{logger: logger.NewNop(), stepDispositions: rec}
	tenantID, stepID := shared.NewID(), shared.NewID()

	b := boundCommand("nuclei")
	b.StepRunID = &stepID
	s.recordStepDispositions(context.Background(), tenantID, b, 3, 2)
	if rec.calls != 1 || rec.held != 3 || rec.refused != 2 || rec.step != stepID || rec.tenant != tenantID {
		t.Fatalf("recorded %+v", rec)
	}

	// Not a command, or a command without a step run: nothing to count on.
	s.recordStepDispositions(context.Background(), tenantID, Binding{StepRunID: &stepID}, 1, 1)
	s.recordStepDispositions(context.Background(), tenantID, boundCommand("nuclei"), 1, 1)
	if rec.calls != 1 {
		t.Fatalf("recorded for a binding with no step run: %d calls", rec.calls)
	}
	// Unwired: nil-safe.
	(&Service{logger: logger.NewNop()}).recordStepDispositions(context.Background(), tenantID, b, 1, 1)
}

func TestSplitRejected(t *testing.T) {
	for _, c := range []struct{ held, rejected, wantHeld, wantRefused int }{
		{0, 0, 0, 0},
		{3, 5, 3, 2},
		{5, 5, 5, 0},
		{7, 5, 5, 0}, // held can never exceed what was rejected
		{-1, 4, 0, 4},
	} {
		h, r := splitRejected(c.held, c.rejected)
		if h != c.wantHeld || r != c.wantRefused {
			t.Errorf("splitRejected(%d,%d) = %d,%d want %d,%d", c.held, c.rejected, h, r, c.wantHeld, c.wantRefused)
		}
	}
}
