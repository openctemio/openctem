package scanrun

import (
	"context"
	"slices"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A connector scan that stopped part-way is one scan in the connected
// product, never split into follow-ups: its unfinished targets end the step
// partial and are recorded on the run (the next scheduled run plans them
// first; coverage never reads them as covered).

type recordingRuns struct {
	*statusRuns
	tenant, run shared.ID
	added       []string
}

func (r *recordingRuns) AddUnfinishedTargets(_ context.Context, tenantID, runID shared.ID, targets []string) error {
	r.tenant, r.run = tenantID, runID
	r.added = append(r.added, targets...)
	return nil
}

func TestStepUnfinished_PartialAndRecordedOnTheRun(t *testing.T) {
	s, store, runs := batchedFixture(command.StepBatch{Total: 1})
	rec := &recordingRuns{statusRuns: runs}
	s.runRepo = rec
	p := Partial{Unfinished: []string{"10.0.0.7", "10.0.1.0/30"}}
	if err := s.OnStepCompletedPartial(context.Background(), runs.run.TenantID, runs.run.ID.String(), "a", 2, nil, p); err != nil {
		t.Fatal(err)
	}
	a := store.rows["a"]
	if a.Status != scanrun.StepRunStatusPartial || a.FindingsCount != 2 || a.ErrorMessage != "2 target(s) not finished" {
		t.Fatalf("step %+v", a)
	}
	if !slices.Equal(rec.added, p.Unfinished) || rec.run != runs.run.ID || rec.tenant != runs.run.TenantID {
		t.Fatalf("recorded %v on run %s tenant %s", rec.added, rec.run, rec.tenant)
	}
	if len(runs.statuses) != 1 || runs.statuses[0] != scanrun.RunStatusPartial {
		t.Fatalf("run transitions = %v, want [partial]", runs.statuses)
	}
}

func TestStepNothingUnfinished_Completes(t *testing.T) {
	s, store, runs := batchedFixture(command.StepBatch{Total: 1})
	rec := &recordingRuns{statusRuns: runs}
	s.runRepo = rec
	if err := s.OnStepCompletedPartial(context.Background(), runs.run.TenantID, runs.run.ID.String(), "a", 0, nil, Partial{}); err != nil {
		t.Fatal(err)
	}
	if a := store.rows["a"]; a.Status != scanrun.StepRunStatusCompleted || len(rec.added) != 0 {
		t.Fatalf("step %s recorded %v", a.Status, rec.added)
	}
}
