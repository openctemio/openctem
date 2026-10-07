package scanrun

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
)

// A result for a step that already finished is ignored: it neither rewrites
// the step nor settles the run. Before, a duplicate completion recounted the
// step's findings, and a failure that arrived after the step completed
// flipped it to failed and failed the whole run.

func TestDuplicateCompletion_IgnoredForFinishedStep(t *testing.T) {
	s, run, store, runs, _ := gatingFixture(
		map[string]scanrun.StepRunStatus{"a": scanrun.StepRunStatusCompleted, "b": scanrun.StepRunStatusRunning},
		nil)
	a := store.rows["a"]
	a.FindingsCount = 2
	store.rows["a"] = a
	run.GetStepRun("a").FindingsCount = 2

	if err := s.OnStepCompleted(context.Background(), run.ID.String(), "a", 7, nil); err != nil {
		t.Fatal(err)
	}
	if got := store.rows["a"]; got.Status != scanrun.StepRunStatusCompleted || got.FindingsCount != 2 {
		t.Fatalf("a rewritten: status=%s findings=%d, want completed with 2", got.Status, got.FindingsCount)
	}
	if len(runs.statuses) != 0 {
		t.Fatalf("run settled by a duplicate result: %v (b is still running)", runs.statuses)
	}
}

func TestLateFailure_IgnoredForCompletedStep(t *testing.T) {
	s, run, store, runs, _ := gatingFixture(
		map[string]scanrun.StepRunStatus{"a": scanrun.StepRunStatusCompleted, "b": scanrun.StepRunStatusRunning},
		nil)

	if err := s.OnStepFailed(context.Background(), run.ID.String(), "a", "late failure", "COMMAND_FAILED"); err != nil {
		t.Fatal(err)
	}
	if got := store.rows["a"]; got.Status != scanrun.StepRunStatusCompleted {
		t.Fatalf("a is %s, want completed", got.Status)
	}
	if len(runs.statuses) != 0 {
		t.Fatalf("run settled by a late failure: %v", runs.statuses)
	}
}

// The live path is unchanged: a running step that completes still finishes
// the run when it is the last one.
func TestRunningStepCompletion_StillSettlesRun(t *testing.T) {
	s, run, store, runs, _ := gatingFixture(
		map[string]scanrun.StepRunStatus{"a": scanrun.StepRunStatusRunning},
		nil)

	if err := s.OnStepCompleted(context.Background(), run.ID.String(), "a", 1, nil); err != nil {
		t.Fatal(err)
	}
	if got := store.rows["a"]; got.Status != scanrun.StepRunStatusCompleted {
		t.Fatalf("a is %s, want completed", got.Status)
	}
	if len(runs.statuses) != 1 || runs.statuses[0] != scanrun.RunStatusCompleted {
		t.Fatalf("run transitions = %v, want [completed]", runs.statuses)
	}
}
