package pipeline

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	pipelinedom "github.com/openctemio/openctem/api/pkg/domain/pipeline"
)

// RFC-046 D5: a run that kept some results and lost others ends partial,
// not failed. Before, one failed batch out of twenty failed the step and the
// run, and a pipeline whose second step failed after the first completed
// read as if nothing had been scanned.

// batchedFixture is gatingFixture with a command repository that reports the
// step's batches as state.
func batchedFixture(state command.StepBatch) (*Service, *memStepRuns, *statusRuns) {
	s, _, store, runs, _ := gatingFixture(
		map[string]pipelinedom.StepRunStatus{"a": pipelinedom.StepRunStatusRunning}, nil)
	s.commandRepo = &gateRepo{state: state, claimed: true}
	return s, store, runs
}

func TestBatchedStep_SomeBatchesFailed_StepAndRunPartial(t *testing.T) {
	s, store, runs := batchedFixture(command.StepBatch{Total: 3, Failed: 1, Findings: 5, FirstError: "connection reset"})

	if err := s.OnStepCompleted(context.Background(), runs.run.ID.String(), "a", 2, nil); err != nil {
		t.Fatal(err)
	}
	a := store.rows["a"]
	if a.Status != pipelinedom.StepRunStatusPartial {
		t.Fatalf("step is %s, want partial", a.Status)
	}
	if a.FindingsCount != 5 {
		t.Fatalf("step findings = %d, want 5 (summed over the batches that completed)", a.FindingsCount)
	}
	if a.ErrorCode != errCodeBatchFailed || a.ErrorMessage == "" {
		t.Fatalf("step error = %q / %q, want the batch summary", a.ErrorCode, a.ErrorMessage)
	}
	if len(runs.statuses) != 1 || runs.statuses[0] != pipelinedom.RunStatusPartial {
		t.Fatalf("run transitions = %v, want [partial]", runs.statuses)
	}
}

// The last batch to finish is the one that failed: same outcome.
func TestBatchedStep_LastBatchFails_StillPartial(t *testing.T) {
	s, store, runs := batchedFixture(command.StepBatch{Total: 3, Failed: 1, Findings: 4})

	if err := s.OnStepFailed(context.Background(), runs.run.ID.String(), "a", "boom", "COMMAND_FAILED"); err != nil {
		t.Fatal(err)
	}
	if got := store.rows["a"].Status; got != pipelinedom.StepRunStatusPartial {
		t.Fatalf("step is %s, want partial", got)
	}
	if len(runs.statuses) != 1 || runs.statuses[0] != pipelinedom.RunStatusPartial {
		t.Fatalf("run transitions = %v, want [partial]", runs.statuses)
	}
}

func TestBatchedStep_EveryBatchFailed_StepAndRunFailed(t *testing.T) {
	s, store, runs := batchedFixture(command.StepBatch{Total: 3, Failed: 3, FirstError: "scanner not found: nuclei"})

	if err := s.OnStepFailed(context.Background(), runs.run.ID.String(), "a", "boom", "COMMAND_FAILED"); err != nil {
		t.Fatal(err)
	}
	if got := store.rows["a"].Status; got != pipelinedom.StepRunStatusFailed {
		t.Fatalf("step is %s, want failed", got)
	}
	if len(runs.statuses) != 1 || runs.statuses[0] != pipelinedom.RunStatusFailed {
		t.Fatalf("run transitions = %v, want [failed]", runs.statuses)
	}
}

func TestBatchedStep_AllBatchesCompleted_RunCompleted(t *testing.T) {
	s, store, runs := batchedFixture(command.StepBatch{Total: 3, Findings: 7})

	if err := s.OnStepCompleted(context.Background(), runs.run.ID.String(), "a", 1, nil); err != nil {
		t.Fatal(err)
	}
	if a := store.rows["a"]; a.Status != pipelinedom.StepRunStatusCompleted || a.FindingsCount != 7 {
		t.Fatalf("step = %s with %d findings, want completed with 7", a.Status, a.FindingsCount)
	}
	if len(runs.statuses) != 1 || runs.statuses[0] != pipelinedom.RunStatusCompleted {
		t.Fatalf("run transitions = %v, want [completed]", runs.statuses)
	}
}

// Two independent steps: a completed, b fails. The run kept a's results.
func TestMultiStep_OneCompletedOneFailed_RunPartial(t *testing.T) {
	s, run, _, runs, _ := gatingFixture(
		map[string]pipelinedom.StepRunStatus{"a": pipelinedom.StepRunStatusCompleted, "b": pipelinedom.StepRunStatusRunning},
		nil)

	if err := s.failStep(context.Background(), run, run.GetStepRun("b"), "boom", "COMMAND_FAILED"); err != nil {
		t.Fatal(err)
	}
	if len(runs.statuses) != 1 || runs.statuses[0] != pipelinedom.RunStatusPartial {
		t.Fatalf("run transitions = %v, want [partial]", runs.statuses)
	}
}

// A partial step still produced results: a step that depends on it runs.
func TestPartialDependency_DoesNotBlockDependents(t *testing.T) {
	_, run, _, _, _ := gatingFixture(
		map[string]pipelinedom.StepRunStatus{"a": pipelinedom.StepRunStatusPartial, "b": pipelinedom.StepRunStatusPending},
		map[string][]string{"b": {"a"}})
	step := &pipelinedom.Step{StepKey: "b", DependsOn: []string{"a"}}
	if dep := step.BlockedByDependency(run); dep != "" {
		t.Fatalf("b blocked by %q; a partial dependency must not block", dep)
	}
	failed := &pipelinedom.Step{StepKey: "b", DependsOn: []string{"a"}}
	run.GetStepRun("a").Status = pipelinedom.StepRunStatusFailed
	if dep := failed.BlockedByDependency(run); dep != "a" {
		t.Fatalf("blocked by %q, want a (a failed dependency still blocks)", dep)
	}
}

func TestRunOutcome(t *testing.T) {
	cases := []struct {
		name string
		st   runStats
		want pipelinedom.RunStatus
	}{
		{"all completed", runStats{completed: 3}, pipelinedom.RunStatusCompleted},
		{"completed and skipped", runStats{completed: 1, skipped: 2}, pipelinedom.RunStatusCompleted},
		{"all skipped", runStats{skipped: 2}, pipelinedom.RunStatusCompleted},
		{"all failed", runStats{failed: 2}, pipelinedom.RunStatusFailed},
		{"failed and skipped", runStats{failed: 1, skipped: 1}, pipelinedom.RunStatusFailed},
		{"completed and failed", runStats{completed: 1, failed: 1}, pipelinedom.RunStatusPartial},
		{"one partial step", runStats{partial: 1}, pipelinedom.RunStatusPartial},
		{"partial and failed", runStats{partial: 1, failed: 1}, pipelinedom.RunStatusPartial},
	}
	for _, tc := range cases {
		if got := tc.st.outcome(); got != tc.want {
			t.Errorf("%s: outcome = %s, want %s", tc.name, got, tc.want)
		}
	}
}
