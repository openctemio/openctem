package scanrun

import (
	"context"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
)

// A sensor that could not reach a task's targets (no route, filtered,
// every attempt timed out) used to report the task completed with zero
// results, which read as "nothing exposed" (RFC-089 §4.7). None reached
// now fails the step with TARGET_UNREACHABLE; some unreached ends it
// partial with the results kept.

func TestStepAllUnreached_FailsTargetUnreachable(t *testing.T) {
	s, store, runs := batchedFixture(command.StepBatch{Total: 1})
	msg := "No target was reachable from the sensor (3 target(s): timeout 3)"
	p := Partial{Unreached: 3, Tried: 3, UnreachedSummary: "x", AllUnreached: true, UnreachableMessage: msg}
	if err := s.OnStepCompletedPartial(context.Background(), runs.run.ID.String(), "a", 0, nil, p); err != nil {
		t.Fatal(err)
	}
	a := store.rows["a"]
	if a.Status != scanrun.StepRunStatusFailed || a.ErrorCode != scanrun.FailureTargetUnreachable || a.ErrorMessage != msg {
		t.Fatalf("step %s %q %q, want failed TARGET_UNREACHABLE", a.Status, a.ErrorCode, a.ErrorMessage)
	}
	if len(runs.statuses) != 1 || runs.statuses[0] != scanrun.RunStatusFailed {
		t.Fatalf("run transitions = %v, want [failed]", runs.statuses)
	}
}

// Findings win over a reach summary that says nothing was reached: the
// results are kept and the step completes, with the unreachable count.
func TestStepAllUnreachedWithFindings_CompletedWithCount(t *testing.T) {
	s, store, runs := batchedFixture(command.StepBatch{Total: 1})
	p := Partial{Unreached: 2, Tried: 2, UnreachedSummary: "Completed with 2 target(s) unreachable", AllUnreached: true, UnreachableMessage: "none"}
	if err := s.OnStepCompletedPartial(context.Background(), runs.run.ID.String(), "a", 4, nil, p); err != nil {
		t.Fatal(err)
	}
	a := store.rows["a"]
	if a.Status != scanrun.StepRunStatusCompleted || a.FindingsCount != 4 || a.ErrorCode != "" {
		t.Fatalf("step %+v", a)
	}
	if a.Output[StepOutputUnreachable] != 2 {
		t.Fatalf("step output %v, want the unreachable count", a.Output)
	}
}

// A single target that did not answer is an ordinary result: the step and the
// run complete, one unreachable. Several targets that none answered still
// fail (the sensor may be cut off).
func TestStepSingleTargetUnreached_Completed(t *testing.T) {
	s, store, runs := batchedFixture(command.StepBatch{Total: 1})
	p := Partial{Unreached: 1, Tried: 1, UnreachedSummary: "1 unreachable", AllUnreached: true, UnreachableMessage: "No target was reachable"}
	if err := s.OnStepCompletedPartial(context.Background(), runs.run.ID.String(), "a", 0, nil, p); err != nil {
		t.Fatal(err)
	}
	if a := store.rows["a"]; a.Status != scanrun.StepRunStatusCompleted || a.Output[StepOutputUnreachable] != 1 {
		t.Fatalf("step %+v", a)
	}
	if len(runs.statuses) != 1 || runs.statuses[0] != scanrun.RunStatusCompleted {
		t.Fatalf("run transitions = %v, want [completed]", runs.statuses)
	}
	if runs.updated == nil || runs.updated.Context[RunContextKeyUnreachableCount] != 1 {
		t.Fatalf("run context %v, want unreachable_target_count 1", runs.updated)
	}
}

// Some targets did not answer: the step and the run complete, with the count.
func TestStepSomeUnreached_CompletedWithCount(t *testing.T) {
	s, store, runs := batchedFixture(command.StepBatch{Total: 1})
	summary := "Completed with 1 of 4 target(s) unreachable from the sensor (no_route 1): 10.2.0.7 (no_route)"
	if err := s.OnStepCompletedPartial(context.Background(), runs.run.ID.String(), "a", 0, nil, Partial{Unreached: 1, Tried: 4, UnreachedSummary: summary}); err != nil {
		t.Fatal(err)
	}
	a := store.rows["a"]
	if a.Status != scanrun.StepRunStatusCompleted || a.ErrorCode != "" || a.ErrorMessage != "" {
		t.Fatalf("step %+v", a)
	}
	if a.Output[StepOutputUnreachable] != 1 || a.Output[stepOutputUnreachableNote] != summary {
		t.Fatalf("step output %v", a.Output)
	}
	if len(runs.statuses) != 1 || runs.statuses[0] != scanrun.RunStatusCompleted {
		t.Fatalf("run transitions = %v, want [completed]", runs.statuses)
	}
	if runs.updated == nil || runs.updated.Context[RunContextKeyUnreachableCount] != 1 {
		t.Fatalf("run context %v", runs.updated)
	}
}

// Unfinished work is what makes a step partial: a coverage gap or targets the
// result left unfinished. The skipped and unreachable counts are still kept.
func TestStepUnfinishedWork_StillPartial(t *testing.T) {
	for name, p := range map[string]Partial{
		"coverage gap": {Gaps: 1, GapSummary: "one gap", Unreached: 2, Skipped: 1},
		"unfinished":   {Unfinished: []string{"a.example.com"}, Unreached: 2, Skipped: 1},
	} {
		s, store, runs := batchedFixture(command.StepBatch{Total: 1})
		if err := s.OnStepCompletedPartial(context.Background(), runs.run.ID.String(), "a", 1, nil, p); err != nil {
			t.Fatal(err)
		}
		a := store.rows["a"]
		if a.Status != scanrun.StepRunStatusPartial || a.ErrorCode != scanrun.ErrCodeCoverageGaps {
			t.Fatalf("%s: step %+v", name, a)
		}
		if a.Output[StepOutputUnreachable] != 2 || a.Output[StepOutputSkipped] != 1 {
			t.Fatalf("%s: counts lost: %v", name, a.Output)
		}
		if len(runs.statuses) != 1 || runs.statuses[0] != scanrun.RunStatusPartial {
			t.Fatalf("%s: run transitions = %v, want [partial]", name, runs.statuses)
		}
		if runs.updated == nil || runs.updated.Context[RunContextKeyUnreachableCount] != 2 || runs.updated.Context[RunContextKeySkippedCount] != 1 {
			t.Fatalf("%s: run context %v", name, runs.updated)
		}
	}
}

// Batched: the step fails as unreachable only when every batch reported
// its reach and none reached a target.
func TestBatchedStep_Unreached(t *testing.T) {
	cases := []struct {
		name     string
		state    command.StepBatch
		status   scanrun.StepRunStatus
		code     string
		contains string
	}{
		{"every batch reached nothing", command.StepBatch{Total: 2, ReachBatches: 2, ReachTargets: 6, Unreached: 6},
			scanrun.StepRunStatusFailed, scanrun.FailureTargetUnreachable, "No target was reachable from the sensors (6 target(s) in 2 scan batches)"},
		{"one batch without a reach summary", command.StepBatch{Total: 2, ReachBatches: 1, ReachTargets: 3, Unreached: 3},
			scanrun.StepRunStatusCompleted, "", ""},
		{"some reached", command.StepBatch{Total: 2, ReachBatches: 2, ReachTargets: 6, Reached: 4, Unreached: 2},
			scanrun.StepRunStatusCompleted, "", ""},
		{"one target in all, not answering", command.StepBatch{Total: 2, ReachBatches: 2, ReachTargets: 1, Unreached: 1},
			scanrun.StepRunStatusCompleted, "", ""},
		{"no reach at all keeps today's behavior", command.StepBatch{Total: 2},
			scanrun.StepRunStatusCompleted, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, store, runs := batchedFixture(tc.state)
			if err := s.OnStepCompleted(context.Background(), runs.run.ID.String(), "a", 0, nil); err != nil {
				t.Fatal(err)
			}
			a := store.rows["a"]
			if a.Status != tc.status || a.ErrorCode != tc.code || !strings.Contains(a.ErrorMessage, tc.contains) {
				t.Fatalf("step %s %q %q", a.Status, a.ErrorCode, a.ErrorMessage)
			}
			if tc.status == scanrun.StepRunStatusCompleted && tc.state.Unreached > 0 && a.Output[StepOutputUnreachable] != tc.state.Unreached {
				t.Fatalf("step output %v, want unreachable count %d", a.Output, tc.state.Unreached)
			}
		})
	}
}
