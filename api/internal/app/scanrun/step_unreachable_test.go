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
	p := Partial{Unreached: 3, UnreachedSummary: "x", AllUnreached: true, UnreachableMessage: msg}
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
// results are kept and the step ends partial.
func TestStepAllUnreachedWithFindings_Partial(t *testing.T) {
	s, store, runs := batchedFixture(command.StepBatch{Total: 1})
	p := Partial{Unreached: 2, UnreachedSummary: "Completed with 2 target(s) unreachable", AllUnreached: true, UnreachableMessage: "none"}
	if err := s.OnStepCompletedPartial(context.Background(), runs.run.ID.String(), "a", 4, nil, p); err != nil {
		t.Fatal(err)
	}
	a := store.rows["a"]
	if a.Status != scanrun.StepRunStatusPartial || a.FindingsCount != 4 || a.ErrorCode != scanrun.FailureTargetUnreachable {
		t.Fatalf("step %+v", a)
	}
}

func TestStepSomeUnreached_Partial(t *testing.T) {
	s, store, runs := batchedFixture(command.StepBatch{Total: 1})
	summary := "Completed with 1 of 4 target(s) unreachable from the sensor (no_route 1): 10.2.0.7 (no_route)"
	if err := s.OnStepCompletedPartial(context.Background(), runs.run.ID.String(), "a", 0, nil, Partial{Unreached: 1, UnreachedSummary: summary}); err != nil {
		t.Fatal(err)
	}
	a := store.rows["a"]
	if a.Status != scanrun.StepRunStatusPartial || a.ErrorCode != scanrun.FailureTargetUnreachable || a.ErrorMessage != summary {
		t.Fatalf("step %+v", a)
	}
	if len(runs.statuses) != 1 || runs.statuses[0] != scanrun.RunStatusPartial {
		t.Fatalf("run transitions = %v, want [partial]", runs.statuses)
	}
}

// Skipped targets keep their code; the unreached message is added.
func TestStepSkippedAndUnreached(t *testing.T) {
	s, store, runs := batchedFixture(command.StepBatch{Total: 1})
	if err := s.OnStepCompletedPartial(context.Background(), runs.run.ID.String(), "a", 0, nil,
		Partial{Skipped: 1, SkippedSummary: "skipped one", Unreached: 1, UnreachedSummary: "one unreached", Gaps: 1, GapSummary: "one gap"}); err != nil {
		t.Fatal(err)
	}
	a := store.rows["a"]
	if a.ErrorCode != scanrun.ErrCodeTargetsSkipped || a.ErrorMessage != "skipped one; one unreached; one gap" {
		t.Fatalf("step %+v", a)
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
			scanrun.StepRunStatusPartial, scanrun.FailureTargetUnreachable, "3 target(s) unreachable from the sensors"},
		{"some reached", command.StepBatch{Total: 2, ReachBatches: 2, ReachTargets: 6, Reached: 4, Unreached: 2},
			scanrun.StepRunStatusPartial, scanrun.FailureTargetUnreachable, "2 target(s) unreachable"},
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
		})
	}
}
