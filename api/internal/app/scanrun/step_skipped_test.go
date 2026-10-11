package scanrun

import (
	"context"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"

	"github.com/openctemio/openctem/api/pkg/domain/command"
)

// A sensor whose local policy skipped some targets (a name that does not
// resolve, a wildcard, a denied range) and ran the task on the rest reports
// it completed with refused_targets. The step and the run end partial, not
// completed and not failed; the results are kept.

func TestStepCompletedWithSkips_StepAndRunPartial(t *testing.T) {
	s, store, runs := batchedFixture(command.StepBatch{Total: 1})
	summary := "Completed with 1 target(s) skipped by the sensor's local policy: api.example.com (unresolvable)"
	if err := s.OnStepCompletedPartial(context.Background(), runs.run.ID.String(), "a", 3, nil, Partial{Skipped: 1, SkippedSummary: summary}); err != nil {
		t.Fatal(err)
	}
	a := store.rows["a"]
	if a.Status != scanrun.StepRunStatusPartial || a.FindingsCount != 3 {
		t.Fatalf("step %s with %d findings, want partial with 3", a.Status, a.FindingsCount)
	}
	if a.ErrorCode != scanrun.ErrCodeTargetsSkipped || a.ErrorMessage != summary {
		t.Fatalf("step error %q / %q", a.ErrorCode, a.ErrorMessage)
	}
	if len(runs.statuses) != 1 || runs.statuses[0] != scanrun.RunStatusPartial {
		t.Fatalf("run transitions = %v, want [partial]", runs.statuses)
	}
}

func TestStepCompletedWithoutSkips_StillCompleted(t *testing.T) {
	s, store, runs := batchedFixture(command.StepBatch{Total: 1})
	if err := s.OnStepCompletedPartial(context.Background(), runs.run.ID.String(), "a", 3, nil, Partial{}); err != nil {
		t.Fatal(err)
	}
	if got := store.rows["a"].Status; got != scanrun.StepRunStatusCompleted {
		t.Fatalf("step is %s, want completed", got)
	}
	if len(runs.statuses) != 1 || runs.statuses[0] != scanrun.RunStatusCompleted {
		t.Fatalf("run transitions = %v, want [completed]", runs.statuses)
	}
}

// Batched step: the skipped targets of every completed batch count.
func TestBatchedStep_SkippedTargets_Partial(t *testing.T) {
	s, store, runs := batchedFixture(command.StepBatch{Total: 3, Findings: 6, Skipped: 2})
	if err := s.OnStepCompleted(context.Background(), runs.run.ID.String(), "a", 1, nil); err != nil {
		t.Fatal(err)
	}
	a := store.rows["a"]
	if a.Status != scanrun.StepRunStatusPartial || a.FindingsCount != 6 || a.ErrorCode != scanrun.ErrCodeTargetsSkipped ||
		!strings.Contains(a.ErrorMessage, "2 target(s) skipped") {
		t.Fatalf("step %+v", a)
	}
	if len(runs.statuses) != 1 || runs.statuses[0] != scanrun.RunStatusPartial {
		t.Fatalf("run transitions = %v, want [partial]", runs.statuses)
	}
}

func TestStepBatchesSummary_Skipped(t *testing.T) {
	b := stepBatches{total: 4, failed: 1, skipped: 3, firstError: "boom"}
	if got := b.summary(); got != "1 of 4 scan batches failed: boom; 3 target(s) skipped by the sensor's local policy" {
		t.Errorf("summary = %q", got)
	}
}

// A sensor that could not fully cover some hosts (RFC-074) completes the
// task: the step and the run end partial with the coverage-gap code, the
// results kept.
func TestStepCompletedWithCoverageGaps_Partial(t *testing.T) {
	s, store, runs := batchedFixture(command.StepBatch{Total: 1})
	summary := "Completed with 1 host(s) not fully covered: a.example.com (breaker_open)"
	if err := s.OnStepCompletedPartial(context.Background(), runs.run.ID.String(), "a", 2, nil, Partial{Gaps: 1, GapSummary: summary}); err != nil {
		t.Fatal(err)
	}
	a := store.rows["a"]
	if a.Status != scanrun.StepRunStatusPartial || a.FindingsCount != 2 || a.ErrorCode != scanrun.ErrCodeCoverageGaps || a.ErrorMessage != summary {
		t.Fatalf("step %+v", a)
	}
	if len(runs.statuses) != 1 || runs.statuses[0] != scanrun.RunStatusPartial {
		t.Fatalf("run transitions = %v, want [partial]", runs.statuses)
	}
}

// Skipped targets and coverage gaps together: both messages, the skip code.
func TestStepCompletedWithSkipsAndGaps(t *testing.T) {
	s, store, runs := batchedFixture(command.StepBatch{Total: 1})
	if err := s.OnStepCompletedPartial(context.Background(), runs.run.ID.String(), "a", 0, nil,
		Partial{Skipped: 1, SkippedSummary: "skipped one", Gaps: 1, GapSummary: "one gap"}); err != nil {
		t.Fatal(err)
	}
	a := store.rows["a"]
	if a.ErrorCode != scanrun.ErrCodeTargetsSkipped || a.ErrorMessage != "skipped one; one gap" {
		t.Fatalf("step %+v", a)
	}
}

// Batched step: the coverage gaps of every completed batch count.
func TestBatchedStep_CoverageGaps_Partial(t *testing.T) {
	s, store, runs := batchedFixture(command.StepBatch{Total: 2, Findings: 4, Gaps: 3})
	if err := s.OnStepCompleted(context.Background(), runs.run.ID.String(), "a", 1, nil); err != nil {
		t.Fatal(err)
	}
	a := store.rows["a"]
	if a.Status != scanrun.StepRunStatusPartial || a.ErrorCode != scanrun.ErrCodeCoverageGaps ||
		!strings.Contains(a.ErrorMessage, "3 host(s) not fully covered") {
		t.Fatalf("step %+v", a)
	}
}
