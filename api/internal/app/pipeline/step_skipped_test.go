package pipeline

import (
	"context"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	pipelinedom "github.com/openctemio/openctem/api/pkg/domain/pipeline"
)

// A sensor whose local policy skipped some targets (a name that does not
// resolve, a wildcard, a denied range) and ran the task on the rest reports
// it completed with refused_targets. The step and the run end partial, not
// completed and not failed; the results are kept.

func TestStepCompletedWithSkips_StepAndRunPartial(t *testing.T) {
	s, store, runs := batchedFixture(command.StepBatch{Total: 1})
	summary := "Completed with 1 target(s) skipped by the sensor's local policy: api.example.com (unresolvable)"
	if err := s.OnStepCompletedWithSkips(context.Background(), runs.run.ID.String(), "a", 3, nil, 1, summary); err != nil {
		t.Fatal(err)
	}
	a := store.rows["a"]
	if a.Status != pipelinedom.StepRunStatusPartial || a.FindingsCount != 3 {
		t.Fatalf("step %s with %d findings, want partial with 3", a.Status, a.FindingsCount)
	}
	if a.ErrorCode != pipelinedom.ErrCodeTargetsSkipped || a.ErrorMessage != summary {
		t.Fatalf("step error %q / %q", a.ErrorCode, a.ErrorMessage)
	}
	if len(runs.statuses) != 1 || runs.statuses[0] != pipelinedom.RunStatusPartial {
		t.Fatalf("run transitions = %v, want [partial]", runs.statuses)
	}
}

func TestStepCompletedWithoutSkips_StillCompleted(t *testing.T) {
	s, store, runs := batchedFixture(command.StepBatch{Total: 1})
	if err := s.OnStepCompletedWithSkips(context.Background(), runs.run.ID.String(), "a", 3, nil, 0, ""); err != nil {
		t.Fatal(err)
	}
	if got := store.rows["a"].Status; got != pipelinedom.StepRunStatusCompleted {
		t.Fatalf("step is %s, want completed", got)
	}
	if len(runs.statuses) != 1 || runs.statuses[0] != pipelinedom.RunStatusCompleted {
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
	if a.Status != pipelinedom.StepRunStatusPartial || a.FindingsCount != 6 || a.ErrorCode != pipelinedom.ErrCodeTargetsSkipped ||
		!strings.Contains(a.ErrorMessage, "2 target(s) skipped") {
		t.Fatalf("step %+v", a)
	}
	if len(runs.statuses) != 1 || runs.statuses[0] != pipelinedom.RunStatusPartial {
		t.Fatalf("run transitions = %v, want [partial]", runs.statuses)
	}
}

func TestStepBatchesSummary_Skipped(t *testing.T) {
	b := stepBatches{total: 4, failed: 1, skipped: 3, firstError: "boom"}
	if got := b.summary(); got != "1 of 4 scan batches failed: boom; 3 target(s) skipped by the sensor's local policy" {
		t.Errorf("summary = %q", got)
	}
}
