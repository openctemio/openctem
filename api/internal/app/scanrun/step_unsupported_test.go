package scanrun

import (
	"context"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A run goes as far as the organization's tools support: a required step no
// tool runs is skipped with NO_MATCHING_TOOL (never failed), the other step
// runs, and the run ends partial, not completed and not failed.
func TestRequiredStepWithoutTool_SkippedAndRunPartial(t *testing.T) {
	s, run, store, runs, cmds := gatingFixture(
		map[string]scanrun.StepRunStatus{"a": scanrun.StepRunStatusPending, "b": scanrun.StepRunStatusPending}, nil)
	tpl, _ := s.templateRepo.GetWithSteps(context.Background(), run.ScanWorkflowID)
	tpl.Steps[0].Capabilities = []string{"capture.screenshot"} // required, no tool implements it
	tpl.Steps[1].Tool = "subfinder"
	s.toolRepo = platformTools{names: map[string]bool{"subfinder": true}}
	run.Context = map[string]any{"targets": []string{"example.com"}, scanrun.RunContextKeyScanZoneID: shared.NewID().String()}

	if err := s.scheduleRunnableSteps(context.Background(), run, tpl); err != nil {
		t.Fatal(err)
	}
	a := store.rows["a"]
	if a.Status != scanrun.StepRunStatusSkipped || a.ErrorCode != scanrun.FailureNoMatchingTool || a.SkipReason == "" {
		t.Fatalf("a = %s/%s (%q), want skipped NO_MATCHING_TOOL with a reason", a.Status, a.ErrorCode, a.SkipReason)
	}
	if len(cmds.created) != 1 || store.rows["b"].Status != scanrun.StepRunStatusQueued {
		t.Fatalf("b must run: commands %d, b = %s", len(cmds.created), store.rows["b"].Status)
	}
	if len(runs.statuses) != 0 {
		t.Fatalf("run settled early: %v", runs.statuses)
	}

	b := store.rows["b"]
	b.Complete(3, nil)
	store.rows["b"] = b
	if err := s.advanceRun(context.Background(), run, tpl); err != nil {
		t.Fatal(err)
	}
	if len(runs.statuses) != 1 || runs.statuses[0] != scanrun.RunStatusPartial {
		t.Fatalf("run transitions = %v, want [partial]", runs.statuses)
	}
}

// A step that needs the results of a skipped step is skipped as
// DEPENDENCY_SKIPPED, with a reason naming the step it needed.
func TestDependentOfSkippedStep_DependencySkipped(t *testing.T) {
	s, run, store, runs, cmds := gatingFixture(
		map[string]scanrun.StepRunStatus{"a": scanrun.StepRunStatusPending, "b": scanrun.StepRunStatusPending, "c": scanrun.StepRunStatusPending},
		map[string][]string{"b": {"a"}})
	tpl, _ := s.templateRepo.GetWithSteps(context.Background(), run.ScanWorkflowID)
	tpl.Steps[0].Capabilities = []string{"capture.screenshot"}
	tpl.Steps[1].Tool = "subfinder"
	tpl.Steps[2].Tool = "subfinder"
	s.toolRepo = platformTools{names: map[string]bool{"subfinder": true}}
	run.Context = map[string]any{"targets": []string{"example.com"}, scanrun.RunContextKeyScanZoneID: shared.NewID().String()}

	if err := s.scheduleRunnableSteps(context.Background(), run, tpl); err != nil {
		t.Fatal(err)
	}
	b := store.rows["b"]
	if b.Status != scanrun.StepRunStatusSkipped || b.ErrorCode != scanrun.FailureDependencySkipped || !strings.Contains(b.SkipReason, `"a"`) {
		t.Fatalf("b = %s/%s (%q), want DEPENDENCY_SKIPPED naming a", b.Status, b.ErrorCode, b.SkipReason)
	}
	if len(cmds.created) != 1 || store.rows["c"].Status != scanrun.StepRunStatusQueued {
		t.Fatalf("c must run: commands %d, c = %s", len(cmds.created), store.rows["c"].Status)
	}
	c := store.rows["c"]
	c.Complete(0, nil)
	store.rows["c"] = c
	if err := s.advanceRun(context.Background(), run, tpl); err != nil {
		t.Fatal(err)
	}
	if len(runs.statuses) != 1 || runs.statuses[0] != scanrun.RunStatusPartial {
		t.Fatalf("run transitions = %v, want [partial]", runs.statuses)
	}
}

// A step skipped for its condition, depth or intensity is a choice, not a
// missing tool: a run whose other steps completed is completed.
func TestRunStats_OnlyUnsupportedSkipsMakeARunPartial(t *testing.T) {
	done := &scanrun.StepRun{Status: scanrun.StepRunStatusCompleted}
	chosen := &scanrun.StepRun{Status: scanrun.StepRunStatusSkipped, SkipReason: "condition false"}
	dep := &scanrun.StepRun{Status: scanrun.StepRunStatusSkipped, ErrorCode: scanrun.FailureDependencySkipped}
	s := &Service{}
	if got := s.calculateRunStats(&scanrun.Run{StepRuns: []*scanrun.StepRun{done, chosen, dep}}).outcome(); got != scanrun.RunStatusCompleted {
		t.Fatalf("chosen skips: %s, want completed", got)
	}
	for _, code := range []string{scanrun.FailureNoMatchingTool, scanrun.FailureToolNotInstalled, scanrun.FailureToolDisabled, scanrun.FailureNoSensorForTool} {
		missing := &scanrun.StepRun{Status: scanrun.StepRunStatusSkipped, ErrorCode: code}
		if got := s.calculateRunStats(&scanrun.Run{StepRuns: []*scanrun.StepRun{done, missing}}).outcome(); got != scanrun.RunStatusPartial {
			t.Errorf("%s: %s, want partial", code, got)
		}
	}
}
