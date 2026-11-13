package scanrun

import (
	"context"
	"strings"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/scanrun"
)

// A step whose work the claim refused because its tool is retired as a
// source on the sensor (docs/architecture/source-retirement.md) is skipped
// with SOURCE_RETIRED, never failed: fail_fast does not stop the run, its
// dependents are skipped as DEPENDENCY_SKIPPED and the run ends partial.
func TestSourceRetiredStep_SkippedAndRunPartial(t *testing.T) {
	s, run, store, runs, cmds := gatingFixture(
		map[string]scanrun.StepRunStatus{"a": scanrun.StepRunStatusCompleted, "b": scanrun.StepRunStatusRunning, "c": scanrun.StepRunStatusPending},
		map[string][]string{"c": {"b"}})
	tpl, _ := s.templateRepo.GetWithSteps(context.Background(), run.ScanWorkflowID)
	tpl.Settings.FailFast = true

	if err := s.OnStepFailed(context.Background(), run.TenantID, run.ID.String(), "b", "SOURCE_RETIRED: retired here", scanrun.FailureSourceRetired); err != nil {
		t.Fatal(err)
	}
	b := store.rows["b"]
	if b.Status != scanrun.StepRunStatusSkipped || b.ErrorCode != scanrun.FailureSourceRetired || b.SkipReason == "" {
		t.Fatalf("b = %s/%s (%q), want skipped SOURCE_RETIRED with its reason", b.Status, b.ErrorCode, b.SkipReason)
	}
	if c := store.rows["c"]; c.Status != scanrun.StepRunStatusSkipped || c.ErrorCode != scanrun.FailureDependencySkipped {
		t.Fatalf("c = %s/%s, want skipped DEPENDENCY_SKIPPED", c.Status, c.ErrorCode)
	}
	if len(cmds.created) != 0 {
		t.Fatalf("queued %d command(s) after the refusal", len(cmds.created))
	}
	if len(runs.statuses) != 1 || runs.statuses[0] != scanrun.RunStatusPartial {
		t.Fatalf("run transitions = %v, want [partial]", runs.statuses)
	}
}

// When every step that could run was refused, nothing ran: the run failed,
// and its message names the step, the reason and the code.
func TestSourceRetiredEveryStep_RunFailedWithTheReason(t *testing.T) {
	s, run, store, runs, _ := gatingFixture(
		map[string]scanrun.StepRunStatus{"a": scanrun.StepRunStatusRunning}, nil)

	if err := s.OnStepFailed(context.Background(), run.TenantID, run.ID.String(), "a", "SOURCE_RETIRED: retired here", scanrun.FailureSourceRetired); err != nil {
		t.Fatal(err)
	}
	if a := store.rows["a"]; a.Status != scanrun.StepRunStatusSkipped {
		t.Fatalf("a = %s, want skipped", a.Status)
	}
	if len(runs.statuses) != 1 || runs.statuses[0] != scanrun.RunStatusFailed {
		t.Fatalf("run transitions = %v, want [failed]", runs.statuses)
	}
	a := store.rows["a"]
	msg := failedRunMessage(&scanrun.Run{StepRuns: []*scanrun.StepRun{&a}})
	if !strings.Contains(msg, scanrun.FailureSourceRetired) || !strings.Contains(msg, "retired here") {
		t.Fatalf("run message %q does not name the refusal", msg)
	}
}

func TestRunOutcome_SourceRetired(t *testing.T) {
	cases := []struct {
		name string
		st   runStats
		want scanrun.RunStatus
	}{
		{"only refused", runStats{skipped: 1, unsupported: 1, refusedAtClaim: 1}, scanrun.RunStatusFailed},
		{"refused and a trigger-time skip", runStats{skipped: 2, unsupported: 2, refusedAtClaim: 1}, scanrun.RunStatusFailed},
		{"refused and completed", runStats{completed: 1, skipped: 1, unsupported: 1, refusedAtClaim: 1}, scanrun.RunStatusPartial},
		{"refused and partial", runStats{partial: 1, skipped: 1, unsupported: 1, refusedAtClaim: 1}, scanrun.RunStatusPartial},
		{"trigger-time skip only, unchanged", runStats{skipped: 1, unsupported: 1}, scanrun.RunStatusPartial},
	}
	for _, tc := range cases {
		if got := tc.st.outcome(); got != tc.want {
			t.Errorf("%s: outcome = %s, want %s", tc.name, got, tc.want)
		}
	}
}
