package scanrun

import (
	"context"
	"errors"
	"strings"
	"testing"

	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

// A passive scan's run never dispatches its active step: b (probe.http, T1)
// is skipped with the intensity as its reason, no command is created, and
// the run still ends (RFC-071).
func TestStepAboveIntensity_SkippedNeverDispatched(t *testing.T) {
	s, run, store, runs, cmds := gatingFixture(
		map[string]scanrun.StepRunStatus{"a": scanrun.StepRunStatusRunning, "b": scanrun.StepRunStatusPending},
		map[string][]string{"b": {"a"}})
	run.Context[scanapp.RunContextKeyIntensity] = "passive"
	tpl := s.templateRepo.(fixedTemplate).tpl
	tpl.Steps[0].Capabilities = []string{"resolve.dns"}
	tpl.Steps[1].Capabilities = []string{"probe.http"}

	if err := s.OnStepCompleted(context.Background(), run.ID.String(), "a", 0, nil); err != nil {
		t.Fatal(err)
	}
	if len(cmds.created) != 0 {
		t.Fatalf("queued %d command(s) for a step above the scan's intensity", len(cmds.created))
	}
	b := store.rows["b"]
	if b.Status != scanrun.StepRunStatusSkipped || !strings.Contains(b.SkipReason, "passive intensity") {
		t.Fatalf("b is %s (%q), want skipped for the intensity", b.Status, b.SkipReason)
	}
	if len(runs.statuses) != 1 {
		t.Fatalf("run transitions = %v, want the run to end", runs.statuses)
	}
}

// A run that records no intensity (a workflow run without a scan) is not
// capped here; a step that fits is not skipped.
func TestIntensitySkipReason(t *testing.T) {
	http := &scanworkflow.Step{StepKey: "http", Capabilities: []string{"probe.http"}}
	dns := &scanworkflow.Step{StepKey: "dns", Capabilities: []string{"resolve.dns"}}
	zap := &scanworkflow.Step{StepKey: "zap", Tool: "zap"}
	run := func(i string) *scanrun.Run {
		r := &scanrun.Run{Context: map[string]any{}}
		if i != "" {
			r.Context[scanapp.RunContextKeyIntensity] = i
		}
		return r
	}
	cases := []struct {
		intensity string
		step      *scanworkflow.Step
		skipped   bool
	}{
		{"passive", dns, false}, {"passive", http, true}, {"active", http, false},
		{"active", zap, true}, {"intrusive", zap, false}, {"", zap, false},
		{"bogus", zap, false}, // an unreadable value records no ceiling; the claim fails it closed
	}
	for _, c := range cases {
		if got := scanapp.IntensitySkipReason(run(c.intensity), c.step) != ""; got != c.skipped {
			t.Errorf("%s step at %q intensity: skipped = %v, want %v", c.step.StepKey, c.intensity, got, c.skipped)
		}
	}
}

// The resolved tool decides too: a passive step whose tool reaches its
// targets, or a step whose tool probes above the run's intensity, is
// refused before any command exists.
func TestCheckStepIntensity_ResolvedTool(t *testing.T) {
	run := &scanrun.Run{ID: shared.NewID(), Context: map[string]any{scanapp.RunContextKeyIntensity: "passive"}}
	dns, _ := stage.Lookup(stage.ResolveDNS)
	ok := scanapp.StepTool{Name: "dnsx", Stage: dns, HasStage: true}
	if err := checkStepIntensity(run, &scanworkflow.Step{Tool: "dnsx"}, ok); err != nil {
		t.Fatalf("dnsx at passive: %v", err)
	}
	// A tool that sends packets to its targets placed on the passive stage.
	bad := scanapp.StepTool{Name: "naabu", Stage: dns, HasStage: true}
	run.Context[scanapp.RunContextKeyIntensity] = "intrusive"
	err := checkStepIntensity(run, &scanworkflow.Step{Capabilities: []string{"resolve.dns"}}, bad)
	if !errors.Is(err, shared.ErrValidation) || !strings.Contains(err.Error(), "sends traffic to its targets") {
		t.Fatalf("passive step with a target-network tool: %v", err)
	}
	// Custom resolvers make dnsx active: refused at passive.
	run.Context[scanapp.RunContextKeyIntensity] = "passive"
	err = checkStepIntensity(run, &scanworkflow.Step{Tool: "dnsx", Config: map[string]any{"resolvers": []any{"203.0.113.53"}}}, ok)
	if err == nil || !strings.Contains(err.Error(), "above the scan's passive intensity") {
		t.Fatalf("dnsx with custom resolvers at passive: %v", err)
	}
}
