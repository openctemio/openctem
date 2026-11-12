package scanrun

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

// policyFixture is one pending step a with the given capability, in a run
// at depth with a target and a zone.
func policyFixture(capability string, depth scanworkflow.Depth, policy scanworkflow.RunPolicy) (*Service, *scanrun.Run, *scanworkflow.Workflow, *memStepRuns, *countingCommands) {
	s, run, store, _, cmds := gatingFixture(map[string]scanrun.StepRunStatus{"a": scanrun.StepRunStatusPending}, nil)
	tpl, _ := s.templateRepo.GetWithSteps(context.Background(), run.ScanWorkflowID)
	tpl.Steps[0].Capabilities = []string{capability}
	tpl.Steps[0].RunPolicy = policy
	s.toolRepo = platformTools{names: map[string]bool{"dnsx": true, "naabu": true, "httpx": true, "katana": true, "nuclei": true, "subfinder": true}}
	run.Context = map[string]any{"targets": []string{"example.com"}, scanrun.RunContextKeyScanZoneID: shared.NewID().String(),
		scanrun.RunContextKeyDepth: string(depth)}
	return s, run, tpl, store, cmds
}

// Passive depth runs only steps that send nothing to the targets: an HTTP
// probe is skipped with the depth as its reason and no command exists.
func TestDepth_PassiveSkipsActiveSteps(t *testing.T) {
	s, run, tpl, store, cmds := policyFixture("probe.http", scanworkflow.DepthPassive, scanworkflow.RunPolicy{})
	if err := s.scheduleRunnableSteps(context.Background(), run, tpl); err != nil {
		t.Fatal(err)
	}
	a := store.rows["a"]
	if len(cmds.created) != 0 || a.Status != scanrun.StepRunStatusSkipped || !strings.Contains(a.SkipReason, "Passive depth") {
		t.Fatalf("commands %d, a = %s (%q)", len(cmds.created), a.Status, a.SkipReason)
	}

	// A passive step still runs at passive depth.
	s, run, tpl, store, cmds = policyFixture("resolve.dns", scanworkflow.DepthPassive, scanworkflow.RunPolicy{})
	if err := s.scheduleRunnableSteps(context.Background(), run, tpl); err != nil {
		t.Fatal(err)
	}
	if len(cmds.created) != 1 {
		t.Fatalf("resolve.dns at passive depth: commands %d (a = %s %q)", len(cmds.created), store.rows["a"].Status, store.rows["a"].ErrorMessage)
	}
}

// A step that starts at Deep is skipped at Standard, and at Deep it runs
// with the depth's params merged over its config (naabu receives top_ports
// 1000).
func TestDepth_MinDepthAndParams(t *testing.T) {
	policy := scanworkflow.RunPolicy{MinDepth: scanworkflow.DepthDeep, Depths: map[scanworkflow.Depth]scanworkflow.DepthOverlay{
		scanworkflow.DepthDeep: {Params: map[string]any{"top_n": 1000}},
	}}
	s, run, tpl, store, cmds := policyFixture("scan.ports", scanworkflow.DepthStandard, policy)
	if err := s.scheduleRunnableSteps(context.Background(), run, tpl); err != nil {
		t.Fatal(err)
	}
	if a := store.rows["a"]; len(cmds.created) != 0 || a.Status != scanrun.StepRunStatusSkipped || !strings.Contains(a.SkipReason, "Deep depth or deeper") {
		t.Fatalf("standard run: commands %d, a = %s (%q)", len(cmds.created), a.Status, a.SkipReason)
	}

	s, run, tpl, store, cmds = policyFixture("scan.ports", scanworkflow.DepthDeep, policy)
	if err := s.scheduleRunnableSteps(context.Background(), run, tpl); err != nil {
		t.Fatal(err)
	}
	if len(cmds.created) != 1 {
		t.Fatalf("deep run: commands %d (a = %s %q)", len(cmds.created), store.rows["a"].Status, store.rows["a"].ErrorMessage)
	}
	if !strings.Contains(cmds.created[0], `"top_ports":1000`) {
		t.Fatalf("the deep params did not reach the tool: %s", cmds.created[0])
	}
	if _, ok := tpl.Steps[0].Config["top_n"]; ok {
		t.Fatal("dispatch changed the template step's config")
	}
}

// An optional step whose capability no tool implements is skipped with the
// reason, never failed; so is the same step when it is required (a run goes
// as far as the organization's tools support).
func TestOptionalStep_SkippedWithoutTool(t *testing.T) {
	s, run, tpl, store, cmds := policyFixture("fingerprint.tech", scanworkflow.DepthStandard, scanworkflow.RunPolicy{Optional: true})
	if err := s.scheduleRunnableSteps(context.Background(), run, tpl); err != nil {
		t.Fatal(err)
	}
	a := store.rows["a"]
	if len(cmds.created) != 0 || a.Status != scanrun.StepRunStatusSkipped ||
		!strings.Contains(a.SkipReason, "available when a tool that runs fingerprint.tech is installed") {
		t.Fatalf("optional: commands %d, a = %s (%q)", len(cmds.created), a.Status, a.SkipReason)
	}

	s, run, tpl, store, _ = policyFixture("fingerprint.tech", scanworkflow.DepthStandard, scanworkflow.RunPolicy{})
	if err := s.scheduleRunnableSteps(context.Background(), run, tpl); err != nil {
		t.Fatal(err)
	}
	if a := store.rows["a"]; a.Status != scanrun.StepRunStatusSkipped || a.ErrorCode != codeNoMatchingTool ||
		!strings.Contains(a.SkipReason, "fingerprint.tech") {
		t.Fatalf("not optional: a = %s/%s (%q)", a.Status, a.ErrorCode, a.SkipReason)
	}
}

// The scan trigger's door: an optional first step without a tool is
// settled (skipped) and the caller advances the run.
func TestQueueRunStep_OptionalSettled(t *testing.T) {
	s, run, tpl, store, _ := policyFixture("detect.services", scanworkflow.DepthStandard, scanworkflow.RunPolicy{Optional: true})
	err := s.QueueRunStep(context.Background(), run, tpl.Steps[0])
	if !errors.Is(err, scanapp.ErrStepSettled) {
		t.Fatalf("err = %v, want ErrStepSettled", err)
	}
	if a := store.rows["a"]; a.Status != scanrun.StepRunStatusSkipped {
		t.Fatalf("a = %s", a.Status)
	}
}

// With continue-on-failure a step whose dependency failed still runs, on
// the run's targets; without it the step is skipped as blocked.
func TestContinueOnFailedDependency(t *testing.T) {
	for _, cont := range []bool{false, true} {
		s, run, store, _, cmds := gatingFixture(
			map[string]scanrun.StepRunStatus{"a": scanrun.StepRunStatusRunning, "b": scanrun.StepRunStatusPending},
			map[string][]string{"b": {"a"}})
		tpl, _ := s.templateRepo.GetWithSteps(context.Background(), run.ScanWorkflowID)
		tpl.Settings.ContinueOnFailedDependency = cont
		tpl.Steps[1].Tool = "subfinder"
		s.toolRepo = platformTools{names: map[string]bool{"subfinder": true}}
		run.Context = map[string]any{"targets": []string{"example.com"}, scanrun.RunContextKeyScanZoneID: shared.NewID().String()}

		if err := s.failStep(context.Background(), run, run.GetStepRun("a"), "boom", "COMMAND_FAILED"); err != nil {
			t.Fatal(err)
		}
		b := store.rows["b"]
		switch {
		case cont && (len(cmds.created) != 1 || b.Status != scanrun.StepRunStatusQueued):
			t.Fatalf("continue: commands %d, b = %s (%q)", len(cmds.created), b.Status, b.SkipReason)
		case !cont && (len(cmds.created) != 0 || b.Status != scanrun.StepRunStatusSkipped):
			t.Fatalf("default: commands %d, b = %s", len(cmds.created), b.Status)
		}
	}
}

// A step's target cap at the run's depth lowers the stage's cap, never
// raises it; the rest are over the cap.
func TestDeriveCandidates_StepCap(t *testing.T) {
	st, _ := stage.Lookup(stage.ProbeHTTP)
	outs := make([]scanrun.StepOutput, 0, 10)
	for i := range 10 {
		outs = append(outs, scanrun.StepOutput{StepRunID: shared.NewID(), AssetID: shared.NewID(), Name: fmt.Sprintf("h%02d.example.com", i), Type: "subdomain"})
	}
	skipped := map[string]int{}
	c, _ := deriveCandidates(st, outs, nil, nil, map[string]bool{}, skipped, 0, 4)
	if len(c.gate) != 4 || skipped[scanrun.ReasonOverCap] != 6 {
		t.Fatalf("cap 4: %d planned, %d over cap", len(c.gate), skipped[scanrun.ReasonOverCap])
	}
	c, _ = deriveCandidates(st, outs, nil, nil, map[string]bool{}, map[string]int{}, 0, stage.RunFanoutCap*2)
	if len(c.gate) != 10 {
		t.Fatalf("a cap above the stage's must not change anything: %d", len(c.gate))
	}
}

// Depth params are the capability's standard params, valid at every depth;
// tool extras and unknown keys are refused when the step is saved.
func TestCheckRunPolicyParams(t *testing.T) {
	ports, _ := stage.Lookup(stage.ScanPorts)
	step := func(params map[string]any) *scanworkflow.Step {
		return &scanworkflow.Step{StepKey: "ports", Capabilities: []string{"scan.ports"},
			RunPolicy: scanworkflow.RunPolicy{Depths: map[scanworkflow.Depth]scanworkflow.DepthOverlay{scanworkflow.DepthDeep: {Params: params}}}}
	}
	if err := checkRunPolicyParams(step(map[string]any{"top_n": 1000}), ports); err != nil {
		t.Fatal(err)
	}
	for _, p := range []map[string]any{
		{"x": map[string]any{"naabu": map[string]any{"rate": 5}}},
		{"top_ports": 1000},
		{"top_n": 0},
	} {
		if err := checkRunPolicyParams(step(p), ports); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%v: %v", p, err)
		}
	}
	// A step outside the catalog may not set depth params.
	opaque := step(map[string]any{"top_n": 1})
	opaque.Capabilities = []string{"custom-thing"}
	if err := checkStepSelection(opaque, nil); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("depth params on a step outside the catalog: %v", err)
	}
}

// The security validator stays strict on planned capabilities; only an
// optional step's planned capability is left to the graph check.
func TestValidatedCapabilities(t *testing.T) {
	opt := &scanworkflow.RunPolicy{Optional: true}
	if got := validatedCapabilities([]string{"fingerprint.tech"}, opt); len(got) != 0 {
		t.Fatalf("optional planned: %v", got)
	}
	if got := validatedCapabilities([]string{"fingerprint.tech"}, &scanworkflow.RunPolicy{}); len(got) != 1 {
		t.Fatalf("a step that is not optional must have its planned capability checked: %v", got)
	}
	if got := validatedCapabilities([]string{"scan.ports", "exploit.everything"}, opt); len(got) != 2 {
		t.Fatalf("routed and unknown capabilities stay checked: %v", got)
	}
	if got := validatedCapabilities([]string{"verify.finding"}, opt); len(got) != 1 {
		t.Fatalf("a cross-cutting capability stays checked: %v", got)
	}
}

// The scan's step params are the last layer: step config, then the depth
// overlay, then the scan override. A read-only (system) workflow step is
// never changed.
func TestStepAtDepth_ScanOverrideWinsOverDepthOverlayAndConfig(t *testing.T) {
	step := &scanworkflow.Step{StepKey: "vulns", Capabilities: []string{"vuln.templates"},
		Config: map[string]any{"severity": []any{"critical"}, "tags": []any{"cve"}},
		RunPolicy: scanworkflow.RunPolicy{Depths: map[scanworkflow.Depth]scanworkflow.DepthOverlay{
			scanworkflow.DepthDeep: {Params: map[string]any{"severity": []any{"info", "low"}, "tags": []any{"tech"}}},
		}}}
	run := &scanrun.Run{Context: map[string]any{
		scanrun.RunContextKeyDepth: "deep",
		scanrun.RunContextKeyStepParams: map[string]any{
			"*:vuln.templates": map[string]any{"severity": []any{"high"}},
		},
	}}
	got := stepAtDepth(run, step)
	if sev := got.Config["severity"].([]any); len(sev) != 1 || sev[0] != "high" {
		t.Fatalf("severity = %v: the scan override must beat the depth overlay", sev)
	}
	if tags := got.Config["tags"].([]any); tags[0] != "tech" {
		t.Fatalf("tags = %v: the depth overlay still beats the step config where the scan sets nothing", tags)
	}
	// A step-key entry beats the capability entry.
	run.Context[scanrun.RunContextKeyStepParams] = map[string]any{
		"*:vuln.templates": map[string]any{"severity": []any{"high"}},
		"vulns":            map[string]any{"severity": []any{"medium"}},
	}
	if sev := stepAtDepth(run, step).Config["severity"].([]any); sev[0] != "medium" {
		t.Fatalf("severity = %v: step key must win", sev)
	}
	if step.Config["severity"].([]any)[0] != "critical" {
		t.Fatal("the workflow step was modified")
	}
	// Another capability's step is not touched by the capability entry.
	ports := &scanworkflow.Step{StepKey: "p", Capabilities: []string{"scan.ports"}, Config: map[string]any{"ports": "80"}}
	if stepAtDepth(run, ports).Config["ports"] != "80" {
		t.Fatal("capability entry leaked to another capability")
	}
}

// A registration lookup answers for the registered domain: the names of a
// predecessor's output collapse to their registrable domains, each once, and
// the cap counts domains, not names.
func TestDeriveCandidates_RegistryLevelCollapsesNames(t *testing.T) {
	rdap, _ := stage.Lookup(stage.LookupRDAP)
	outs := []scanrun.StepOutput{}
	for _, n := range []string{"a.example.com", "b.example.com", "example.com", "www.example.co.uk", "c.example.org", "co.uk"} {
		outs = append(outs, scanrun.StepOutput{StepRunID: shared.NewID(), AssetID: shared.NewID(), Name: n, Type: "domain"})
	}
	skipped := map[string]int{}
	c, _ := deriveCandidates(rdap, outs, nil, nil, map[string]bool{}, skipped, 0, 0)
	got := map[string]bool{}
	for _, g := range c.gate {
		got[g.key] = true
	}
	if len(c.gate) != 3 || !got["example.com"] || !got["example.co.uk"] || !got["example.org"] {
		t.Fatalf("planned %v", got)
	}
	if skipped[scanrun.ReasonDuplicate] != 2 || skipped[scanrun.ReasonInvalid] != 1 {
		t.Fatalf("skipped %v", skipped)
	}

	// A stage that answers per name keeps every name.
	probe, _ := stage.Lookup(stage.ProbeHTTP)
	c, _ = deriveCandidates(probe, outs, nil, nil, map[string]bool{}, map[string]int{}, 0, 0)
	if len(c.gate) != 6 {
		t.Fatalf("probe planned %d", len(c.gate))
	}
}

func TestCollapseRegistrable(t *testing.T) {
	rdap, _ := stage.Lookup(stage.LookupRDAP)
	resolved := scanapp.StepTool{Name: "rdap", Stage: rdap, HasStage: true}
	in := &scanapp.StepTargets{Targets: []string{"a.example.com", "B.Example.com", "example.com", "x.example.org", "198.51.100.7"}, Refused: 2, Reason: "r"}
	out := collapseRegistrable(resolved, in, nil)
	want := []string{"example.com", "example.org", "198.51.100.7"}
	if len(out.Targets) != len(want) || out.Refused != 2 || out.Reason != "r" {
		t.Fatalf("collapsed %+v", out)
	}
	for i, w := range want {
		if out.Targets[i] != w {
			t.Fatalf("collapsed %v, want %v", out.Targets, want)
		}
	}
	// The input is not changed, and a stage that answers per name is left alone.
	if len(in.Targets) != 5 {
		t.Fatal("input changed")
	}
	probe, _ := stage.Lookup(stage.ProbeHTTP)
	if got := collapseRegistrable(scanapp.StepTool{Name: "httpx", Stage: probe, HasStage: true}, in, nil); got != in {
		t.Fatal("a per-name stage must keep its targets")
	}
	// No explicit target list: left as is.
	if got := collapseRegistrable(resolved, nil, nil); got != nil {
		t.Fatalf("got %+v", got)
	}
}

type stepGateStub struct{ reason string }

func (g stepGateStub) StepSkipReason(context.Context, shared.ID, *scanworkflow.Step) string {
	return g.reason
}

// A step the organization's switch holds off (screenshots) is skipped with
// the reason and no command exists, so the sensor never takes the picture;
// with the switch on the same step is dispatched to the screenshot tool.
func TestStepGate_SkipsScreenshotStepWhenOff(t *testing.T) {
	s, run, tpl, store, cmds := policyFixture("capture.screenshot", scanworkflow.DepthStandard, scanworkflow.RunPolicy{Optional: true})
	s.toolRepo = platformTools{names: map[string]bool{"webshot": true, "httpx": true}}
	s.SetStepGate(stepGateStub{reason: "skipped: screenshots are off for this organization"})
	if err := s.scheduleRunnableSteps(context.Background(), run, tpl); err != nil {
		t.Fatal(err)
	}
	a := store.rows["a"]
	if len(cmds.created) != 0 || a.Status != scanrun.StepRunStatusSkipped || !strings.Contains(a.SkipReason, "screenshots are off") {
		t.Fatalf("switch off: commands %d, a = %s (%q)", len(cmds.created), a.Status, a.SkipReason)
	}

	s, run, tpl, store, cmds = policyFixture("capture.screenshot", scanworkflow.DepthStandard, scanworkflow.RunPolicy{Optional: true})
	s.toolRepo = platformTools{names: map[string]bool{"webshot": true, "httpx": true}}
	s.SetStepGate(stepGateStub{})
	run.Context["targets"] = []string{"https://example.com"}
	if err := s.scheduleRunnableSteps(context.Background(), run, tpl); err != nil {
		t.Fatal(err)
	}
	if len(cmds.created) != 1 {
		t.Fatalf("switch on: commands %d (a = %s %q)", len(cmds.created), store.rows["a"].Status, store.rows["a"].ErrorMessage)
	}
}
