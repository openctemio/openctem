package scan

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tool"
)

func effectiveFor(t *testing.T, run *scanrun.Run, step *scanworkflow.Step, name string) scanrun.EffectiveConfig {
	t.Helper()
	tools := &fakeToolLookup{platform: map[string]*tool.Tool{name: activeTool(name)}}
	resolved, err := ResolveStepTool(context.Background(), tools, shared.NewID(), step)
	if err != nil {
		t.Fatal(err)
	}
	at := *step
	at.Config = step.RunPolicy.ConfigAt(step.Config, RunDepth(run))
	payload, err := resolved.CommandPayload(run, resolved.WithTool(&at), "sr", nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg, _ := payload[scanworkflow.PayloadKeyConfig].(map[string]any)
	return EffectiveConfigOf(run, &at, resolved, cfg)
}

func vulnStep(config map[string]any, overlay map[string]any) *scanworkflow.Step {
	s := &scanworkflow.Step{ID: shared.NewID(), StepKey: "vuln", Tool: "nuclei", Capabilities: []string{"vulnerability"}, Config: config}
	if overlay != nil {
		s.RunPolicy = scanworkflow.RunPolicy{Depths: map[scanworkflow.Depth]scanworkflow.DepthOverlay{
			scanworkflow.DepthStandard: {Params: overlay}}}
	}
	return s
}

func TestEffectiveConfigOf_SourceOrder(t *testing.T) {
	run := &scanrun.Run{ID: shared.NewID(), Context: map[string]any{"targets": []string{"a.example.com"}}}

	// template step only
	got := effectiveFor(t, run, vulnStep(map[string]any{"severity": []any{"critical"}}, nil), "nuclei")
	if p := got.Params["severity"]; p.Source != scanrun.ParamSourceTemplateStep {
		t.Fatalf("template: %+v", got.Params)
	}
	// the depth overlay beats the step config
	got = effectiveFor(t, run, vulnStep(map[string]any{"severity": []any{"critical"}}, map[string]any{"severity": []any{"low", "high"}}), "nuclei")
	if p := got.Params["severity"]; p.Source != scanrun.ParamSourceDepthOverlay || len(p.Value.([]string)) != 2 {
		t.Fatalf("overlay: %+v", got.Params)
	}
	if got.Depth != "standard" || got.Tool != "nuclei" {
		t.Fatalf("meta: %+v", got)
	}
}

func TestEffectiveConfigOf_ScanOverrideAndStageFixedWin(t *testing.T) {
	step := vulnStep(map[string]any{"tags": []any{"cve"}}, map[string]any{"tags": []any{"misconfig"}})
	step.Capabilities = []string{"check.takeover"}
	// stage-fixed: nuclei on a takeover step always runs the takeover tag
	run := &scanrun.Run{ID: shared.NewID(), Context: map[string]any{}}
	got := effectiveFor(t, run, step, "nuclei")
	if p, ok := got.Params["tags"]; ok && p.Source != scanrun.ParamSourceStageFixed {
		t.Fatalf("stage fixed should win, got %+v", p)
	}
	// scan override beats the overlay
	step2 := vulnStep(nil, map[string]any{"severity": []any{"info", "low"}})
	run2 := &scanrun.Run{ID: shared.NewID(), Context: map[string]any{
		"step_params": map[string]any{"vuln": map[string]any{"severity": []any{"info", "low"}}}}}
	// the override reaches the command through the config the dispatcher builds
	got = effectiveFor(t, run2, step2, "nuclei")
	if p := got.Params["severity"]; p.Source != scanrun.ParamSourceScanOverride {
		t.Fatalf("scan override: %+v", got.Params)
	}
	// another step's override never attributes
	run2.Context["step_params"] = map[string]any{"other": map[string]any{"severity": []any{"info", "low"}}}
	got = effectiveFor(t, run2, step2, "nuclei")
	if p := got.Params["severity"]; p.Source == scanrun.ParamSourceScanOverride {
		t.Fatalf("other step's override attributed: %+v", p)
	}
}

func TestEffectiveConfigOf_DefaultPortSetAndNoSecrets(t *testing.T) {
	step := &scanworkflow.Step{ID: shared.NewID(), StepKey: "ports", Tool: "naabu", Capabilities: []string{"portscan"},
		Config: map[string]any{"headers": "Authorization: Bearer s3cret"}}
	run := &scanrun.Run{ID: shared.NewID(), Context: map[string]any{"targets": []string{"a.example.com"}}}
	got := effectiveFor(t, run, step, "naabu")
	if p := got.Params["top_n"]; p.Source != scanrun.ParamSourceDefaultPortSet {
		t.Fatalf("port set: %+v", got.Params)
	}
	for k, v := range got.Params {
		if k == "headers" || v.Value == "Authorization: Bearer s3cret" {
			t.Fatalf("non-standard value copied: %s", k)
		}
	}
}
