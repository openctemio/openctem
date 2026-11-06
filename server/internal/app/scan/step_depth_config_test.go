package scan

import (
	"reflect"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

func depthTemplatesStep(cfg map[string]any, policy scanworkflow.RunPolicy) *scanworkflow.Step {
	return &scanworkflow.Step{StepKey: "templates", Capabilities: []string{"vuln.templates"}, Config: cfg, RunPolicy: policy}
}

func nucleiTool(t *testing.T) StepTool {
	t.Helper()
	st, err := stage.ForCapabilities([]string{"vuln.templates"})
	if err != nil {
		t.Fatal(err)
	}
	return StepTool{Name: "nuclei", Stage: st, HasStage: true}
}

// The capability default is the lowest layer: low..critical at standard,
// info..critical at deep; a step value or a depth overlay replaces it.
func TestVulnTemplatesDepthDefaults(t *testing.T) {
	tool := nucleiTool(t)
	sev := func(s *scanworkflow.Step) any { return s.Config["severity"] }
	if got := sev(tool.WithDepthDefaults(StepAtDepth(depthTemplatesStep(nil, scanworkflow.RunPolicy{}), scanworkflow.DepthStandard), scanworkflow.DepthStandard)); !reflect.DeepEqual(got, stage.StandardTemplateSeverities) {
		t.Fatalf("standard: %v", got)
	}
	if got := sev(tool.WithDepthDefaults(StepAtDepth(depthTemplatesStep(nil, scanworkflow.RunPolicy{}), scanworkflow.DepthDeep), scanworkflow.DepthDeep)); !reflect.DeepEqual(got, stage.DeepTemplateSeverities) {
		t.Fatalf("deep: %v", got)
	}
	own := []string{"critical"}
	step := depthTemplatesStep(map[string]any{"severity": own}, scanworkflow.RunPolicy{})
	if got := sev(tool.WithDepthDefaults(StepAtDepth(step, scanworkflow.DepthDeep), scanworkflow.DepthDeep)); !reflect.DeepEqual(got, own) {
		t.Fatalf("the step's own severity was replaced: %v", got)
	}
	overlay := scanworkflow.RunPolicy{Depths: map[scanworkflow.Depth]scanworkflow.DepthOverlay{
		scanworkflow.DepthDeep: {Params: map[string]any{"severity": []string{"high"}}}}}
	if got := sev(tool.WithDepthDefaults(StepAtDepth(depthTemplatesStep(nil, overlay), scanworkflow.DepthDeep), scanworkflow.DepthDeep)); !reflect.DeepEqual(got, []string{"high"}) {
		t.Fatalf("the depth overlay was replaced: %v", got)
	}
	if step.Config["severity"] == nil || len(step.Config) != 1 {
		t.Fatal("the stored step changed")
	}
}

// A default never reaches a tool that does not take the param (a declared
// tool whose descriptor maps no severity stays eligible and gets none), and
// a stage without defaults is untouched.
func TestDepthDefaultsOnlyForParamsTheToolTakes(t *testing.T) {
	tool := nucleiTool(t)
	tool.Declared, tool.Name, tool.params = true, "acme-templates", map[string]string{"tags": "tags"}
	got := tool.WithDepthDefaults(depthTemplatesStep(nil, scanworkflow.RunPolicy{}), scanworkflow.DepthDeep)
	if _, set := got.Config["severity"]; set {
		t.Fatalf("a declared tool without severity got one: %v", got.Config)
	}
	ports, err := stage.ForCapabilities([]string{"scan.ports"})
	if err != nil {
		t.Fatal(err)
	}
	step := &scanworkflow.Step{StepKey: "ports", Capabilities: []string{"scan.ports"}}
	if got := (StepTool{Name: "naabu", Stage: ports, HasStage: true}).WithDepthDefaults(step, scanworkflow.DepthDeep); got != step {
		t.Fatal("a stage without depth defaults changed the step")
	}
	if got := (StepTool{Name: "nuclei", Stage: tool.Stage, HasStage: true}).WithDepthDefaults(depthTemplatesStep(nil, scanworkflow.RunPolicy{}), scanworkflow.DepthPassive); got.Config["severity"] != nil {
		t.Fatal("passive depth got a severity")
	}
}
