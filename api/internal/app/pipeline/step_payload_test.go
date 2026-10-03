package pipeline

import (
	"reflect"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/pipeline"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The sensor SDK runs the scanner named in the payload's `scanner`
// (ScanCommandPayload). A step that carried only preferred_tool failed on
// every sensor with "scanner not found: ".
func TestStepCommandPayload_NamesTheScanner(t *testing.T) {
	run := &pipeline.Run{ID: shared.NewID(), Context: map[string]any{"targets": []string{"example.com"}}}
	stepRun := &pipeline.StepRun{ID: shared.NewID()}
	step := &pipeline.Step{ID: shared.NewID(), StepKey: "subfinder_enum", Tool: "subfinder", Capabilities: []string{"recon", "subdomain"}}

	p := stepCommandPayload(run, step, stepRun, pipeline.Settings{})
	if p["scanner"] != "subfinder" || p["preferred_tool"] != "subfinder" {
		t.Fatalf("scanner = %v, preferred_tool = %v", p["scanner"], p["preferred_tool"])
	}
	if !reflect.DeepEqual(p["targets"], []string{"example.com"}) {
		t.Fatalf("targets = %v", p["targets"])
	}
	if !reflect.DeepEqual(p["required_capabilities"], []string{"recon", "subdomain"}) {
		t.Fatalf("required_capabilities = %v", p["required_capabilities"])
	}

	// A tool-less step names no scanner, and no targets appear from nowhere.
	toolless := &pipeline.Step{ID: shared.NewID(), StepKey: "merge"}
	p = stepCommandPayload(&pipeline.Run{ID: shared.NewID()}, toolless, stepRun, pipeline.Settings{})
	if _, ok := p["scanner"]; ok {
		t.Fatalf("tool-less step names a scanner: %v", p["scanner"])
	}
	if _, ok := p["targets"]; ok {
		t.Fatalf("targets without run targets: %v", p["targets"])
	}
}
