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

	p, err := stepCommandPayload(run, step, stepRun, pipeline.Settings{}, nil)
	if err != nil {
		t.Fatal(err)
	}
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
	p, err = stepCommandPayload(&pipeline.Run{ID: shared.NewID()}, toolless, stepRun, pipeline.Settings{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := p["scanner"]; ok {
		t.Fatalf("tool-less step names a scanner: %v", p["scanner"])
	}
	if _, ok := p["targets"]; ok {
		t.Fatalf("targets without run targets: %v", p["targets"])
	}
}

// The sensor SDK reads a scan's settings from the payload key `config`
// (ScanCommandPayload.Config). Steps sent them as `step_config`, which no
// sensor reads: a naabu step with ports "80" scanned the top 100 ports.
func TestStepCommandPayload_SettingsUnderTheKeyTheSensorReads(t *testing.T) {
	run := &pipeline.Run{ID: shared.NewID()}
	stepRun := &pipeline.StepRun{ID: shared.NewID()}
	step := &pipeline.Step{ID: shared.NewID(), StepKey: "ports", Tool: "naabu",
		Config: map[string]any{"ports": "80"}}
	p, err := stepCommandPayload(run, step, stepRun, pipeline.Settings{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg, ok := p["config"].(map[string]any)
	if !ok || cfg["ports"] != "80" {
		t.Fatalf("payload config = %#v; the sensor would scan its default ports", p["config"])
	}
	if _, ok := p["step_config"]; ok {
		t.Error("payload still carries step_config, which no sensor reads")
	}

	// Values are sent in the form the sensor's schema takes.
	step = &pipeline.Step{ID: shared.NewID(), StepKey: "vulns", Tool: "nuclei",
		Config: map[string]any{"tags": "CVE, exposure", "severity": []any{"high", "critical"}}}
	p, err = stepCommandPayload(run, step, stepRun, pipeline.Settings{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg = p["config"].(map[string]any)
	if !reflect.DeepEqual(cfg["tags"], []string{"cve", "exposure"}) || !reflect.DeepEqual(cfg["severity"], []string{"high", "critical"}) {
		t.Fatalf("config = %#v", cfg)
	}

	// SECURITY: a value the sensor would refuse fails the step before any
	// command exists.
	step = &pipeline.Step{ID: shared.NewID(), StepKey: "ports", Tool: "naabu",
		Config: map[string]any{"ports": "80 -nmap-cli id"}}
	if _, err := stepCommandPayload(run, step, stepRun, pipeline.Settings{}, nil); err == nil {
		t.Fatal("flag injection in ports reached a command payload")
	}
}
