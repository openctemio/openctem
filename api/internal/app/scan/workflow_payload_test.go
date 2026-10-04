package scan

import (
	"reflect"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/pipeline"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A workflow step's command names its tool in `scanner`, which the sensor
// SDK runs; preferred_tool alone made every step fail with "scanner not
// found: ".
func TestWorkflowStepPayload_NamesTheScanner(t *testing.T) {
	run := &pipeline.Run{ID: shared.NewID(), Context: map[string]any{"targets": []string{"example.com"}}}
	step := &pipeline.Step{ID: shared.NewID(), StepKey: "dns_resolve", Tool: "dnsx", Capabilities: []string{"recon", "dns"}}
	p, err := workflowStepPayload(run, step, "sr-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if p["scanner"] != "dnsx" || p["preferred_tool"] != "dnsx" {
		t.Fatalf("scanner = %v, preferred_tool = %v", p["scanner"], p["preferred_tool"])
	}
	if !reflect.DeepEqual(p["targets"], []string{"example.com"}) {
		t.Fatalf("targets = %v", p["targets"])
	}
	if p[pipeline.PayloadKeyStepRunID] != "sr-1" {
		t.Fatalf("step run = %v", p[pipeline.PayloadKeyStepRunID])
	}
	p, err = workflowStepPayload(&pipeline.Run{ID: shared.NewID()}, &pipeline.Step{ID: shared.NewID(), StepKey: "merge"}, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := p["scanner"]; ok {
		t.Fatal("tool-less step names a scanner")
	}
}

// A workflow step's settings go under `config`, the key the sensor SDK
// reads; `step_config` reached no sensor.
func TestWorkflowStepPayload_SettingsUnderTheKeyTheSensorReads(t *testing.T) {
	run := &pipeline.Run{ID: shared.NewID()}
	step := &pipeline.Step{ID: shared.NewID(), StepKey: "ports", Tool: "naabu",
		Config: map[string]any{"ports": "80", "top_ports": "1000"}}
	if _, err := workflowStepPayload(run, step, "sr-1", nil); err == nil {
		t.Fatal("ports and top_ports together accepted")
	}
	step.Config = map[string]any{"top_ports": "1000", "rate": float64(500)}
	p, err := workflowStepPayload(run, step, "sr-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg, ok := p[pipeline.PayloadKeyConfig].(map[string]any)
	if !ok || cfg["top_ports"] != int64(1000) || cfg["rate"] != int64(500) {
		t.Fatalf("config = %#v", p[pipeline.PayloadKeyConfig])
	}
	if _, ok := p["step_config"]; ok {
		t.Error("payload still carries step_config")
	}
	step.Config = map[string]any{"tags": []any{"cve", "-code"}}
	step.Tool = "nuclei"
	if _, err := workflowStepPayload(run, step, "sr-1", nil); err == nil {
		t.Fatal("a flag as a nuclei tag reached a command payload")
	}
}

// The recon tools run through the SDK's recon scanner, which reads the
// whole target list: one job, not one per target.
func TestScannerAcceptsTargetList_ReconTools(t *testing.T) {
	for _, s := range []string{"subfinder", "dnsx", "naabu", "httpx", "katana", "Subfinder"} {
		if !scannerAcceptsTargetList(s) {
			t.Errorf("%s does not take a target list", s)
		}
		p := map[string]any{}
		applyTargetsToPayload(p, s, []string{"a.example.com", "b.example.com"})
		if _, ok := p["target"]; ok {
			t.Errorf("%s: a list job also sets target %v", s, p["target"])
		}
	}
	if scannerAcceptsTargetList("semgrep") {
		t.Error("semgrep takes a list")
	}
}
