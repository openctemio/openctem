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
	p := workflowStepPayload(run, step, "sr-1")
	if p["scanner"] != "dnsx" || p["preferred_tool"] != "dnsx" {
		t.Fatalf("scanner = %v, preferred_tool = %v", p["scanner"], p["preferred_tool"])
	}
	if !reflect.DeepEqual(p["targets"], []string{"example.com"}) {
		t.Fatalf("targets = %v", p["targets"])
	}
	if p[pipeline.PayloadKeyStepRunID] != "sr-1" {
		t.Fatalf("step run = %v", p[pipeline.PayloadKeyStepRunID])
	}
	p = workflowStepPayload(&pipeline.Run{ID: shared.NewID()}, &pipeline.Step{ID: shared.NewID(), StepKey: "merge"}, "")
	if _, ok := p["scanner"]; ok {
		t.Fatal("tool-less step names a scanner")
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
