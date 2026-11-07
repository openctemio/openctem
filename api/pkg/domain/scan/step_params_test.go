package scan

import (
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestStepParams_StepKeyWinsOverCapability(t *testing.T) {
	p := StepParams{
		"*:vuln.templates": {"severity": []any{"high"}, "tags": []any{"cve"}},
		"nuclei_step":      {"severity": []any{"info"}},
	}
	got := p.ParamsFor("nuclei_step", "vuln.templates")
	if sev := got["severity"].([]any); len(sev) != 1 || sev[0] != "info" {
		t.Fatalf("severity = %v, step key must win", got["severity"])
	}
	if got["tags"] == nil {
		t.Fatal("capability entry must still apply for keys the step entry does not set")
	}
	other := p.ParamsFor("other", "vuln.templates")
	if other["severity"].([]any)[0] != "high" {
		t.Fatalf("capability entry must apply to every step of the capability: %v", other)
	}
	if p.ParamsFor("other", "scan.ports") != nil {
		t.Fatal("no entry for another capability")
	}
}

func TestStepParams_CheckShape(t *testing.T) {
	big := StepParams{}
	for i := 0; i <= MaxStepParamsEntries; i++ {
		big[string(rune('a'+i%26))+string(rune('a'+i/26))] = map[string]any{"x": 1}
	}
	wide := map[string]any{}
	for i := 0; i <= MaxStepParamsPerEntry; i++ {
		wide[string(rune('a'+i))] = 1
	}
	for name, p := range map[string]StepParams{
		"too many entries": big,
		"too many params":  {"s": wide},
		"empty entry":      {"s": {}},
		"bare prefix":      {"*:": {"a": 1}},
		"blank key":        {" ": {"a": 1}},
	} {
		err := p.CheckShape()
		var de *shared.DomainError
		if err == nil || !errors.Is(err, shared.ErrValidation) || !errors.As(err, &de) || de.Code != CodeInvalidStepParams {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if err := (StepParams{"s": {"a": 1}}).CheckShape(); err != nil {
		t.Fatal(err)
	}
}

func TestScan_SetStepParams_ClearAndClone(t *testing.T) {
	sc, _ := NewScanWithTargets(shared.NewID(), "n", []string{"example.com"}, ScanTypeWorkflow)
	if err := sc.SetStepParams(StepParams{"s": {"tags": []string{"cve"}}}); err != nil {
		t.Fatal(err)
	}
	c := sc.Clone("copy")
	c.StepParams["s"]["tags"].([]string)[0] = "changed"
	if sc.StepParams["s"]["tags"].([]string)[0] != "cve" {
		t.Fatal("clone shares step params")
	}
	if err := sc.SetStepParams(StepParams{}); err != nil || sc.StepParams != nil {
		t.Fatalf("empty must clear: %v %v", err, sc.StepParams)
	}
}
