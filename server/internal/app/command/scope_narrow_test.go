package command

import (
	"encoding/json"
	"slices"
	"testing"
)

// SECURITY: a job narrowed at claim (scope re-check, host split) names only
// the targets it still runs on, also in the tool settings where a quick scan
// carries its target list: a refused target never travels to the sensor.
func TestNarrowPayload_ToolSettingsTargets(t *testing.T) {
	raw := json.RawMessage(`{"targets":["a.example.org","b.example.org","c.example.org"],` +
		`"config":{"targets":["a.example.org","b.example.org","c.example.org"],"rate":150},` +
		`"scanner_config":{"targets":["a.example.org","b.example.org","c.example.org"],"target":"c.example.org"},` +
		`"context":{"targets":["a.example.org","b.example.org","c.example.org"],"scanner_config":{"targets":["c.example.org"]}},` +
		`"targets_per_job":50}`)
	out, err := narrowPayload(raw, []string{"B.example.org"})
	if err != nil {
		t.Fatal(err)
	}
	type lists struct {
		Targets []string `json:"targets"`
		Target  string   `json:"target"`
	}
	var p struct {
		lists
		Config        map[string]any `json:"config"`
		ScannerConfig lists          `json:"scanner_config"`
		Context       struct {
			lists
			ScannerConfig lists `json:"scanner_config"`
		} `json:"context"`
		TargetsPerJob json.Number `json:"targets_per_job"`
	}
	if err := json.Unmarshal(out, &p); err != nil {
		t.Fatal(err)
	}
	want := []string{"b.example.org"}
	cfgTargets := []string{}
	for _, v := range p.Config["targets"].([]any) {
		cfgTargets = append(cfgTargets, v.(string))
	}
	for name, got := range map[string][]string{
		"targets": p.Targets, "config.targets": cfgTargets, "scanner_config.targets": p.ScannerConfig.Targets,
		"context.targets": p.Context.Targets,
	} {
		if !slices.Equal(got, want) {
			t.Errorf("%s = %v, want %v", name, got, want)
		}
	}
	if len(p.Context.ScannerConfig.Targets) != 0 {
		t.Errorf("context.scanner_config.targets = %v, want none", p.Context.ScannerConfig.Targets)
	}
	if p.ScannerConfig.Target != "b.example.org" {
		t.Errorf("scanner_config.target = %q, want the one target left", p.ScannerConfig.Target)
	}
	if p.Config["rate"] != float64(150) || p.TargetsPerJob != "50" {
		t.Errorf("other settings changed: %s", out)
	}
}
