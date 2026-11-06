package command

import (
	"encoding/json"
	"testing"

	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
)

// SECURITY (RFC-054 §16): a job clamped at claim carries the caps in both
// config maps, and a job the caps cannot describe is not clamped.
func TestClampPayload(t *testing.T) {
	raw := json.RawMessage(`{"targets":["a.example.org"],"config":{"ports":"1-65535","rate":1000},"scanner_config":{"rate_limit":500}}`)
	out, ok := clampPayload(raw, "naabu", true, true)
	if !ok {
		t.Fatal("naabu is clampable")
	}
	var p struct {
		Targets       []string       `json:"targets"`
		Config        map[string]any `json:"config"`
		ScannerConfig map[string]any `json:"scanner_config"`
	}
	if err := json.Unmarshal(out, &p); err != nil {
		t.Fatal(err)
	}
	if p.Config["ports"] != scopedom.WebPorts || p.Config["rate"] != float64(scopedom.LowImpactMaxRate) ||
		p.ScannerConfig["rate_limit"] != float64(scopedom.LowImpactMaxRate) || len(p.Targets) != 1 {
		t.Fatalf("clamped: %s", out)
	}
	if _, ok := clampPayload(raw, "katana", true, false); ok {
		t.Fatal("a crawler cannot be clamped into the low-impact profile")
	}
	tpl := json.RawMessage(`{"config":{},"custom_templates":[{"content":"eA=="}]}`)
	if _, ok := clampPayload(tpl, "nuclei", true, false); ok {
		t.Fatal("custom templates cannot be clamped")
	}
	if _, ok := clampPayload(json.RawMessage(`not json`), "naabu", true, false); ok {
		t.Fatal("an unreadable payload is not clamped")
	}
	nuc, ok := clampPayload(json.RawMessage(`{"config":{"severity":"critical","tags":"cve"}}`), "nuclei", true, false)
	if !ok {
		t.Fatal("nuclei is clampable")
	}
	if err := json.Unmarshal(nuc, &p); err != nil {
		t.Fatal(err)
	}
	if sev, _ := p.Config["severity"].([]any); len(sev) != 1 || sev[0] != "info" {
		t.Fatalf("nuclei clamp: %s", nuc)
	}
	if !clampable(map[string]string{"a": scopedom.RefusalLowImpact, "b": scopedom.RefusalWebPortsOnly}) ||
		clampable(map[string]string{"a": scopedom.RefusalLowImpact, "b": scopedom.RefusalExcluded}) || clampable(nil) {
		t.Fatal("clampable")
	}
}

// The platform's default port set (top_ports) is cut like any port list:
// to the web ports for names whose addresses are not in scope, to the
// low-impact list for unclassified assets.
func TestClampPayload_DefaultTopPorts(t *testing.T) {
	raw := json.RawMessage(`{"targets":["a.example.org"],"config":{"top_ports":1000},"scanner_config":{"top_ports":1000}}`)
	for _, c := range []struct {
		lowImpact, web bool
		want           string
	}{{false, true, scopedom.WebPorts}, {true, false, scopedom.LowImpactPorts}} {
		out, ok := clampPayload(raw, "naabu", c.lowImpact, c.web)
		if !ok {
			t.Fatalf("lowImpact=%v web=%v: not clamped", c.lowImpact, c.web)
		}
		var p struct {
			Config        map[string]any `json:"config"`
			ScannerConfig map[string]any `json:"scanner_config"`
		}
		if err := json.Unmarshal(out, &p); err != nil {
			t.Fatal(err)
		}
		for _, cfg := range []map[string]any{p.Config, p.ScannerConfig} {
			if _, top := cfg["top_ports"]; top || cfg["ports"] != c.want {
				t.Errorf("lowImpact=%v web=%v: clamped to %s", c.lowImpact, c.web, out)
			}
		}
	}
}
