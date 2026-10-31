package scope

import "testing"

// SECURITY (RFC-054 §16.3): whatever a job asks for, the clamp of a tool
// in the profile passes the low-impact check, and a tool outside it is
// never clamped.
func TestLowImpactClampPassesTheCheck(t *testing.T) {
	cases := []struct {
		tool string
		cfg  map[string]any
	}{
		{"naabu", map[string]any{"ports": "1-65535", "rate": 1000}},
		{"naabu", map[string]any{"top_ports": 1000}},
		{"naabu", map[string]any{"ports": "22,80,9999", "rate": "fast"}},
		{"nuclei", map[string]any{"severity": "critical,high", "tags": "cve,rce", "rate_limit": 150, "concurrency": 25, "templates": []any{"x"}}},
		{"nuclei", map[string]any{}},
		{"nuclei", map[string]any{"tags": []any{"tech", "cve"}}},
		{"httpx", map[string]any{"path": []any{"/admin", "/.well-known/security.txt"}, "rate_limit": 500, "ports": "1-65535"}},
		{"dnsx", nil},
	}
	for _, tc := range cases {
		out, ok := LowImpactClamp(tc.tool, tc.cfg)
		if !ok {
			t.Fatalf("%s %v: not clamped", tc.tool, tc.cfg)
		}
		if r := LowImpactRefusal(LowImpactJob{Tool: tc.tool, Config: out}); r != "" {
			t.Fatalf("%s %v -> %v still refused", tc.tool, tc.cfg, out)
		}
	}
	if _, ok := LowImpactClamp("katana", map[string]any{}); ok {
		t.Fatal("a crawler is never clamped into the profile")
	}
	out, _ := LowImpactClamp("naabu", map[string]any{"ports": "22,80,9999"})
	if out["ports"] != "22,80" {
		t.Fatalf("ports cut to the profile: %v", out["ports"])
	}
	in := map[string]any{"ports": "1-65535"}
	_, _ = LowImpactClamp("naabu", in)
	if in["ports"] != "1-65535" {
		t.Fatal("the input is not modified")
	}
}

func TestLowImpactRefusalFailsClosed(t *testing.T) {
	refused := []LowImpactJob{
		{Tool: "naabu", Config: map[string]any{"ports": "full", "rate": 5}},
		{Tool: "naabu", Config: map[string]any{"ports": 80, "rate": 5}},
		{Tool: "nuclei", Config: map[string]any{"severity": "info", "tags": "tech", "rate_limit": 5, "concurrency": 2}, Interactsh: true},
		{Tool: "nuclei", Config: map[string]any{"severity": []any{1}, "tags": "tech", "rate_limit": 5, "concurrency": 2}},
		{Tool: "httpx", Config: map[string]any{"path": 7}},
		{Tool: "httpx", Config: map[string]any{"rate_limit": 0}},
		{Tool: "", Config: nil},
	}
	for _, j := range refused {
		if LowImpactRefusal(j) == "" {
			t.Fatalf("not refused: %+v", j)
		}
	}
	if _, ok := LowImpactConfig(map[string]any{"ports": "80"}, map[string]any{"ports": "1-65535"}); ok {
		t.Fatal("conflicting config and scanner_config must be unreadable")
	}
	if m, ok := LowImpactConfig(map[string]any{"ports": "80"}, map[string]any{"rate": 5}); !ok || len(m) != 2 {
		t.Fatalf("merge: %v %v", m, ok)
	}
	if got := ClampPorts("1-65535", WebPorts); got != WebPorts {
		t.Fatalf("clamp to web ports: %s", got)
	}
	if !PortsWithin(WebPorts, []Constraint{{Ports: LowImpactPorts}}) {
		t.Fatal("the web ports are low-impact ports")
	}
	if got := (JobShape{Tool: "naabu", Settings: SettingsUnreadable}).LowImpactJob(); LowImpactRefusal(got) == "" {
		t.Fatal("unreadable settings are refused")
	}
}

// Subdomain brute force (dnsx-enum) is not a low-impact tool: an
// unclassified asset never gets it, whatever its settings.
func TestLowImpactRefusesSubdomainBruteForce(t *testing.T) {
	job := LowImpactJob{Tool: "dnsx-enum", Config: map[string]any{"method": "bruteforce", "rate_limit": 1, "max_queries": 1}}
	if LowImpactRefusal(job) != LowImpactRefused {
		t.Fatal("dnsx-enum may run on a low-impact target")
	}
}
