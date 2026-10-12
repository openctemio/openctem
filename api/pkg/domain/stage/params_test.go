package stage

import (
	"errors"
	"reflect"
	"testing"
)

func TestValidateParams(t *testing.T) {
	ports, _ := Lookup(ScanPorts)
	vuln, _ := Lookup(VulnTemplates)

	ok := []struct {
		name   string
		s      Stage
		config map[string]any
		pinned string
	}{
		{"standard params", ports, map[string]any{"ports": "80,443,8000-8100", "rate": float64(500), "protocol": "tcp"}, ""},
		{"top_n", ports, map[string]any{"top_n": 100}, ""},
		{"port as a number", ports, map[string]any{"ports": float64(443)}, ""},
		{"list as array", vuln, map[string]any{"severity": []any{"high", "critical"}, "tags": []any{"cve"}}, ""},
		{"list as text", vuln, map[string]any{"severity": "high, critical"}, ""},
		{"executor key", ports, map[string]any{"exclude": []any{"10.0.0.1"}}, ""},
		{"pinned tool setting", ports, map[string]any{"exclude_cdn": true}, "naabu"},
		{"pinned tool extras", ports, map[string]any{"x": map[string]any{"naabu": map[string]any{"retries": 2}}}, "naabu"},
		{"nil", ports, nil, ""},
	}
	for _, c := range ok {
		if err := ValidateParams(c.s, c.config, c.pinned); err != nil {
			t.Errorf("%s: refused: %v", c.name, err)
		}
	}

	bad := []struct {
		name   string
		s      Stage
		config map[string]any
		pinned string
	}{
		{"unknown key, not pinned", ports, map[string]any{"exclude_cdn": true}, ""},
		{"rate above max", ports, map[string]any{"rate": float64(1e6)}, ""},
		{"rate below min", ports, map[string]any{"rate": 0}, ""},
		{"fractional rate", ports, map[string]any{"rate": 1.5}, ""},
		{"rate as text", ports, map[string]any{"rate": "fast"}, ""},
		{"udp not in contract", ports, map[string]any{"protocol": "udp"}, ""},
		{"bad port list", ports, map[string]any{"ports": "80;rm -rf"}, ""},
		{"flag-like port", ports, map[string]any{"ports": "-p-"}, ""},
		{"unknown severity", vuln, map[string]any{"severity": []any{"urgent"}}, ""},
		{"list of numbers", vuln, map[string]any{"tags": []any{1, 2}}, ""},
		{"extras without a pin", ports, map[string]any{"x": map[string]any{"naabu": map[string]any{}}}, ""},
		{"extras for another tool", ports, map[string]any{"x": map[string]any{"masscan": map[string]any{}}}, "naabu"},
		{"extras not an object", ports, map[string]any{"x": "naabu"}, "naabu"},
	}
	for _, c := range bad {
		err := ValidateParams(c.s, c.config, c.pinned)
		if !errors.Is(err, ErrInvalidParams) {
			t.Errorf("%s: err = %v, want ErrInvalidParams", c.name, err)
		}
	}
}

func TestUnsupportedParams(t *testing.T) {
	secrets, _ := Lookup(SecretsCode)
	if got := UnsupportedParams(secrets, "betterleaks", map[string]any{"history": true}); !reflect.DeepEqual(got, []string{"history"}) {
		t.Fatalf("betterleaks maps no params: %v", got)
	}
	ports, _ := Lookup(ScanPorts)
	if got := UnsupportedParams(ports, "naabu", map[string]any{"top_n": 10, "rate": 5, "exclude": []any{"x"}, "own": 1}); len(got) != 0 {
		t.Fatalf("naabu takes top_n and rate: %v", got)
	}
}

func TestToolConfig(t *testing.T) {
	ports, _ := Lookup(ScanPorts)
	config := map[string]any{
		"top_n":   100,
		"rate":    500,
		"exclude": []any{"10.0.0.1"},
		"x": map[string]any{
			"naabu":   map[string]any{"retries": 2},
			"masscan": map[string]any{"wait": 1},
		},
	}
	got := ToolConfig(ports, "naabu", config, false)
	want := map[string]any{"top_ports": 100, "rate": 500, "exclude": []any{"10.0.0.1"}, "retries": 2}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("naabu config = %v, want %v", got, want)
	}

	// A pinned step keeps a standard param the tool has no mapping for under
	// its own name (the tool's own setting, as before capabilities), and its
	// plain tool settings.
	probe, _ := Lookup(ProbeHTTP)
	got = ToolConfig(probe, "httpx", map[string]any{"follow_redirects": true, "threads": 50}, true)
	want = map[string]any{"follow_redirects": true, "threads": 50}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("pinned httpx config = %v, want %v", got, want)
	}
	// Resolved (not pinned): a param the tool does not take never goes out.
	got = ToolConfig(probe, "httpx", map[string]any{"follow_redirects": true}, false)
	if len(got) != 0 {
		t.Fatalf("resolved httpx config = %v, want empty", got)
	}
	if ToolConfig(probe, "httpx", nil, true) != nil {
		t.Fatal("nil config must stay nil")
	}
}
