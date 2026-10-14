package scanrun

import (
	"sort"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

func outNames(outs []scanrun.StepOutput) string {
	n := make([]string, 0, len(outs))
	for _, o := range outs {
		n = append(n, o.Name)
	}
	sort.Strings(n)
	return strings.Join(n, ",")
}

// The template stage gets each web service once, as its origin: not again
// as the port scan's host:port, nor as the name it is served on; an open
// web port the probe found nothing on is not web input; a non-web port
// still goes to the stage (network templates). A stage that takes no
// origins is unchanged, and without origins the ports stay.
func TestCanonicalWebInputs(t *testing.T) {
	vulns, _ := stage.Lookup(stage.VulnTemplates)
	ports, _ := stage.Lookup(stage.ScanPorts)
	outs := []scanrun.StepOutput{
		{Name: "https://www.example.com", Type: "service", SubType: "http"},
		{Name: "http://203.0.113.7:8080", Type: "service", SubType: "http"},
		{Name: "www.example.com", Type: "subdomain"},
		{Name: "api.example.com", Type: "subdomain"},
		{Name: "203.0.113.7", Type: "ip_address"},
		{Name: "www.example.com:443:tcp", Type: "service", SubType: "open_port"},
		{Name: "203.0.113.7:8080:tcp", Type: "service", SubType: "open_port"},
		{Name: "203.0.113.7:8443:tcp", Type: "service", SubType: "open_port"},
		{Name: "203.0.113.7:22:tcp", Type: "service", SubType: "open_port"},
		{Name: "203.0.113.7:5432:tcp", Type: "service", SubType: "open_port"},
	}
	skipped := map[string]int{}
	got := outNames(canonicalWebInputs(vulns, outs, skipped))
	want := "203.0.113.7:22:tcp,203.0.113.7:5432:tcp,api.example.com,http://203.0.113.7:8080,https://www.example.com"
	if got != want {
		t.Fatalf("vulns inputs = %s\nwant %s", got, want)
	}
	if skipped[scanrun.ReasonCoveredByOrigin] != 5 {
		t.Errorf("skipped = %v, want 5 covered_by_origin", skipped)
	}

	if got := canonicalWebInputs(ports, outs, map[string]int{}); len(got) != len(outs) {
		t.Errorf("a stage without web inputs changed: %d of %d", len(got), len(outs))
	}
	noOrigin := []scanrun.StepOutput{
		{Name: "203.0.113.7:443:tcp", Type: "service", SubType: "open_port"},
		{Name: "203.0.113.7", Type: "ip_address"},
	}
	if got := canonicalWebInputs(vulns, noOrigin, map[string]int{}); len(got) != 2 {
		t.Errorf("without origins the ports must stay: %v", outNames(got))
	}
}

func TestOriginAndPortHostPort(t *testing.T) {
	for in, want := range map[string]string{
		"https://www.example.com":     "www.example.com:443",
		"http://203.0.113.7:8080":     "203.0.113.7:8080",
		"http://[2001:db8::1]":        "[2001:db8::1]:80",
		"https://WWW.Example.com/app": "www.example.com:443",
	} {
		if _, hp, ok := originHostPort(in); !ok || hp != want {
			t.Errorf("origin %q -> %q (%v), want %q", in, hp, ok, want)
		}
	}
	if _, _, ok := originHostPort("ftp://x"); ok {
		t.Error("a non-web scheme is an origin")
	}
	for in, want := range map[string]string{
		"203.0.113.7:8080:tcp":  "203.0.113.7:8080",
		"www.example.com:443":   "www.example.com:443",
		"[2001:db8::1]:443:tcp": "[2001:db8::1]:443",
	} {
		if _, hp, _, ok := openPortHostPort(in); !ok || hp != want {
			t.Errorf("port %q -> %q (%v), want %q", in, hp, ok, want)
		}
	}
}
