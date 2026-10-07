package pipeline

import (
	"slices"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

func TestHostKey(t *testing.T) {
	for in, want := range map[string]string{
		"App.Example.com":               "app.example.com",
		"app.example.com.":              "app.example.com",
		"https://app.example.com:8443/": "app.example.com",
		"http://[2001:db8::1]:80/x":     "2001:db8::1",
		"app.example.com:443":           "app.example.com",
		"10.0.0.5":                      "10.0.0.5",
		"10.0.0.5:22":                   "10.0.0.5",
		"10.0.0.0/24":                   "10.0.0.0/24",
		"app.example.com/login":         "app.example.com",
		"2001:db8::2":                   "2001:db8::2",
		"  ":                            "",
	} {
		if got := hostKey(in); got != want {
			t.Errorf("hostKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestChunkHostKeys(t *testing.T) {
	probe, _ := stage.Lookup(stage.ProbeHTTP)
	dns, _ := stage.Lookup(stage.ResolveDNS)
	got := chunkHostKeys(probe, true, []string{"https://a.example.com", "a.example.com:443", "b.example.com"})
	if !slices.Equal(got, []string{"a.example.com", "b.example.com"}) {
		t.Fatalf("probe keys = %v", got)
	}
	if got := chunkHostKeys(dns, true, []string{"a.example.com"}); got != nil {
		t.Fatalf("a passive stage got host keys %v", got)
	}
	if got := chunkHostKeys(probe, false, []string{"a.example.com"}); got != nil {
		t.Fatalf("a step outside the catalog got host keys %v", got)
	}
}
