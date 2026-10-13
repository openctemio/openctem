package scanrun

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/openctemio/sdk-go/pkg/politeness"

	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

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

// The platform keys a chunk with the function the sensor admits it with
// (sdk-go pkg/politeness), over every target form a step carries: names,
// URLs, services in every name form, addresses (mapped and IPv6 too) and
// ranges. The sensor side proves, with the same keys, that it admits a
// chunk exactly when the platform offers it (sdk-go core
// TestQueue_KeysAgreeWithPlatform).
func TestChunkHostKeys_SameAsSensor(t *testing.T) {
	probe, _ := stage.Lookup(stage.ProbeHTTP)
	targets := []string{
		"App.Example.com", "app.example.com.", "https://app.example.com:8443/", "http://[2001:db8::1]:80/x",
		"app.example.com:443", "10.0.0.5", "10.0.0.5:22", "app.example.com/login", "2001:db8::2",
		"example.co.uk:443:tcp", "example.co.uk:443/tcp", "[2001:db8::1]:443/tcp", "2001:db8::1:443:tcp",
		"203.0.113.0/22", "203.0.113.7-203.0.114.9", "::ffff:10.0.0.6", "10.0.0.7/32",
	}
	if got, want := chunkHostKeys(probe, true, targets), politeness.Keys(targets, ""); !slices.Equal(got, want) {
		t.Fatalf("platform keys %q\nsensor keys %q", got, want)
	}
	for _, tg := range targets {
		if got, want := chunkHostKeys(probe, true, []string{tg}), politeness.Keys([]string{tg}, ""); !slices.Equal(got, want) {
			t.Errorf("%s: platform %q, sensor %q", tg, got, want)
		}
	}
	// Canonical addresses: a mapped or /32 form holds the same host.
	if got := chunkHostKeys(probe, true, []string{"::ffff:10.0.0.6", "10.0.0.6/32", "10.0.0.6"}); !slices.Equal(got, []string{"10.0.0.6", "in:10.0.0.0/24"}) {
		t.Fatalf("canonical address keys = %q", got)
	}
}

func TestWithHostKeys(t *testing.T) {
	out, err := withHostKeys(json.RawMessage(`{"targets":["a.example.com"],"host_keys":["forged"],"scanner":"httpx"}`), []string{"a.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	var p map[string]any
	if err := json.Unmarshal(out, &p); err != nil {
		t.Fatal(err)
	}
	if p["scanner"] != "httpx" || len(p["targets"].([]any)) != 1 {
		t.Fatalf("other fields changed: %s", out)
	}
	if hk := p["host_keys"].([]any); len(hk) != 1 || hk[0] != "a.example.com" {
		t.Fatalf("host_keys = %v, want the platform's", hk)
	}
	// A passive stage: an empty list, never null.
	out, err = withHostKeys(nil, nil)
	if err != nil || string(out) != `{"host_keys":[]}` {
		t.Fatalf("passive payload = %s (%v)", out, err)
	}
	if _, err := withHostKeys(json.RawMessage(`[1]`), nil); err == nil {
		t.Fatal("a payload that is not an object must fail")
	}
}
