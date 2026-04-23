package adapters

import (
	"sort"
	"testing"
)

// P0-1: lock in the list of registered adapters. If someone removes one
// (or forgets to add a new one), this test fails loudly instead of the
// regression going undetected until a customer reports missing SARIF
// ingest in production.
//
// This test is the second of three layers that guard the adapter list:
//   1. The registry constructor (registry.go)
//   2. This test (registry_test.go)
//   3. Future: the F-310-style linter scanning for `r.Register(` calls
func TestNewRegistry_HasExpectedAdapters(t *testing.T) {
	reg := NewRegistry()

	got := reg.List()
	sort.Strings(got)

	want := []string{
		"gitleaks",
		"nuclei",
		"recon", // subdomain/DNS/port/http_probe/url_crawl adapter.
		"sarif", // P0-1 — previously built but unregistered.
		"semgrep",
		"trivy",
		"vuls",
	}

	if len(got) != len(want) {
		t.Fatalf("registry size = %d, want %d. got=%v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("registered adapters mismatch.\n got: %v\nwant: %v", got, want)
		}
	}
}

// SARIF is the one that used to be missing; assert it by name so a
// reviewer reading this diff in two years still understands the intent.
func TestNewRegistry_SARIFRegistered(t *testing.T) {
	reg := NewRegistry()
	if _, ok := reg.Get("sarif"); !ok {
		t.Fatalf("sarif adapter not registered — P0-1 regression")
	}
}
