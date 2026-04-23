package handler

import (
	"testing"
)

// P0-3: unit tests for the charter → in_scope_services extractor used by
// Activate(). The SQL path that actually writes the snapshot is covered
// by an integration test once the DB harness lands; here we lock in the
// parsing and fallback behaviour.

func TestExtractInScopeServices_Empty(t *testing.T) {
	if got := extractInScopeServices(nil); len(got) != 0 {
		t.Fatalf("nil charter → len %d, want 0", len(got))
	}
	if got := extractInScopeServices([]byte{}); len(got) != 0 {
		t.Fatalf("empty charter → len %d, want 0", len(got))
	}
}

func TestExtractInScopeServices_Malformed(t *testing.T) {
	// Malformed JSON must fall back to "no filter" so the caller defaults
	// to the legacy all-tenant-assets snapshot rather than activating
	// with an empty scope.
	if got := extractInScopeServices([]byte("not json")); len(got) != 0 {
		t.Fatalf("malformed charter → len %d, want 0", len(got))
	}
}

func TestExtractInScopeServices_HappyPath(t *testing.T) {
	raw := []byte(`{"in_scope_services":["svc-1","svc-2"]}`)
	got := extractInScopeServices(raw)
	if len(got) != 2 || got[0] != "svc-1" || got[1] != "svc-2" {
		t.Fatalf("unexpected: %v", got)
	}
}

func TestExtractInScopeServices_FiltersEmpties(t *testing.T) {
	// Defensive: empty strings in the array must not propagate — they
	// would cause the subsequent pq.Array query to filter by "" and
	// match nothing, which looks the same as "all filtered out" from
	// the outside.
	raw := []byte(`{"in_scope_services":["svc-1","","svc-2",""]}`)
	got := extractInScopeServices(raw)
	if len(got) != 2 {
		t.Fatalf("expected 2 non-empty items, got %v", got)
	}
}

func TestExtractInScopeServices_ExtraFieldsIgnored(t *testing.T) {
	raw := []byte(`{"other_field":123,"in_scope_services":["s1"]}`)
	got := extractInScopeServices(raw)
	if len(got) != 1 || got[0] != "s1" {
		t.Fatalf("unexpected: %v", got)
	}
}

func TestScopeModeLabel(t *testing.T) {
	if got := scopeModeLabel(nil); got != "all-tenant-assets" {
		t.Fatalf("nil → %q", got)
	}
	if got := scopeModeLabel([]string{}); got != "all-tenant-assets" {
		t.Fatalf("empty → %q", got)
	}
	if got := scopeModeLabel([]string{"x"}); got != "targeted" {
		t.Fatalf("non-empty → %q", got)
	}
}
