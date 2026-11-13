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

func TestPartitionServiceIDs_MixedNamesAndIDs(t *testing.T) {
	const a = "4f1c2a8e-3b6d-4c1e-9f0a-1b2c3d4e5f60"
	const b = "0a1b2c3d-4e5f-4061-8728-394a5b6c7d8e"
	valid, invalid := partitionServiceIDs([]string{a, "Payments API", b, "urn:uuid:" + a, "{" + b + "}"})
	if len(valid) != 2 || valid[0] != a || valid[1] != b {
		t.Fatalf("valid = %v, want [%s %s]", valid, a, b)
	}
	if len(invalid) != 3 || invalid[0] != "Payments API" {
		t.Fatalf("invalid = %v, want the name and the two non-canonical forms", invalid)
	}
}

func TestPartitionServiceIDs_OnlyNamesFallsBack(t *testing.T) {
	// No valid ID left: the caller must see an empty list so it takes the
	// all-tenant-assets path, the same as an empty charter.
	valid, invalid := partitionServiceIDs([]string{"Payments", "Checkout"})
	if len(valid) != 0 || len(invalid) != 2 {
		t.Fatalf("valid=%v invalid=%v", valid, invalid)
	}
	if got := scopeModeLabel(valid); got != "all-tenant-assets" {
		t.Fatalf("scope mode = %q, want all-tenant-assets", got)
	}
}

func TestPartitionServiceIDs_Empty(t *testing.T) {
	valid, invalid := partitionServiceIDs(nil)
	if len(valid) != 0 || len(invalid) != 0 {
		t.Fatalf("valid=%v invalid=%v", valid, invalid)
	}
}

func TestCapStrings(t *testing.T) {
	if got := capStrings([]string{"a", "b", "c"}, 2); len(got) != 2 {
		t.Fatalf("got %v", got)
	}
	if got := capStrings([]string{"a"}, 2); len(got) != 1 {
		t.Fatalf("got %v", got)
	}
}
