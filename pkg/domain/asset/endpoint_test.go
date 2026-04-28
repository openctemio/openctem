package asset

import "testing"

// first-class endpoint asset type tests. Locks the minimum
// contract so regressions in the enum / category / normalizer are
// caught immediately.

func TestAssetTypeEndpoint_IsValid(t *testing.T) {
	if !AssetTypeEndpoint.IsValid() {
		t.Fatal("AssetTypeEndpoint should be valid")
	}
	// Sanity: the raw value is stable — the DB CHECK constraint
	// (migrations/000008_assets.up.sql) already whitelists "endpoint".
	if string(AssetTypeEndpoint) != "endpoint" {
		t.Fatalf("wire value changed: got %q, want \"endpoint\"", AssetTypeEndpoint)
	}
}

func TestParseAssetType_Endpoint(t *testing.T) {
	tests := []string{"endpoint", "ENDPOINT", "  Endpoint  "}
	for _, raw := range tests {
		got, err := ParseAssetType(raw)
		if err != nil {
			t.Fatalf("ParseAssetType(%q): %v", raw, err)
		}
		if got != AssetTypeEndpoint {
			t.Fatalf("ParseAssetType(%q) = %q, want endpoint", raw, got)
		}
	}
}

func TestCategoryForType_EndpointInfrastructure(t *testing.T) {
	// Endpoints are user-operated compute → Infrastructure category.
	// UI / dashboards group them with Host, Compute, etc.
	if got := CategoryForType(AssetTypeEndpoint); got != CategoryInfrastructure {
		t.Fatalf("endpoint category = %q, want %q", got, CategoryInfrastructure)
	}
}

func TestNormalize_Endpoint_UsesHostRules(t *testing.T) {
	// Endpoint names normalize via the host rules (lowercase, strip
	// trailing dot). Locks the delegation so a future Host-only tweak
	// doesn't silently stop applying to endpoints.
	raw := "LAPTOP-UK-0141.CORP.EXAMPLE."
	got := NormalizeName(raw, AssetTypeEndpoint, "")
	if got != "laptop-uk-0141.corp.example" {
		t.Fatalf("normalize(endpoint, %q) = %q", raw, got)
	}
}

func TestAllAssetTypes_IncludesEndpoint(t *testing.T) {
	found := false
	for _, t := range AllAssetTypes() {
		if t == AssetTypeEndpoint {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("AllAssetTypes() must include AssetTypeEndpoint")
	}
}
