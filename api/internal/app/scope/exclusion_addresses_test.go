package scope

import (
	"slices"
	"testing"
)

// An exclusion of an address excludes every asset recorded with it, under
// the canonical key or any synonym a row written before the property
// normalisation still holds (RFC-042 §6.3.9): matching fails closed.
func TestAssetExclusionValues_ReadEveryAddressSpelling(t *testing.T) {
	cases := map[string]map[string]any{
		"ip_addresses":           {"ip_addresses": []any{"203.0.113.7"}},
		"ip":                     {"ip": "203.0.113.7"},
		"resolved_ips string":    {"resolved_ips": "198.51.100.1, 203.0.113.7"},
		"ips":                    {"ips": []string{"203.0.113.7"}},
		"addresses":              {"addresses": []any{"203.0.113.7"}},
		"ip_address block":       {"ip_address": map[string]any{"address": "203.0.113.7"}},
		"plain ip_address":       {"ip_address": "203.0.113.7"},
		"resolved_ip (singular)": {"resolved_ip": "203.0.113.7"},
	}
	for name, props := range cases {
		t.Run(name, func(t *testing.T) {
			if got := AssetExclusionValues("domain", "app.example.com", props); !slices.Contains(got, "203.0.113.7") {
				t.Errorf("AssetExclusionValues = %v, want the address", got)
			}
		})
	}
}
