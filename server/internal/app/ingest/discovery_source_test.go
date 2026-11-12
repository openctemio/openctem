package ingest

import "testing"

// Sensors embed the ctis recon converter, whose default label is "agent";
// it is stored as "sensor". Any other label is kept.
func TestNormalizeDiscoverySource(t *testing.T) {
	for in, want := range map[string]string{
		"agent":       DiscoverySourceSensor,
		"sensor":      DiscoverySourceSensor,
		"integration": "integration",
		"manual":      "manual",
		"":            "",
	} {
		if got := normalizeDiscoverySource(in); got != want {
			t.Errorf("normalizeDiscoverySource(%q) = %q, want %q", in, got, want)
		}
	}
}
