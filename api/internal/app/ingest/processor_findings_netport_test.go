package ingest

import (
	"testing"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// RFC-043 P0: a network finding without a CVE is keyed by the generic recipe,
// which had no port. The port (and transport) is now part of its key.
func TestGenerateFindingFingerprint_GenericNetworkFindingKeysOnPort(t *testing.T) {
	assetID := shared.NewID()
	mk := func(port int, proto string) *ctis.Finding {
		f := &ctis.Finding{RuleID: "51192", Title: "SSL Certificate Cannot Be Trusted"}
		if port > 0 {
			f.Network = &ctis.NetworkLocation{Port: port, Protocol: proto}
		}
		return f
	}
	a, _ := generateFindingFingerprint(assetID, mk(443, "tcp"), nil)
	b, _ := generateFindingFingerprint(assetID, mk(8443, "tcp"), nil)
	if a == b {
		t.Fatal("one plugin on ports 443 and 8443 has one fingerprint")
	}
	c, _ := generateFindingFingerprint(assetID, mk(443, ""), nil)
	if a != c {
		t.Fatal("an empty transport must mean tcp")
	}
	u, _ := generateFindingFingerprint(assetID, mk(443, "udp"), nil)
	if a == u {
		t.Fatal("443/tcp and 443/udp share a fingerprint")
	}
	// A host-level finding keeps the key it always had.
	if legacyPortlessFingerprint(assetID, mk(0, "")) != "" {
		t.Fatal("a host-level finding has no legacy key")
	}
	if got, want := legacyPortlessFingerprint(assetID, mk(443, "tcp")), func() string { h, _ := generateFindingFingerprint(assetID, mk(0, ""), nil); return h }(); got != want {
		t.Fatalf("legacy key of a port finding = %s, want the port-less key %s", got, want)
	}
}

// Recipes that were port-aware already (network VA with a CVE) or that the
// sensor decides (a valid sensor fingerprint) did not change, so they have no
// legacy key to adopt.
func TestLegacyPortlessFingerprint_OnlyForTheGenericRecipe(t *testing.T) {
	assetID := shared.NewID()
	cve := &ctis.Finding{RuleID: "p", Title: "t", Network: &ctis.NetworkLocation{Port: 443},
		Vulnerability: &ctis.VulnerabilityDetails{CVEID: "CVE-2024-6387"}}
	if legacyPortlessFingerprint(assetID, cve) != "" {
		t.Fatal("network VA with a CVE must not be re-keyed")
	}
	sensorFP := &ctis.Finding{RuleID: "p", Title: "t", Network: &ctis.NetworkLocation{Port: 443},
		Fingerprint: "0123456789abcdef0123456789abcdef"}
	if legacyPortlessFingerprint(assetID, sensorFP) != "" {
		t.Fatal("a sensor-supplied fingerprint must not be re-keyed")
	}
	sca := &ctis.Finding{RuleID: "p", Title: "t", Network: &ctis.NetworkLocation{Port: 443},
		Vulnerability: &ctis.VulnerabilityDetails{Package: "openssl", AffectedVersion: "1", CVEID: "CVE-1"}}
	if legacyPortlessFingerprint(assetID, sca) != "" {
		t.Fatal("an SCA finding must not be re-keyed")
	}
}
