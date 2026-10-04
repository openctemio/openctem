package ingest

import (
	"testing"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// goldenNetworkFindings are CTIS findings that carry Finding.Network.
func goldenNetworkFindings() []*ctis.Finding {
	net := &ctis.NetworkLocation{Host: "10.0.0.5", Port: 8443, Protocol: "tcp", Service: "https"}
	return []*ctis.Finding{
		// network VA: the port is in the fingerprint (netva:<port>:<cve>)
		{Type: ctis.FindingTypeVulnerability, Title: "OpenSSL RCE", RuleID: "nessus-118987",
			Vulnerability: &ctis.VulnerabilityDetails{CVEID: "CVE-2022-3602"}, Network: net},
		// no CVE: keyed on port and transport since #920 (RFC-043)
		{Type: ctis.FindingTypeVulnerability, Title: "SSL Certificate Cannot Be Trusted", RuleID: "nessus-51192", Network: net},
		// host-level network VA (no port)
		{Type: ctis.FindingTypeVulnerability, Title: "Host-level CVE", RuleID: "nessus-1",
			Vulnerability: &ctis.VulnerabilityDetails{CVEID: "CVE-2023-44487"}, Network: &ctis.NetworkLocation{Host: "10.0.0.5"}},
	}
}

// Storing the port must not change any fingerprint: fingerprint changes go
// through the dedup RFC's re-fingerprint migration. These values are what
// develop computes (a911f939, after #920 keyed no-CVE network findings on
// their port) without this change.
func TestGenerateFindingFingerprint_NetworkFindings_Unchanged(t *testing.T) {
	assetID := shared.MustIDFromString("0193e000-0000-7000-8000-000000000001")
	want := [][2]string{
		{"3448e177470ef2628ca2572ee3d80f476aca76d262cf7f85bcae44aada153a06", "a715fd46e1966e5359f4ee90c04de391b83df0b8e36ac373b449e47ac399a38c"},
		{"67f13437c04edfee6d79b6b2b1e8d337af47ddce7686f33f664e54554d3a4cff", "1472da3219a89c3339bc42a801548c4b71ea169ec3e6a51ff09eecf5066aaea0"},
		{"c4217533d21dfa08da665ed155bfdcfabeabf8ca9ee8d7709eecf926d8743d17", "129397079e4ce7560ed537e3b25b2f7200050bbdf1a64dcdd43216912818c7dc"},
	}
	for i, f := range goldenNetworkFindings() {
		c, b := generateFindingFingerprint(assetID, f, nil)
		if c != want[i][0] || b != want[i][1] {
			t.Errorf("finding %d: fingerprint changed\n got  %s / %s\n want %s / %s", i, c, b, want[i][0], want[i][1])
		}
	}
}

// Ingest used Finding.Network.Port only inside the network-VA fingerprint and
// dropped it, so a stored finding did not know its port.
func TestSetFindingLocationFields_StoresNetworkLocation(t *testing.T) {
	p := &FindingProcessor{}
	f, err := vulnerability.NewFinding(shared.NewID(), shared.NewID(), vulnerability.FindingSourceDAST, "nessus",
		vulnerability.SeverityHigh, "msg")
	if err != nil {
		t.Fatal(err)
	}
	p.setFindingLocationFields(f, goldenNetworkFindings()[0], &ctis.Report{})
	got := f.Network()
	want := vulnerability.NetworkLocation{Port: 8443, Transport: "tcp", Service: "https"}
	if got != want {
		t.Fatalf("network = %+v, want %+v", got, want)
	}
}

// The domain fingerprint (manual findings, recompute after an asset merge)
// must not read the network location either.
func TestGenerateFingerprint_IgnoresNetworkLocation(t *testing.T) {
	tenant, asset := shared.NewID(), shared.NewID()
	mk := func() *vulnerability.Finding {
		f, err := vulnerability.NewFinding(tenant, asset, vulnerability.FindingSourceDAST, "nessus",
			vulnerability.SeverityHigh, "SSL Certificate Cannot Be Trusted")
		if err != nil {
			t.Fatal(err)
		}
		f.SetRuleID("nessus-51192")
		return f
	}
	plain, withNet := mk(), mk()
	withNet.SetNetwork(vulnerability.NetworkLocation{Port: 8443, Transport: "tcp", Service: "https"})
	if a, b := plain.GenerateFingerprint(), withNet.GenerateFingerprint(); a != b {
		t.Fatalf("network location changed the domain fingerprint: %s vs %s", a, b)
	}
}
