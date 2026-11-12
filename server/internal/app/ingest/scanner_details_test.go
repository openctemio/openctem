package ingest

import (
	"testing"
	"time"

	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

func TestSetFindingScannerDetails(t *testing.T) {
	f, err := vulnerability.NewFinding(shared.NewID(), shared.NewID(), vulnerability.FindingSourceVA, "tenable_sc",
		vulnerability.SeverityCritical, "m")
	if err != nil {
		t.Fatal(err)
	}
	pub := time.Date(2021, 12, 10, 0, 0, 0, 0, time.UTC)
	setFindingScannerDetails(f, &ctis.Finding{Category: "CGI abuses",
		Vulnerability: &ctis.VulnerabilityDetails{IDs: cveIDs("CVE-2021-44228", "CVE-2021-45046"),
			ThreatSignals: []ctis.ThreatSignal{{Type: ctis.ThreatSignalPublicExploit, Source: "tenable"}}},
		Scores: []ctis.Score{
			cvssScore("3.0", "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10, "nvd"),
			{System: ctis.ScoreSystemVendor, Value: ptrF(10), Source: "tenable"}, // VPR
		},
		Remediation: &ctis.Remediation{PatchPublishedAt: &pub}})
	d := f.ScannerDetails()
	if d.Family != "CGI abuses" || !d.ExploitAvailable || d.VPRScore == nil || *d.VPRScore != 10 || d.CVSSVersion != "3.0" ||
		len(d.CVEIDs) != 2 || d.PatchPublishedAt == nil {
		t.Fatalf("details: %+v", d)
	}
	// A vendor score of another source is not the VPR.
	h, _ := vulnerability.NewFinding(shared.NewID(), shared.NewID(), vulnerability.FindingSourceVA, "x", vulnerability.SeverityLow, "m")
	setFindingScannerDetails(h, &ctis.Finding{Scores: []ctis.Score{{System: ctis.ScoreSystemVendor, Value: ptrF(9), Source: "other"}}})
	if d := h.ScannerDetails(); d.VPRScore != nil {
		t.Fatalf("VPR from another source: %+v", d)
	}
	// A CVSS version without a score describes nothing and is not kept.
	g, _ := vulnerability.NewFinding(shared.NewID(), shared.NewID(), vulnerability.FindingSourceVA, "x", vulnerability.SeverityLow, "m")
	setFindingScannerDetails(g, &ctis.Finding{Scores: []ctis.Score{{System: ctis.ScoreSystemCVSS, Version: "3.1"}}})
	if d := g.ScannerDetails(); d.CVSSVersion != "" || d.PatchPublishedAt != nil {
		t.Fatalf("details: %+v", d)
	}
}

func TestScannerEvidenceUpdate(t *testing.T) {
	v2 := "AV:N/AC:L/Au:N/C:P/I:P/A:P"
	v3 := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	hostile := "Server: <img src=x onerror=alert(1)>\x1b[2J\u202e"
	cf := &ctis.Finding{
		Type:          ctis.FindingTypeVulnerability,
		EvidenceItems: []ctis.EvidenceItem{{Kind: ctis.EvidenceKindRawText, Text: hostile}},
		Scores: []ctis.Score{
			cvssScore("2.0", v2, 7.5, "nvd"),
			cvssScore("3.1", v3, 9.8, "nvd"),
		},
	}
	u := scannerEvidenceUpdate("fp1", cf)
	if u.Fingerprint != "fp1" || u.Output != vulnerability.SanitizeScannerOutput(hostile) || u.CVSSv2Vector != v2 || u.CVSSv3Vector != v3 {
		t.Fatalf("update = %+v", u)
	}

	// A secret finding keeps no output: the evidence is the leaked value.
	leak := []ctis.EvidenceItem{{Kind: ctis.EvidenceKindRawText, Text: "AKIA..."}}
	for _, s := range []*ctis.Finding{
		{Type: ctis.FindingTypeSecret, EvidenceItems: leak},
		{Type: ctis.FindingTypeVulnerability, EvidenceItems: leak, Secret: &ctis.SecretDetails{}},
	} {
		if u := scannerEvidenceUpdate("fp", s); u.Output != "" || !u.IsEmpty() {
			t.Errorf("secret finding stored output: %+v", u)
		}
	}

	// A malformed vector from a sensor never reaches the column.
	bad := &ctis.Finding{Scores: []ctis.Score{cvssScore("3.1", "CVSS:3.1/<script>", 5, "x")}}
	if u := scannerEvidenceUpdate("fp", bad); u.CVSSv3Vector != "" {
		t.Errorf("malformed v3 vector kept: %q", u.CVSSv3Vector)
	}
}
