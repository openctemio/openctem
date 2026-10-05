package ingest

import (
	"testing"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

func TestSetFindingScannerDetails(t *testing.T) {
	f, err := vulnerability.NewFinding(shared.NewID(), shared.NewID(), vulnerability.FindingSourceVA, "tenable_sc",
		vulnerability.SeverityCritical, "m")
	if err != nil {
		t.Fatal(err)
	}
	setFindingScannerDetails(f, &ctis.Finding{Category: "CGI abuses",
		Vulnerability: &ctis.VulnerabilityDetails{CVEID: "CVE-2021-44228", CVEIDs: []string{"CVE-2021-44228", "CVE-2021-45046"},
			CVSSVersion: "3.x", CVSSScore: 10, VPRScore: 10, ExploitAvailable: true},
		Properties: ctis.Properties{"tenable_patch_pub_date": "2021-12-10T00:00:00Z"}})
	d := f.ScannerDetails()
	if d.Family != "CGI abuses" || !d.ExploitAvailable || d.VPRScore == nil || *d.VPRScore != 10 || d.CVSSVersion != "3.x" ||
		len(d.CVEIDs) != 2 || d.PatchPublishedAt == nil {
		t.Fatalf("details: %+v", d)
	}
	// A CVSS version without a score describes nothing and is not kept.
	g, _ := vulnerability.NewFinding(shared.NewID(), shared.NewID(), vulnerability.FindingSourceVA, "x", vulnerability.SeverityLow, "m")
	setFindingScannerDetails(g, &ctis.Finding{Vulnerability: &ctis.VulnerabilityDetails{CVSSVersion: "3.1"},
		Properties: ctis.Properties{"patch_publication_date": "not a date"}})
	if d := g.ScannerDetails(); d.CVSSVersion != "" || d.PatchPublishedAt != nil {
		t.Fatalf("details: %+v", d)
	}
}

func TestScannerEvidenceUpdate(t *testing.T) {
	v2 := "AV:N/AC:L/Au:N/C:P/I:P/A:P"
	v3 := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	hostile := "Server: <img src=x onerror=alert(1)>\x1b[2J‮"
	cf := &ctis.Finding{
		Type:          ctis.FindingTypeVulnerability,
		Evidence:      hostile,
		Properties:    ctis.Properties{"cvss_v2_vector": v2},
		Vulnerability: &ctis.VulnerabilityDetails{CVSSVector: v3, CVSSVersion: "3.x"},
	}
	u := scannerEvidenceUpdate("fp1", cf)
	if u.Fingerprint != "fp1" || u.Output != hostile || u.CVSSv2Vector != v2 || u.CVSSv3Vector != v3 {
		t.Fatalf("update = %+v", u)
	}

	// A secret finding keeps no output: the evidence is the leaked value.
	for _, s := range []*ctis.Finding{
		{Type: ctis.FindingTypeSecret, Evidence: "AKIA..."},
		{Type: ctis.FindingTypeVulnerability, Evidence: "AKIA...", Secret: &ctis.SecretDetails{}},
	} {
		if u := scannerEvidenceUpdate("fp", s); u.Output != "" || !u.IsEmpty() {
			t.Errorf("secret finding stored output: %+v", u)
		}
	}

	// A malformed vector from a sensor never reaches the column.
	bad := &ctis.Finding{Properties: ctis.Properties{"cvss_v3_vector": "CVSS:3.1/<script>"}}
	if u := scannerEvidenceUpdate("fp", bad); u.CVSSv3Vector != "" {
		t.Errorf("malformed v3 vector kept: %q", u.CVSSv3Vector)
	}
}
