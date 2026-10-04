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
