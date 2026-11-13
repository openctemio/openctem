package report

import (
	"strings"
	"testing"
	"time"
)

// The report must honor IncludePOC so client-facing exports can omit exploit
// code. Default (true) keeps PoC; false strips it.
func TestGenerateHTML_IncludePOCFlag(t *testing.T) {
	base := ReportInput{
		Campaign:    CampaignData{Name: "C1"},
		GeneratedAt: time.Unix(0, 0).UTC(),
		Findings: []FindingData{{
			Title:    "SQLi",
			Severity: "high",
			POC:      "SECRET_EXPLOIT_PAYLOAD_xyz",
		}},
	}

	withPOC := base
	withPOC.IncludePOC = true
	html, err := GenerateHTML(withPOC)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if !strings.Contains(html, "SECRET_EXPLOIT_PAYLOAD_xyz") {
		t.Fatal("expected PoC present when IncludePOC=true")
	}

	noPOC := base
	noPOC.IncludePOC = false
	html2, err := GenerateHTML(noPOC)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if strings.Contains(html2, "SECRET_EXPLOIT_PAYLOAD_xyz") {
		t.Fatal("PoC must be omitted when IncludePOC=false")
	}
	if strings.Contains(html2, "Proof of Concept") {
		t.Fatal("PoC section header must be omitted when IncludePOC=false")
	}
}
