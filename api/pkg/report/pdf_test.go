package report

import (
	"bytes"
	"testing"
	"time"
)

func sampleReportInput() ReportInput {
	return ReportInput{
		Campaign: CampaignData{
			Name:          "Q2 External Pentest",
			Description:   "Black-box assessment of the public perimeter.",
			ClientName:    "Acme Corp",
			ClientContact: "ciso@acme.example",
			Type:          "penetration_test",
			Priority:      "high",
			Status:        "completed",
			StartDate:     "2026-04-01",
			EndDate:       "2026-04-14",
			Methodology:   "OWASP WSTG",
			Team: []TeamMemberData{
				{Name: "Alice Tester", Email: "alice@sec.example", Role: "lead"},
			},
		},
		Stats: StatsData{
			Total: 3, Critical: 1, High: 1, Low: 1, Progress: 33.3, AvgCVSS: 7.2, MaxCVSS: 9.8,
		},
		Findings: []FindingData{
			{
				Title: "SQL Injection in login", Severity: "critical", Status: "open",
				CVSSScore: 9.8, CVSSVector: "CVSS:3.1/AV:N/AC:L", CWE: "CWE-89",
				Description: "Unsanitised input reaches the query.",
				Steps:       []string{"Open /login", "Submit ' OR 1=1 --"},
				Impact:      "Full DB read.", Remediation: "Use parameterised queries.",
				POC: "' OR 1=1 --", Targets: []string{"app.acme.example"},
				References: []string{"https://owasp.org/sqli"},
			},
			{
				Title: "Verbose error — café résumé €", Severity: "low", Status: "resolved",
				Description: "Stack traces leak. Unicode: café résumé €.",
			},
		},
		GeneratedAt:    time.Date(2026, 4, 15, 12, 0, 0, 0, time.UTC),
		Classification: "confidential",
		Watermark:      "ACME ONLY",
		IncludePOC:     true,
	}
}

func TestGeneratePDF_ProducesValidPDF(t *testing.T) {
	out, err := GeneratePDF(sampleReportInput())
	if err != nil {
		t.Fatalf("GeneratePDF: %v", err)
	}
	if len(out) < 1000 {
		t.Fatalf("pdf too small (%d bytes) — likely empty", len(out))
	}
	if !bytes.HasPrefix(out, []byte("%PDF")) {
		t.Errorf("output does not start with %%PDF magic: %q", out[:8])
	}
	if !bytes.Contains(out, []byte("%%EOF")) {
		t.Error("output missing EOF trailer")
	}
}

func TestGeneratePDF_EmptyFindings(t *testing.T) {
	in := sampleReportInput()
	in.Findings = nil
	out, err := GeneratePDF(in)
	if err != nil {
		t.Fatalf("GeneratePDF with no findings: %v", err)
	}
	if !bytes.HasPrefix(out, []byte("%PDF")) {
		t.Error("expected a valid PDF even with no findings")
	}
}

func TestGeneratePDF_MinimalInput(t *testing.T) {
	// No classification, no campaign name, no watermark — must not panic and
	// must still render (classification defaults to INTERNAL).
	out, err := GeneratePDF(ReportInput{GeneratedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatalf("GeneratePDF minimal: %v", err)
	}
	if !bytes.HasPrefix(out, []byte("%PDF")) {
		t.Error("expected a valid PDF for minimal input")
	}
}

func TestGeneratePDF_ExcludePOC(t *testing.T) {
	// Smoke test the include_poc=false path renders without error.
	in := sampleReportInput()
	in.IncludePOC = false
	if _, err := GeneratePDF(in); err != nil {
		t.Fatalf("GeneratePDF exclude-poc: %v", err)
	}
}
