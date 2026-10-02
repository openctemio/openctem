package handler

import (
	"bytes"
	"strings"
	"testing"

	"github.com/openctemio/api/internal/app"
)

func TestRenderExecutiveSummaryHTML_ContainsHeadlineMetrics(t *testing.T) {
	epss := 0.87
	summary := &app.ExecutiveSummary{
		Period:            "last 30 days",
		RiskScoreCurrent:  72.4,
		RiskScoreChange:   -3.1,
		FindingsTotal:     142,
		FindingsResolved:  35,
		FindingsNew:       18,
		P0Open:            4,
		P0Resolved:        7,
		P1Open:            22,
		P1Resolved:        14,
		SLACompliancePct:  91.3,
		SLABreached:       3,
		MTTRCriticalHrs:   14.2,
		MTTRHighHrs:       42.6,
		CrownJewelsAtRisk: 2,
		RegressionCount:   1,
		RegressionRatePct: 0.7,
		TopRisks: []app.TopRisk{
			{
				FindingTitle:  "Log4Shell reachable over the internet",
				Severity:      "CRITICAL",
				PriorityClass: "P0",
				AssetName:     "api-gateway",
				EPSSScore:     &epss,
				IsInKEV:       true,
			},
		},
	}

	var buf bytes.Buffer
	if err := renderExecutiveSummaryHTML(&buf, summary, "2026-04-20"); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()

	// Headline metric values must appear verbatim.
	mustContain := []string{
		"last 30 days",
		"2026-04-20",
		"72.4",
		"-3.1",
		"142",
		"91.3%",
		"Log4Shell reachable over the internet",
		"P0",
		"api-gateway",
		"0.87",  // EPSS
		"YES",   // KEV badge
	}
	for _, want := range mustContain {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q", want)
		}
	}

	// Print-styling assertion — the @media print block must ship so
	// save-as-PDF produces a clean layout.
	if !strings.Contains(out, "@media print") {
		t.Error("output missing @media print CSS — PDF rendering will include navigation chrome")
	}
}

func TestRenderExecutiveSummaryHTML_NoTopRisksOmitsTable(t *testing.T) {
	summary := &app.ExecutiveSummary{
		Period:   "last 7 days",
		TopRisks: nil,
	}
	var buf bytes.Buffer
	if err := renderExecutiveSummaryHTML(&buf, summary, "2026-04-20"); err != nil {
		t.Fatalf("%v", err)
	}
	out := buf.String()
	if strings.Contains(out, "<h2>Top Risks</h2>") {
		t.Error("Top Risks section should be omitted when list is empty")
	}
}

func TestRenderExecutiveSummaryHTML_EscapesHTMLInRiskTitle(t *testing.T) {
	// html/template auto-escapes but assert explicitly — a misused
	// template.HTML cast would silently re-introduce XSS.
	summary := &app.ExecutiveSummary{
		Period: "last 30 days",
		TopRisks: []app.TopRisk{
			{
				FindingTitle:  `<script>alert("pwn")</script>`,
				Severity:      "HIGH",
				PriorityClass: "P1",
				AssetName:     "web-01",
			},
		},
	}
	var buf bytes.Buffer
	if err := renderExecutiveSummaryHTML(&buf, summary, "2026-04-20"); err != nil {
		t.Fatalf("%v", err)
	}
	out := buf.String()
	if strings.Contains(out, "<script>alert") {
		t.Fatal("finding title rendered unescaped — XSS risk")
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Fatalf("expected HTML-encoded script tag, got: %s", out)
	}
}
