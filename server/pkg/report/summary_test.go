package report

import (
	"strings"
	"testing"
	"time"
)

func TestGenerateSummaryHTML(t *testing.T) {
	html, err := GenerateSummaryHTML(SummaryInput{
		TenantName:  "Acme",
		GeneratedAt: time.Date(2026, 6, 8, 9, 0, 0, 0, time.UTC),
		Total:       42, Open: 30, Resolved: 12,
		BySeverity: map[string]int64{"critical": 4, "high": 10, "medium": 16, "low": 12},
		WindowDays: 7, NewInWindow: 8, ResolvedInWindow: 3,
	})
	if err != nil {
		t.Fatalf("GenerateSummaryHTML: %v", err)
	}
	for _, want := range []string{"Acme", "2026-06-08", "42", "By severity", "Critical", "Last 7 days", "trend-up"} {
		if !strings.Contains(html, want) {
			t.Errorf("summary HTML missing %q", want)
		}
	}
	// Net = New(8) - Resolved(3) = +5 (backlog grew → up).
	if !strings.Contains(html, "+5") {
		t.Errorf("expected net +5 in output")
	}
}

func TestGenerateSummaryHTML_RendersRiskPosture(t *testing.T) {
	html, err := GenerateSummaryHTML(SummaryInput{
		TenantName:  "Acme",
		GeneratedAt: time.Date(2026, 6, 8, 9, 0, 0, 0, time.UTC),
		Total:       42, Open: 30, Resolved: 12,
		BySeverity:   map[string]int64{"critical": 4},
		KevOpen:      7,
		EpssHighOpen: 11,
		SLABreached:  3,
	})
	if err != nil {
		t.Fatalf("GenerateSummaryHTML: %v", err)
	}
	for _, want := range []string{"Risk posture", "CISA KEV", "High EPSS", "SLA breached", ">7<", ">11<", ">3<"} {
		if !strings.Contains(html, want) {
			t.Errorf("risk posture section missing %q", want)
		}
	}
}

func TestGenerateSummaryHTML_EscapesTenantName(t *testing.T) {
	html, err := GenerateSummaryHTML(SummaryInput{
		TenantName:  `<script>alert(1)</script>`,
		GeneratedAt: time.Now(),
		BySeverity:  map[string]int64{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(html, "<script>alert") {
		t.Fatal("tenant name must be HTML-escaped (XSS)")
	}
}

func TestGenerateSummaryHTML_RequiresGeneratedAt(t *testing.T) {
	if _, err := GenerateSummaryHTML(SummaryInput{TenantName: "x"}); err == nil {
		t.Fatal("expected error when GeneratedAt is zero")
	}
}

func TestGenerateSummaryHTML_NoWindowSectionWhenZero(t *testing.T) {
	html, err := GenerateSummaryHTML(SummaryInput{
		TenantName: "x", GeneratedAt: time.Now(), Total: 1,
		BySeverity: map[string]int64{"high": 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(html, "Last 0 days") || strings.Contains(html, "days</h1>") {
		t.Error("window section must be omitted when WindowDays == 0")
	}
}
