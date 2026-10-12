package report

import (
	"strings"
	"testing"
)

func TestChecklistCoverageInReports(t *testing.T) {
	in := SampleReportInput()
	html, err := GenerateHTML(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Methodology Coverage", "OWASP Web Security Testing Guide (4.2)", "83.3%", "WSTG-INPV-05 Testing for SQL Injection"} {
		if !strings.Contains(html, want) {
			t.Errorf("HTML report lacks %q", want)
		}
	}
	if _, err := GeneratePDF(in); err != nil {
		t.Fatal(err)
	}

	data := TemplateData(in, "vi")
	sum := data["checklist_summary"].(map[string]any)
	if sum["total"] != 12 || sum["tested"] != 10 || sum["coverage"] != 83.3 {
		t.Fatalf("summary = %v", sum)
	}
	failed := data["checklist_failed_items"].([]map[string]any)
	if len(failed) != 2 || failed[1]["severity_label"] != "Nghiêm trọng" {
		t.Fatalf("failed items = %v", failed)
	}
	if data["has_checklists"] != true || len(data["checklist_sections"].([]map[string]any)) != 2 {
		t.Fatalf("checklists = %v", data["checklists"])
	}

	in.Checklists = nil
	html, err = GenerateHTML(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(html, "Methodology Coverage") {
		t.Fatal("coverage section without checklists")
	}
	if d := TemplateData(in, "en"); d["has_checklists"] != false || len(d["checklists"].([]map[string]any)) != 0 {
		t.Fatalf("empty checklists = %v", d["checklists"])
	}
}
