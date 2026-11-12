package report

import (
	"strings"
	"testing"
)

// The retest environment is its own field in every rendering: the HTML and
// PDF reports and the template data ({environment} inside {#retests}).
func TestRetestEnvironmentInReports(t *testing.T) {
	in := SampleReportInput()
	in.ReportType = TypeRetest
	if !in.ShowRetests() {
		t.Fatal("sample retest report shows no retests")
	}
	html, err := GenerateHTML(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(html, "<th>Environment</th>") || !strings.Contains(html, "<td>staging</td>") {
		t.Errorf("HTML retest table lacks the environment")
	}
	if _, err := GeneratePDF(in); err != nil {
		t.Fatal(err)
	}
	retests := TemplateData(in, "en")["retests"].([]map[string]any)
	if len(retests) != 1 || retests[0]["environment"] != "staging" || retests[0]["notes"] != "Header removed." {
		t.Fatalf("template retests = %v", retests)
	}
}
