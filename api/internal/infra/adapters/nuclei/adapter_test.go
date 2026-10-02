package nuclei

import (
	"context"
	"testing"

	"github.com/openctemio/api/internal/infra/adapters/core"
	"github.com/openctemio/ctis"
)

// JSONL format: one JSON object per line
var sampleNucleiJSONL = []byte(`{"template-id":"cve-2023-1234","info":{"name":"Apache RCE","severity":"critical","description":"Remote code execution in Apache HTTP Server.","tags":["cve","apache","rce"],"reference":["https://nvd.nist.gov/vuln/detail/CVE-2023-1234","https://httpd.apache.org/security/"],"classification":{"cve-id":["CVE-2023-1234"],"cwe-id":["CWE-78"],"cvss-metrics":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","cvss-score":9.8},"remediation":"Upgrade Apache to version 2.4.58 or later."},"type":"http","host":"https://example.com","matched-at":"https://example.com/cgi-bin/test","curl-command":"curl -X GET https://example.com/cgi-bin/test","matcher-name":"body","matcher-status":true,"template-url":"https://github.com/projectdiscovery/nuclei-templates/blob/main/cves/2023/CVE-2023-1234.yaml"}
{"template-id":"tech-detect","info":{"name":"Apache HTTP Server Detection","severity":"info","description":"Apache HTTP Server was detected.","tags":["tech","apache"]},"type":"http","host":"https://example.com","matched-at":"https://example.com/","matcher-status":true}
{"template-id":"ssl-expired","info":{"name":"Expired SSL Certificate","severity":"high","description":"The SSL certificate has expired.","tags":["ssl","tls","expired"],"reference":"https://ssl-config.mozilla.org/"},"type":"ssl","host":"https://expired.example.com","matched-at":"https://expired.example.com:443","matcher-status":true}`)

func TestAdapterName(t *testing.T) {
	a := NewAdapter()
	if a.Name() != "nuclei" {
		t.Errorf("expected name 'nuclei', got %q", a.Name())
	}
}

func TestAdapterInputFormats(t *testing.T) {
	a := NewAdapter()
	formats := a.InputFormats()
	if len(formats) != 3 {
		t.Errorf("expected 3 input formats, got %d", len(formats))
	}
}

func TestAdapterOutputFormat(t *testing.T) {
	a := NewAdapter()
	if a.OutputFormat() != "ctis" {
		t.Errorf("expected output format 'ctis', got %q", a.OutputFormat())
	}
}

func TestCanConvert(t *testing.T) {
	a := NewAdapter()

	if !a.CanConvert(sampleNucleiJSONL) {
		t.Error("expected CanConvert to return true for valid Nuclei JSONL")
	}

	if a.CanConvert([]byte(`{"invalid": true}`)) {
		t.Error("expected CanConvert to return false for non-Nuclei JSON")
	}

	if a.CanConvert([]byte(`not json`)) {
		t.Error("expected CanConvert to return false for invalid input")
	}
}

func TestConvert(t *testing.T) {
	a := NewAdapter()
	report, err := a.Convert(context.Background(), sampleNucleiJSONL, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if report == nil {
		t.Fatal("expected non-nil report")
	}

	if report.Tool == nil {
		t.Fatal("expected non-nil tool")
	}

	if report.Tool.Name != "nuclei" {
		t.Errorf("expected tool name 'nuclei', got %q", report.Tool.Name)
	}

	if len(report.Findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(report.Findings))
	}
}

func TestConvertCriticalFinding(t *testing.T) {
	a := NewAdapter()
	report, err := a.Convert(context.Background(), sampleNucleiJSONL, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	f := report.Findings[0]
	if f.Type != ctis.FindingTypeVulnerability {
		t.Errorf("expected finding type vulnerability, got %q", f.Type)
	}
	if f.Severity != ctis.SeverityCritical {
		t.Errorf("expected severity critical, got %q", f.Severity)
	}
	if f.Title != "Apache RCE" {
		t.Errorf("expected title 'Apache RCE', got %q", f.Title)
	}
	if f.RuleID != "cve-2023-1234" {
		t.Errorf("expected rule ID 'cve-2023-1234', got %q", f.RuleID)
	}
	if f.Vulnerability == nil {
		t.Fatal("expected non-nil vulnerability details")
	}
	if f.Vulnerability.CVEID != "CVE-2023-1234" {
		t.Errorf("expected CVE ID 'CVE-2023-1234', got %q", f.Vulnerability.CVEID)
	}
	if f.Vulnerability.CVSSScore != 9.8 {
		t.Errorf("expected CVSS score 9.8, got %f", f.Vulnerability.CVSSScore)
	}
	if f.Location == nil {
		t.Fatal("expected non-nil location")
	}
	if f.Location.Path != "https://example.com/cgi-bin/test" {
		t.Errorf("expected matched-at path, got %q", f.Location.Path)
	}
	if f.Fingerprint == "" {
		t.Error("expected non-empty fingerprint")
	}
	if len(f.References) < 2 {
		t.Errorf("expected at least 2 references, got %d", len(f.References))
	}
	if f.Remediation == nil {
		t.Fatal("expected non-nil remediation")
	}
	if f.Confidence != 90 {
		t.Errorf("expected confidence 90 (matcher-status true), got %d", f.Confidence)
	}
}

func TestConvertInfoFinding(t *testing.T) {
	a := NewAdapter()
	report, err := a.Convert(context.Background(), sampleNucleiJSONL, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	f := report.Findings[1]
	if f.Severity != ctis.SeverityInfo {
		t.Errorf("expected severity info, got %q", f.Severity)
	}
	if f.Title != "Apache HTTP Server Detection" {
		t.Errorf("expected title 'Apache HTTP Server Detection', got %q", f.Title)
	}
}

func TestConvertHighFinding(t *testing.T) {
	a := NewAdapter()
	report, err := a.Convert(context.Background(), sampleNucleiJSONL, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	f := report.Findings[2]
	if f.Severity != ctis.SeverityHigh {
		t.Errorf("expected severity high, got %q", f.Severity)
	}
	// Single string reference
	if len(f.References) < 1 {
		t.Error("expected at least 1 reference from single string")
	}
}

func TestConvertWithMinSeverity(t *testing.T) {
	a := NewAdapter()
	opts := &core.AdapterOptions{
		MinSeverity: "high",
	}
	report, err := a.Convert(context.Background(), sampleNucleiJSONL, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Only critical + high = 2 findings
	if len(report.Findings) != 2 {
		t.Errorf("expected 2 findings with min severity high, got %d", len(report.Findings))
	}
}

func TestConvertJSONArray(t *testing.T) {
	// Nuclei can also output as JSON array
	arrayJSON := []byte(`[
		{"template-id":"test-template","info":{"name":"Test","severity":"medium"},"type":"http","host":"https://test.com","matched-at":"https://test.com/path","matcher-status":true}
	]`)

	a := NewAdapter()
	report, err := a.Convert(context.Background(), arrayJSON, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(report.Findings) != 1 {
		t.Errorf("expected 1 finding from JSON array, got %d", len(report.Findings))
	}
}

func TestConvertInvalidInput(t *testing.T) {
	a := NewAdapter()
	_, err := a.Convert(context.Background(), []byte(`not json`), nil)
	if err == nil {
		t.Error("expected error for invalid input")
	}
}

func TestConvertEmptyInput(t *testing.T) {
	a := NewAdapter()
	_, err := a.Convert(context.Background(), []byte(``), nil)
	if err == nil {
		t.Error("expected error for empty input")
	}
}

func TestMapNucleiSeverity(t *testing.T) {
	tests := []struct {
		input    string
		expected ctis.Severity
	}{
		{"critical", ctis.SeverityCritical},
		{"high", ctis.SeverityHigh},
		{"medium", ctis.SeverityMedium},
		{"low", ctis.SeverityLow},
		{"info", ctis.SeverityInfo},
		{"unknown", ctis.SeverityInfo},
	}

	for _, tt := range tests {
		result := mapNucleiSeverity(tt.input)
		if result != tt.expected {
			t.Errorf("mapNucleiSeverity(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestParseToCTIS(t *testing.T) {
	report, err := ParseToCTIS(sampleNucleiJSONL, &core.ParseOptions{
		AssetValue: "https://example.com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report == nil {
		t.Fatal("expected non-nil report")
	}
	if len(report.Findings) != 3 {
		t.Errorf("expected 3 findings, got %d", len(report.Findings))
	}
}
