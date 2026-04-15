package semgrep

import (
	"context"
	"testing"

	"github.com/openctemio/api/internal/infra/adapters/core"
	"github.com/openctemio/ctis"
)

var sampleSemgrepJSON = []byte(`{
  "version": "1.50.0",
  "results": [
    {
      "check_id": "python.lang.security.injection.sql-injection",
      "path": "app/models.py",
      "start": {"line": 42, "col": 5, "offset": 1200},
      "end": {"line": 42, "col": 60, "offset": 1255},
      "extra": {
        "message": "SQL injection vulnerability detected. User input is used directly in a SQL query without sanitization.",
        "severity": "ERROR",
        "metadata": {
          "cwe": ["CWE-89"],
          "owasp": ["A03:2021"],
          "confidence": "HIGH",
          "impact": "HIGH",
          "likelihood": "HIGH",
          "category": "security",
          "subcategory": ["vuln"],
          "technology": ["python", "django"],
          "references": [
            "https://owasp.org/Top10/A03_2021-Injection/",
            "https://cwe.mitre.org/data/definitions/89.html"
          ],
          "vulnerability_class": ["SQL Injection"]
        },
        "lines": "query = f\"SELECT * FROM users WHERE id = {user_id}\"",
        "fingerprint": "abc123def456"
      }
    },
    {
      "check_id": "python.lang.security.deserialization.avoid-pickle",
      "path": "app/utils.py",
      "start": {"line": 15, "col": 1},
      "end": {"line": 15, "col": 30},
      "extra": {
        "message": "Avoid using pickle for deserialization. Pickle is known to be insecure.",
        "severity": "WARNING",
        "metadata": {
          "cwe": "CWE-502",
          "confidence": "MEDIUM",
          "category": "security",
          "references": "https://docs.python.org/3/library/pickle.html"
        },
        "lines": "data = pickle.loads(user_data)"
      }
    },
    {
      "check_id": "python.lang.best-practice.logging-format",
      "path": "app/views.py",
      "start": {"line": 100, "col": 1},
      "end": {"line": 100, "col": 50},
      "extra": {
        "message": "Use lazy logging format instead of f-string.",
        "severity": "INFO",
        "metadata": {
          "confidence": "HIGH",
          "category": "best-practice"
        },
        "lines": "logger.info(f\"User {user_id} logged in\")"
      }
    }
  ]
}`)

func TestAdapterName(t *testing.T) {
	a := NewAdapter()
	if a.Name() != "semgrep" {
		t.Errorf("expected name 'semgrep', got %q", a.Name())
	}
}

func TestAdapterInputFormats(t *testing.T) {
	a := NewAdapter()
	formats := a.InputFormats()
	if len(formats) != 2 || formats[0] != "semgrep" || formats[1] != "json" {
		t.Errorf("unexpected input formats: %v", formats)
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

	if !a.CanConvert(sampleSemgrepJSON) {
		t.Error("expected CanConvert to return true for valid Semgrep JSON")
	}

	// Empty results array is still valid Semgrep output
	if !a.CanConvert([]byte(`{"results": []}`)) {
		t.Error("expected CanConvert to return true for empty results")
	}

	if a.CanConvert([]byte(`{"invalid": true}`)) {
		t.Error("expected CanConvert to return false for non-Semgrep JSON")
	}

	if a.CanConvert([]byte(`not json`)) {
		t.Error("expected CanConvert to return false for invalid JSON")
	}
}

func TestConvert(t *testing.T) {
	a := NewAdapter()
	report, err := a.Convert(context.Background(), sampleSemgrepJSON, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if report == nil {
		t.Fatal("expected non-nil report")
	}

	if report.Tool == nil {
		t.Fatal("expected non-nil tool")
	}

	if report.Tool.Name != "semgrep" {
		t.Errorf("expected tool name 'semgrep', got %q", report.Tool.Name)
	}

	if report.Tool.Version != "1.50.0" {
		t.Errorf("expected tool version '1.50.0', got %q", report.Tool.Version)
	}

	if len(report.Findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(report.Findings))
	}
}

func TestConvertSQLInjection(t *testing.T) {
	a := NewAdapter()
	report, err := a.Convert(context.Background(), sampleSemgrepJSON, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	f := report.Findings[0]
	if f.Type != ctis.FindingTypeVulnerability {
		t.Errorf("expected finding type vulnerability, got %q", f.Type)
	}
	if f.Severity != ctis.SeverityHigh {
		t.Errorf("expected severity high (from ERROR), got %q", f.Severity)
	}
	if f.RuleID != "python.lang.security.injection.sql-injection" {
		t.Errorf("unexpected rule ID: %q", f.RuleID)
	}
	if f.RuleName != "Sql Injection" {
		t.Errorf("expected rule name 'Sql Injection', got %q", f.RuleName)
	}
	if f.Confidence != 90 {
		t.Errorf("expected confidence 90 (HIGH), got %d", f.Confidence)
	}
	if f.Location == nil {
		t.Fatal("expected non-nil location")
	}
	if f.Location.Path != "app/models.py" {
		t.Errorf("expected path 'app/models.py', got %q", f.Location.Path)
	}
	if f.Location.StartLine != 42 {
		t.Errorf("expected start line 42, got %d", f.Location.StartLine)
	}
	if f.Location.StartColumn != 5 {
		t.Errorf("expected start column 5, got %d", f.Location.StartColumn)
	}
	if f.Location.Snippet == "" {
		t.Error("expected non-empty snippet")
	}
	if f.Vulnerability == nil {
		t.Fatal("expected non-nil vulnerability details")
	}
	if f.Vulnerability.CWEID != "CWE-89" {
		t.Errorf("expected CWE ID 'CWE-89', got %q", f.Vulnerability.CWEID)
	}
	if len(f.Vulnerability.OWASPIDs) == 0 || f.Vulnerability.OWASPIDs[0] != "A03:2021" {
		t.Errorf("expected OWASP ID 'A03:2021', got %v", f.Vulnerability.OWASPIDs)
	}
	if f.Fingerprint != "abc123def456" {
		t.Errorf("expected fingerprint 'abc123def456', got %q", f.Fingerprint)
	}
	if len(f.References) < 2 {
		t.Errorf("expected at least 2 references, got %d", len(f.References))
	}
	if f.Category != "security" {
		t.Errorf("expected category 'security', got %q", f.Category)
	}
	if f.Impact != "HIGH" {
		t.Errorf("expected impact 'HIGH', got %q", f.Impact)
	}
}

func TestConvertWarning(t *testing.T) {
	a := NewAdapter()
	report, err := a.Convert(context.Background(), sampleSemgrepJSON, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	f := report.Findings[1]
	if f.Severity != ctis.SeverityMedium {
		t.Errorf("expected severity medium (from WARNING), got %q", f.Severity)
	}
	if f.Confidence != 70 {
		t.Errorf("expected confidence 70 (MEDIUM), got %d", f.Confidence)
	}
	// Single string CWE (not array)
	if f.Vulnerability == nil || f.Vulnerability.CWEID != "CWE-502" {
		t.Errorf("expected CWE ID 'CWE-502' from single string")
	}
	// Generated fingerprint (no fingerprint in extra)
	if f.Fingerprint == "" {
		t.Error("expected non-empty generated fingerprint")
	}
}

func TestConvertInfo(t *testing.T) {
	a := NewAdapter()
	report, err := a.Convert(context.Background(), sampleSemgrepJSON, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	f := report.Findings[2]
	if f.Severity != ctis.SeverityLow {
		t.Errorf("expected severity low (from INFO), got %q", f.Severity)
	}
}

func TestConvertWithMinSeverity(t *testing.T) {
	a := NewAdapter()
	opts := &core.AdapterOptions{
		MinSeverity: "high",
	}
	report, err := a.Convert(context.Background(), sampleSemgrepJSON, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Only ERROR (high) should pass
	if len(report.Findings) != 1 {
		t.Errorf("expected 1 finding with min severity high, got %d", len(report.Findings))
	}
}

func TestConvertInvalidJSON(t *testing.T) {
	a := NewAdapter()
	_, err := a.Convert(context.Background(), []byte(`not json`), nil)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestMapSemgrepSeverity(t *testing.T) {
	tests := []struct {
		input    string
		expected ctis.Severity
	}{
		{"ERROR", ctis.SeverityHigh},
		{"WARNING", ctis.SeverityMedium},
		{"INFO", ctis.SeverityLow},
		{"INVENTORY", ctis.SeverityInfo},
		{"EXPERIMENT", ctis.SeverityInfo},
	}

	for _, tt := range tests {
		result := mapSemgrepSeverity(tt.input)
		if result != tt.expected {
			t.Errorf("mapSemgrepSeverity(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestExtractStringList(t *testing.T) {
	// nil
	if extractStringList(nil) != nil {
		t.Error("expected nil for nil input")
	}

	// single string
	result := extractStringList("CWE-89")
	if len(result) != 1 || result[0] != "CWE-89" {
		t.Errorf("unexpected result for string input: %v", result)
	}

	// []interface{}
	result = extractStringList([]interface{}{"CWE-89", "CWE-90"})
	if len(result) != 2 {
		t.Errorf("expected 2 items, got %d", len(result))
	}
}

func TestRuleIDToName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"python.lang.security.injection.sql-injection", "Sql Injection"},
		{"simple-rule", "Simple Rule"},
		{"single", "Single"},
	}

	for _, tt := range tests {
		result := ruleIDToName(tt.input)
		if result != tt.expected {
			t.Errorf("ruleIDToName(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestParseToCTIS(t *testing.T) {
	report, err := ParseToCTIS(sampleSemgrepJSON, &core.ParseOptions{
		AssetValue: "github.com/org/repo",
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
