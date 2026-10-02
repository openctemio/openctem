package sarif

import (
	"context"
	"testing"

	"github.com/openctemio/api/internal/infra/adapters/core"
	"github.com/openctemio/ctis"
)

var sampleSARIFJSON = []byte(`{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "TestScanner",
          "version": "1.0.0",
          "semanticVersion": "1.0.0",
          "organization": "TestOrg",
          "rules": [
            {
              "id": "rule-001",
              "name": "SQL Injection",
              "shortDescription": {"text": "SQL Injection vulnerability detected"},
              "fullDescription": {"text": "User input is used directly in SQL query without sanitization"},
              "helpUri": "https://owasp.org/Top10/A03_2021-Injection/",
              "help": {"text": "Use parameterized queries", "markdown": "Use [parameterized queries](https://owasp.org/sqli)"},
              "defaultConfiguration": {"level": "error"},
              "properties": {
                "tags": ["CWE-89: SQL Injection", "OWASP-A03:2021 - Injection", "security", "high"],
                "precision": "high"
              }
            },
            {
              "id": "rule-002",
              "name": "Hardcoded Secret",
              "shortDescription": {"text": "Hardcoded credential detected"},
              "defaultConfiguration": {"level": "warning"},
              "properties": {"tags": ["CWE-798: Use of Hard-coded Credentials", "security"]}
            },
            {
              "id": "rule-003",
              "name": "Info Disclosure",
              "shortDescription": {"text": "Information disclosure"},
              "defaultConfiguration": {"level": "note"}
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "rule-001",
          "level": "error",
          "message": {"text": "SQL injection in login handler"},
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {"uri": "src/auth/login.go"},
                "region": {"startLine": 42, "endLine": 42, "startColumn": 10, "endColumn": 55, "snippet": {"text": "db.Query(\"SELECT * FROM users WHERE id=\" + userInput)"}}
              }
            }
          ],
          "fingerprints": {"matchBasedId/v1": "abc123def456"},
          "codeFlows": [
            {
              "threadFlows": [
                {
                  "locations": [
                    {"location": {"physicalLocation": {"artifactLocation": {"uri": "src/auth/login.go"}, "region": {"startLine": 38}}}},
                    {"location": {"physicalLocation": {"artifactLocation": {"uri": "src/auth/login.go"}, "region": {"startLine": 40}}}},
                    {"location": {"physicalLocation": {"artifactLocation": {"uri": "src/auth/login.go"}, "region": {"startLine": 42}}}}
                  ]
                }
              ]
            }
          ]
        },
        {
          "ruleId": "rule-002",
          "level": "warning",
          "message": {"text": "Hardcoded API key found"},
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {"uri": "src/config/keys.go"},
                "region": {"startLine": 15, "startColumn": 1}
              }
            }
          ]
        },
        {
          "ruleId": "rule-003",
          "level": "note",
          "message": {"text": "Debug endpoint exposed"},
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {"uri": "src/debug/handler.go"},
                "region": {"startLine": 8}
              }
            }
          ]
        }
      ]
    }
  ]
}`)

func TestAdapterName(t *testing.T) {
	a := NewAdapter()
	if a.Name() != "sarif" {
		t.Errorf("expected name 'sarif', got %q", a.Name())
	}
}

func TestAdapterInputFormats(t *testing.T) {
	a := NewAdapter()
	formats := a.InputFormats()
	if len(formats) != 2 || formats[0] != "sarif" || formats[1] != "json" {
		t.Errorf("unexpected input formats: %v", formats)
	}
}

func TestAdapterOutputFormat(t *testing.T) {
	a := NewAdapter()
	if a.OutputFormat() != "ctis" {
		t.Errorf("expected output format 'ctis', got %q", a.OutputFormat())
	}
}

func TestCanConvert_ValidSARIF(t *testing.T) {
	a := NewAdapter()
	if !a.CanConvert(sampleSARIFJSON) {
		t.Error("expected CanConvert to return true for valid SARIF JSON with schema field")
	}
}

func TestCanConvert_ValidSARIFVersionOnly(t *testing.T) {
	a := NewAdapter()
	input := []byte(`{"version": "2.1.0", "runs": []}`)
	if !a.CanConvert(input) {
		t.Error("expected CanConvert to return true for SARIF JSON with only version field")
	}
}

func TestCanConvert_InvalidJSON(t *testing.T) {
	a := NewAdapter()
	if a.CanConvert([]byte(`not json at all`)) {
		t.Error("expected CanConvert to return false for invalid JSON")
	}
}

func TestCanConvert_NotSARIF(t *testing.T) {
	a := NewAdapter()
	if a.CanConvert([]byte(`{"name": "something", "results": []}`)) {
		t.Error("expected CanConvert to return false for valid JSON without schema or version")
	}
}

func TestConvert_Success(t *testing.T) {
	a := NewAdapter()
	report, err := a.Convert(context.Background(), sampleSARIFJSON, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if report == nil {
		t.Fatal("expected non-nil report")
	}

	if len(report.Findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(report.Findings))
	}
}

func TestConvert_SQLInjectionFinding(t *testing.T) {
	a := NewAdapter()
	report, err := a.Convert(context.Background(), sampleSARIFJSON, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	f := report.Findings[0]

	if f.Title != "SQL Injection vulnerability detected" {
		t.Errorf("expected title 'SQL Injection vulnerability detected', got %q", f.Title)
	}

	if f.Severity != ctis.SeverityHigh {
		t.Errorf("expected severity high (from 'error' level), got %q", f.Severity)
	}

	if f.RuleID != "rule-001" {
		t.Errorf("expected rule ID 'rule-001', got %q", f.RuleID)
	}

	if f.RuleName != "SQL Injection" {
		t.Errorf("expected rule name 'SQL Injection', got %q", f.RuleName)
	}

	if f.Description != "User input is used directly in SQL query without sanitization" {
		t.Errorf("unexpected description: %q", f.Description)
	}

	if f.Message != "SQL injection in login handler" {
		t.Errorf("expected message 'SQL injection in login handler', got %q", f.Message)
	}

	if f.Fingerprint != "abc123def456" {
		t.Errorf("expected fingerprint 'abc123def456', got %q", f.Fingerprint)
	}

	if f.Location == nil {
		t.Fatal("expected non-nil location")
	}

	if f.Location.Path != "src/auth/login.go" {
		t.Errorf("expected path 'src/auth/login.go', got %q", f.Location.Path)
	}

	if f.Location.StartLine != 42 {
		t.Errorf("expected start line 42, got %d", f.Location.StartLine)
	}

	if f.Vulnerability == nil {
		t.Fatal("expected non-nil vulnerability details")
	}

	if len(f.Vulnerability.CWEIDs) == 0 || f.Vulnerability.CWEIDs[0] != "CWE-89" {
		t.Errorf("expected CWE ID 'CWE-89', got %v", f.Vulnerability.CWEIDs)
	}

	if f.Vulnerability.CWEID != "CWE-89" {
		t.Errorf("expected primary CWEID 'CWE-89', got %q", f.Vulnerability.CWEID)
	}

	if len(f.Vulnerability.OWASPIDs) == 0 || f.Vulnerability.OWASPIDs[0] != "A03:2021" {
		t.Errorf("expected OWASP ID 'A03:2021', got %v", f.Vulnerability.OWASPIDs)
	}

	if f.DataFlow == nil {
		t.Fatal("expected non-nil data flow")
	}

	if len(f.DataFlow.Sources) == 0 {
		t.Error("expected at least one data flow source")
	}

	if len(f.DataFlow.Sinks) == 0 {
		t.Error("expected at least one data flow sink")
	}

	if len(f.References) == 0 {
		t.Error("expected at least one reference")
	}

	// HelpURI should be first reference
	foundHelpURI := false
	for _, ref := range f.References {
		if ref == "https://owasp.org/Top10/A03_2021-Injection/" {
			foundHelpURI = true
			break
		}
	}
	if !foundHelpURI {
		t.Errorf("expected helpUri in references, got %v", f.References)
	}
}

func TestConvert_ToolMetadata(t *testing.T) {
	a := NewAdapter()
	report, err := a.Convert(context.Background(), sampleSARIFJSON, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if report.Tool == nil {
		t.Fatal("expected non-nil tool")
	}

	if report.Tool.Name != "TestScanner" {
		t.Errorf("expected tool name 'TestScanner', got %q", report.Tool.Name)
	}

	if report.Tool.Version != "1.0.0" {
		t.Errorf("expected tool version '1.0.0', got %q", report.Tool.Version)
	}

	if report.Tool.Vendor != "TestOrg" {
		t.Errorf("expected tool vendor 'TestOrg', got %q", report.Tool.Vendor)
	}
}

func TestConvert_FindingLocation(t *testing.T) {
	a := NewAdapter()
	report, err := a.Convert(context.Background(), sampleSARIFJSON, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	loc := report.Findings[0].Location
	if loc == nil {
		t.Fatal("expected non-nil location")
	}

	if loc.Path != "src/auth/login.go" {
		t.Errorf("expected path 'src/auth/login.go', got %q", loc.Path)
	}

	if loc.StartLine != 42 {
		t.Errorf("expected start line 42, got %d", loc.StartLine)
	}

	if loc.EndLine != 42 {
		t.Errorf("expected end line 42, got %d", loc.EndLine)
	}

	if loc.StartColumn != 10 {
		t.Errorf("expected start column 10, got %d", loc.StartColumn)
	}

	if loc.EndColumn != 55 {
		t.Errorf("expected end column 55, got %d", loc.EndColumn)
	}

	expectedSnippet := `db.Query("SELECT * FROM users WHERE id=" + userInput)`
	if loc.Snippet != expectedSnippet {
		t.Errorf("expected snippet %q, got %q", expectedSnippet, loc.Snippet)
	}
}

func TestConvert_FindingFingerprint(t *testing.T) {
	a := NewAdapter()
	report, err := a.Convert(context.Background(), sampleSARIFJSON, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// First finding has explicit matchBasedId/v1 fingerprint
	f := report.Findings[0]
	if f.Fingerprint != "abc123def456" {
		t.Errorf("expected fingerprint 'abc123def456' from matchBasedId/v1, got %q", f.Fingerprint)
	}

	// Second finding should have a generated fingerprint (no fingerprints field)
	f2 := report.Findings[1]
	if f2.Fingerprint == "" {
		t.Error("expected non-empty generated fingerprint for finding without explicit fingerprints")
	}
}

func TestConvert_DataFlow(t *testing.T) {
	a := NewAdapter()
	report, err := a.Convert(context.Background(), sampleSARIFJSON, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	df := report.Findings[0].DataFlow
	if df == nil {
		t.Fatal("expected non-nil data flow for SQL injection finding")
	}

	// 3 locations in the thread flow: first is source, middle is intermediate, last is sink
	if len(df.Sources) != 1 {
		t.Errorf("expected 1 source, got %d", len(df.Sources))
	}

	if len(df.Intermediates) != 1 {
		t.Errorf("expected 1 intermediate, got %d", len(df.Intermediates))
	}

	if len(df.Sinks) != 1 {
		t.Errorf("expected 1 sink, got %d", len(df.Sinks))
	}

	if df.Sources[0].Line != 38 {
		t.Errorf("expected source at line 38, got %d", df.Sources[0].Line)
	}

	if df.Sources[0].Path != "src/auth/login.go" {
		t.Errorf("expected source path 'src/auth/login.go', got %q", df.Sources[0].Path)
	}

	if df.Intermediates[0].Line != 40 {
		t.Errorf("expected intermediate at line 40, got %d", df.Intermediates[0].Line)
	}

	if df.Sinks[0].Line != 42 {
		t.Errorf("expected sink at line 42, got %d", df.Sinks[0].Line)
	}
}

func TestConvert_HardcodedSecretFinding(t *testing.T) {
	a := NewAdapter()
	report, err := a.Convert(context.Background(), sampleSARIFJSON, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	f := report.Findings[1]

	if f.Severity != ctis.SeverityMedium {
		t.Errorf("expected severity medium (from 'warning' level), got %q", f.Severity)
	}

	if f.Title != "Hardcoded credential detected" {
		t.Errorf("expected title 'Hardcoded credential detected', got %q", f.Title)
	}

	if f.RuleID != "rule-002" {
		t.Errorf("expected rule ID 'rule-002', got %q", f.RuleID)
	}

	if f.Location == nil {
		t.Fatal("expected non-nil location")
	}

	if f.Location.Path != "src/config/keys.go" {
		t.Errorf("expected path 'src/config/keys.go', got %q", f.Location.Path)
	}

	if f.Location.StartLine != 15 {
		t.Errorf("expected start line 15, got %d", f.Location.StartLine)
	}

	// Should have CWE extracted from tags
	if f.Vulnerability == nil {
		t.Fatal("expected non-nil vulnerability details for hardcoded secret")
	}

	if f.Vulnerability.CWEID != "CWE-798" {
		t.Errorf("expected CWE ID 'CWE-798', got %q", f.Vulnerability.CWEID)
	}

	// Should not have data flow (no codeFlows in result)
	if f.DataFlow != nil {
		t.Error("expected nil data flow for finding without code flows")
	}
}

func TestConvert_InfoFinding(t *testing.T) {
	a := NewAdapter()
	report, err := a.Convert(context.Background(), sampleSARIFJSON, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	f := report.Findings[2]

	if f.Severity != ctis.SeverityLow {
		t.Errorf("expected severity low (from 'note' level), got %q", f.Severity)
	}

	if f.Title != "Information disclosure" {
		t.Errorf("expected title 'Information disclosure', got %q", f.Title)
	}

	if f.RuleID != "rule-003" {
		t.Errorf("expected rule ID 'rule-003', got %q", f.RuleID)
	}

	if f.Location == nil {
		t.Fatal("expected non-nil location")
	}

	if f.Location.Path != "src/debug/handler.go" {
		t.Errorf("expected path 'src/debug/handler.go', got %q", f.Location.Path)
	}

	if f.Location.StartLine != 8 {
		t.Errorf("expected start line 8, got %d", f.Location.StartLine)
	}
}

func TestConvertWithMinSeverity(t *testing.T) {
	a := NewAdapter()
	opts := &core.AdapterOptions{
		MinSeverity: "high",
	}
	report, err := a.Convert(context.Background(), sampleSARIFJSON, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Only the error-level (high) finding should pass
	if len(report.Findings) != 1 {
		t.Errorf("expected 1 finding with min severity high, got %d", len(report.Findings))
	}

	if len(report.Findings) > 0 && report.Findings[0].Severity != ctis.SeverityHigh {
		t.Errorf("expected high severity finding, got %q", report.Findings[0].Severity)
	}
}

func TestConvertWithMinSeverityMedium(t *testing.T) {
	a := NewAdapter()
	opts := &core.AdapterOptions{
		MinSeverity: "medium",
	}
	report, err := a.Convert(context.Background(), sampleSARIFJSON, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// error (high) + warning (medium) should pass, note (low) should not
	if len(report.Findings) != 2 {
		t.Errorf("expected 2 findings with min severity medium, got %d", len(report.Findings))
	}
}

func TestConvert_InvalidJSON(t *testing.T) {
	a := NewAdapter()
	_, err := a.Convert(context.Background(), []byte(`not json`), nil)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestConvert_EmptyRuns(t *testing.T) {
	a := NewAdapter()
	input := []byte(`{"version": "2.1.0", "runs": []}`)
	report, err := a.Convert(context.Background(), input, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if report == nil {
		t.Fatal("expected non-nil report")
	}

	if len(report.Findings) != 0 {
		t.Errorf("expected 0 findings for empty runs, got %d", len(report.Findings))
	}
}

func TestMapSARIFSeverity(t *testing.T) {
	tests := []struct {
		input    string
		expected ctis.Severity
	}{
		{"error", ctis.SeverityHigh},
		{"warning", ctis.SeverityMedium},
		{"note", ctis.SeverityLow},
		{"none", ctis.SeverityInfo},
		{"unknown", ctis.SeverityMedium},
		{"ERROR", ctis.SeverityHigh},
		{"Warning", ctis.SeverityMedium},
	}

	for _, tt := range tests {
		result := mapSARIFSeverity(tt.input)
		if result != tt.expected {
			t.Errorf("mapSARIFSeverity(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestSlugToTitle(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"dockerfile.security.missing-user", "Missing User"},
		{"dockerfile.security.missing-user.missing-user", "Missing User"},
		{"simple-rule", "Simple Rule"},
		{"single", "Single"},
		{"a.b.c", "C"},
		{"multi-word-slug", "Multi Word Slug"},
	}

	for _, tt := range tests {
		result := slugToTitle(tt.input)
		if result != tt.expected {
			t.Errorf("slugToTitle(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestExtractFromTags(t *testing.T) {
	a := NewAdapter()

	// Test CWE extraction
	tags := []string{"CWE-89: SQL Injection", "OWASP-A03:2021 - Injection", "security", "high"}
	cwes, owasps, confidence := a.extractFromTags(tags)

	if len(cwes) != 1 || cwes[0] != "CWE-89" {
		t.Errorf("expected CWE-89, got %v", cwes)
	}

	if len(owasps) != 1 || owasps[0] != "A03:2021" {
		t.Errorf("expected OWASP A03:2021, got %v", owasps)
	}

	// Default confidence (no confidence tag present)
	if confidence != 70 {
		t.Errorf("expected default confidence 70, got %d", confidence)
	}

	// Test with HIGH CONFIDENCE tag
	tags2 := []string{"CWE-79", "HIGH CONFIDENCE"}
	_, _, confidence2 := a.extractFromTags(tags2)
	if confidence2 != 90 {
		t.Errorf("expected confidence 90 for HIGH CONFIDENCE, got %d", confidence2)
	}

	// Test with LOW CONFIDENCE tag
	tags3 := []string{"LOW CONFIDENCE"}
	_, _, confidence3 := a.extractFromTags(tags3)
	if confidence3 != 50 {
		t.Errorf("expected confidence 50 for LOW CONFIDENCE, got %d", confidence3)
	}

	// Test with MEDIUM CONFIDENCE tag
	tags4 := []string{"MEDIUM CONFIDENCE"}
	_, _, confidence4 := a.extractFromTags(tags4)
	if confidence4 != 70 {
		t.Errorf("expected confidence 70 for MEDIUM CONFIDENCE, got %d", confidence4)
	}

	// Test empty tags
	cwes5, owasps5, confidence5 := a.extractFromTags(nil)
	if len(cwes5) != 0 || len(owasps5) != 0 {
		t.Errorf("expected empty results for nil tags, got cwes=%v, owasps=%v", cwes5, owasps5)
	}
	if confidence5 != 70 {
		t.Errorf("expected default confidence 70 for nil tags, got %d", confidence5)
	}

	// Test multiple CWEs
	tags6 := []string{"CWE-89: SQL Injection", "CWE-79: Cross-site Scripting"}
	cwes6, _, _ := a.extractFromTags(tags6)
	if len(cwes6) != 2 {
		t.Errorf("expected 2 CWEs, got %d: %v", len(cwes6), cwes6)
	}

	// Test CWE without colon or space separator
	tags7 := []string{"CWE-120"}
	cwes7, _, _ := a.extractFromTags(tags7)
	if len(cwes7) != 1 || cwes7[0] != "CWE-120" {
		t.Errorf("expected CWE-120, got %v", cwes7)
	}
}

func TestExtractURLsFromMarkdown(t *testing.T) {
	// Test markdown link extraction
	md := "Use [parameterized queries](https://owasp.org/sqli) for safety"
	urls := extractURLsFromMarkdown(md)
	if len(urls) != 1 {
		t.Fatalf("expected 1 URL, got %d: %v", len(urls), urls)
	}
	if urls[0] != "https://owasp.org/sqli" {
		t.Errorf("expected 'https://owasp.org/sqli', got %q", urls[0])
	}

	// Test raw URL extraction
	md2 := "See https://example.com/docs for details"
	urls2 := extractURLsFromMarkdown(md2)
	if len(urls2) != 1 {
		t.Fatalf("expected 1 URL, got %d: %v", len(urls2), urls2)
	}
	if urls2[0] != "https://example.com/docs" {
		t.Errorf("expected 'https://example.com/docs', got %q", urls2[0])
	}

	// Test deduplication: markdown link URL should not appear twice
	md3 := "Visit [link](https://example.com) at https://example.com"
	urls3 := extractURLsFromMarkdown(md3)
	if len(urls3) != 1 {
		t.Errorf("expected 1 unique URL (dedup), got %d: %v", len(urls3), urls3)
	}

	// Test empty markdown
	urls4 := extractURLsFromMarkdown("")
	if len(urls4) != 0 {
		t.Errorf("expected 0 URLs for empty markdown, got %d", len(urls4))
	}

	// Test multiple markdown links
	md5 := "See [a](https://a.com) and [b](https://b.com)"
	urls5 := extractURLsFromMarkdown(md5)
	if len(urls5) != 2 {
		t.Errorf("expected 2 URLs, got %d: %v", len(urls5), urls5)
	}

	// Test non-http link in markdown (should be excluded)
	md6 := "See [local](file:///tmp/foo) link"
	urls6 := extractURLsFromMarkdown(md6)
	if len(urls6) != 0 {
		t.Errorf("expected 0 URLs for non-http link, got %d: %v", len(urls6), urls6)
	}
}

func TestParseToCTIS(t *testing.T) {
	report, err := ParseToCTIS(sampleSARIFJSON, &core.ParseOptions{
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

func TestParseToCTIS_NilOptions(t *testing.T) {
	report, err := ParseToCTIS(sampleSARIFJSON, nil)
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

func TestParseToCTIS_WithBranchInfo(t *testing.T) {
	report, err := ParseToCTIS(sampleSARIFJSON, &core.ParseOptions{
		BranchInfo: &ctis.BranchInfo{
			RepositoryURL: "https://github.com/org/repo",
			Name:          "main",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report == nil {
		t.Fatal("expected non-nil report")
	}
	if report.Metadata.Scope == nil || report.Metadata.Scope.Name != "https://github.com/org/repo" {
		t.Errorf("expected scope name from BranchInfo.RepositoryURL, got %v", report.Metadata.Scope)
	}
}

func TestParseJSONBytes(t *testing.T) {
	sarif, err := ParseJSONBytes(sampleSARIFJSON)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if sarif == nil {
		t.Fatal("expected non-nil SARIF report")
	}

	if sarif.Version != "2.1.0" {
		t.Errorf("expected version '2.1.0', got %q", sarif.Version)
	}

	if len(sarif.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(sarif.Runs))
	}

	if sarif.Runs[0].Tool.Driver.Name != "TestScanner" {
		t.Errorf("expected driver name 'TestScanner', got %q", sarif.Runs[0].Tool.Driver.Name)
	}

	if len(sarif.Runs[0].Results) != 3 {
		t.Errorf("expected 3 results, got %d", len(sarif.Runs[0].Results))
	}

	if len(sarif.Runs[0].Tool.Driver.Rules) != 3 {
		t.Errorf("expected 3 rules, got %d", len(sarif.Runs[0].Tool.Driver.Rules))
	}
}

func TestParseJSONBytes_InvalidJSON(t *testing.T) {
	_, err := ParseJSONBytes([]byte(`not valid json`))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestConvert_SourceTypeMetadata(t *testing.T) {
	a := NewAdapter()
	report, err := a.Convert(context.Background(), sampleSARIFJSON, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if report.Metadata.SourceType != "scanner" {
		t.Errorf("expected source type 'scanner', got %q", report.Metadata.SourceType)
	}
}

func TestConvert_WithRepository(t *testing.T) {
	a := NewAdapter()
	opts := &core.AdapterOptions{
		Repository: "github.com/org/repo",
	}
	report, err := a.Convert(context.Background(), sampleSARIFJSON, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if report.Metadata.Scope == nil {
		t.Fatal("expected non-nil scope when repository is set")
	}

	if report.Metadata.Scope.Name != "github.com/org/repo" {
		t.Errorf("expected scope name 'github.com/org/repo', got %q", report.Metadata.Scope.Name)
	}
}

func TestConvert_SemanticVersionFallback(t *testing.T) {
	// Test that semanticVersion is used when version is empty
	input := []byte(`{
		"version": "2.1.0",
		"runs": [{
			"tool": {
				"driver": {
					"name": "FallbackTool",
					"semanticVersion": "2.5.0"
				}
			},
			"results": []
		}]
	}`)

	a := NewAdapter()
	report, err := a.Convert(context.Background(), input, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if report.Tool == nil {
		t.Fatal("expected non-nil tool")
	}

	if report.Tool.Version != "2.5.0" {
		t.Errorf("expected version '2.5.0' from semanticVersion, got %q", report.Tool.Version)
	}
}

func TestConvert_TagsFiltering(t *testing.T) {
	a := NewAdapter()
	report, err := a.Convert(context.Background(), sampleSARIFJSON, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	f := report.Findings[0]

	// CWE and OWASP tags should be filtered out, leaving "security" and "high"
	for _, tag := range f.Tags {
		tagLower := tag
		if tagLower == "CWE-89: SQL Injection" || tagLower == "OWASP-A03:2021 - Injection" {
			t.Errorf("CWE/OWASP tag %q should have been filtered from tags", tag)
		}
	}

	foundSecurity := false
	for _, tag := range f.Tags {
		if tag == "security" {
			foundSecurity = true
			break
		}
	}
	if !foundSecurity {
		t.Errorf("expected 'security' tag to remain, got tags: %v", f.Tags)
	}
}

func TestConvert_FindingType(t *testing.T) {
	a := NewAdapter()
	report, err := a.Convert(context.Background(), sampleSARIFJSON, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for i, f := range report.Findings {
		if f.Type != ctis.FindingTypeVulnerability {
			t.Errorf("finding[%d]: expected type vulnerability, got %q", i, f.Type)
		}
	}
}

func TestConvert_FindingIDs(t *testing.T) {
	a := NewAdapter()
	report, err := a.Convert(context.Background(), sampleSARIFJSON, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedIDs := []string{"run0-finding1", "run0-finding2", "run0-finding3"}
	for i, f := range report.Findings {
		if f.ID != expectedIDs[i] {
			t.Errorf("finding[%d]: expected ID %q, got %q", i, expectedIDs[i], f.ID)
		}
	}
}

func TestMeetsMinSeverity(t *testing.T) {
	tests := []struct {
		severity ctis.Severity
		min      ctis.Severity
		expected bool
	}{
		{ctis.SeverityCritical, ctis.SeverityHigh, true},
		{ctis.SeverityHigh, ctis.SeverityHigh, true},
		{ctis.SeverityMedium, ctis.SeverityHigh, false},
		{ctis.SeverityLow, ctis.SeverityMedium, false},
		{ctis.SeverityInfo, ctis.SeverityLow, false},
		{ctis.SeverityHigh, ctis.SeverityLow, true},
		{ctis.SeverityMedium, ctis.SeverityInfo, true},
	}

	for _, tt := range tests {
		result := meetsMinSeverity(tt.severity, tt.min)
		if result != tt.expected {
			t.Errorf("meetsMinSeverity(%q, %q) = %v, want %v", tt.severity, tt.min, result, tt.expected)
		}
	}
}

func TestConvert_NoResultLocations(t *testing.T) {
	input := []byte(`{
		"version": "2.1.0",
		"runs": [{
			"tool": {"driver": {"name": "Test", "rules": []}},
			"results": [{
				"ruleId": "test-rule",
				"level": "warning",
				"message": {"text": "A finding with no location"}
			}]
		}]
	}`)

	a := NewAdapter()
	report, err := a.Convert(context.Background(), input, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(report.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(report.Findings))
	}

	f := report.Findings[0]
	if f.Location != nil {
		t.Error("expected nil location for finding without locations")
	}

	// Title should fall back to message text
	if f.Title != "A finding with no location" {
		t.Errorf("expected title from message fallback, got %q", f.Title)
	}

	// Fingerprint should still be generated
	if f.Fingerprint == "" {
		t.Error("expected non-empty generated fingerprint even without locations")
	}
}

func TestConvert_MultipleRuns(t *testing.T) {
	input := []byte(`{
		"version": "2.1.0",
		"runs": [
			{
				"tool": {"driver": {"name": "Scanner1", "version": "1.0", "rules": []}},
				"results": [
					{"ruleId": "r1", "level": "error", "message": {"text": "Finding 1"}}
				]
			},
			{
				"tool": {"driver": {"name": "Scanner2", "version": "2.0", "rules": []}},
				"results": [
					{"ruleId": "r2", "level": "warning", "message": {"text": "Finding 2"}},
					{"ruleId": "r3", "level": "note", "message": {"text": "Finding 3"}}
				]
			}
		]
	}`)

	a := NewAdapter()
	report, err := a.Convert(context.Background(), input, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Tool should come from first run
	if report.Tool == nil || report.Tool.Name != "Scanner1" {
		t.Errorf("expected tool name 'Scanner1' from first run, got %v", report.Tool)
	}

	// All findings from both runs
	if len(report.Findings) != 3 {
		t.Errorf("expected 3 findings across 2 runs, got %d", len(report.Findings))
	}

	// IDs should reflect run index
	if report.Findings[0].ID != "run0-finding1" {
		t.Errorf("expected ID 'run0-finding1', got %q", report.Findings[0].ID)
	}
	if report.Findings[1].ID != "run1-finding1" {
		t.Errorf("expected ID 'run1-finding1', got %q", report.Findings[1].ID)
	}
	if report.Findings[2].ID != "run1-finding2" {
		t.Errorf("expected ID 'run1-finding2', got %q", report.Findings[2].ID)
	}
}

func TestConvert_Confidence(t *testing.T) {
	a := NewAdapter()
	report, err := a.Convert(context.Background(), sampleSARIFJSON, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// SQL injection finding has tags without explicit confidence, so default 70
	f := report.Findings[0]
	if f.Confidence != 70 {
		t.Errorf("expected default confidence 70, got %d", f.Confidence)
	}
}

func TestConvert_ReferencesFromHelp(t *testing.T) {
	a := NewAdapter()
	report, err := a.Convert(context.Background(), sampleSARIFJSON, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	f := report.Findings[0]

	// Should have helpUri + URL from help markdown
	foundHelpURI := false
	foundMarkdownURL := false
	for _, ref := range f.References {
		if ref == "https://owasp.org/Top10/A03_2021-Injection/" {
			foundHelpURI = true
		}
		if ref == "https://owasp.org/sqli" {
			foundMarkdownURL = true
		}
	}

	if !foundHelpURI {
		t.Errorf("expected helpUri reference, got %v", f.References)
	}

	if !foundMarkdownURL {
		t.Errorf("expected markdown URL reference, got %v", f.References)
	}
}
