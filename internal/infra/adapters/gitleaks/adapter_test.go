package gitleaks

import (
	"context"
	"testing"

	"github.com/openctemio/api/internal/infra/adapters/core"
	"github.com/openctemio/ctis"
)

var sampleGitleaksJSON = []byte(`[
  {
    "Description": "AWS Access Key",
    "StartLine": 10,
    "EndLine": 10,
    "StartColumn": 1,
    "EndColumn": 20,
    "Match": "AKIAIOSFODNN7EXAMPLE",
    "Secret": "AKIAIOSFODNN7EXAMPLE",
    "File": "config.yml",
    "Commit": "abc123def456",
    "Author": "dev@example.com",
    "Email": "dev@example.com",
    "Date": "2023-01-15T10:30:00Z",
    "Message": "add config",
    "RuleID": "aws-access-key-id",
    "Fingerprint": "config.yml:aws-access-key-id:10",
    "Entropy": 3.6
  },
  {
    "Description": "Generic API Key",
    "StartLine": 25,
    "EndLine": 25,
    "StartColumn": 10,
    "EndColumn": 50,
    "Match": "api_key = \"sk_live_abcdef1234567890\"",
    "Secret": "sk_live_abcdef1234567890",
    "File": "src/config.py",
    "Commit": "def789abc012",
    "Author": "admin@example.com",
    "Email": "admin@example.com",
    "RuleID": "generic-api-key",
    "Fingerprint": "src/config.py:generic-api-key:25",
    "Entropy": 4.2
  },
  {
    "Description": "GitHub Personal Access Token",
    "StartLine": 5,
    "EndLine": 5,
    "StartColumn": 1,
    "EndColumn": 40,
    "Match": "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "Secret": "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "File": ".env",
    "Commit": "111222333444",
    "Author": "dev2@example.com",
    "Email": "dev2@example.com",
    "RuleID": "github-pat",
    "Fingerprint": ".env:github-pat:5",
    "Tags": ["github", "pat"]
  },
  {
    "Description": "Stripe Secret Key",
    "StartLine": 3,
    "EndLine": 3,
    "StartColumn": 1,
    "EndColumn": 30,
    "Secret": "sk_test_abc123",
    "File": "payment.js",
    "Commit": "aaa111bbb222",
    "RuleID": "stripe-api-key",
    "Fingerprint": "payment.js:stripe-api-key:3"
  }
]`)

func TestAdapterName(t *testing.T) {
	a := NewAdapter()
	if a.Name() != "gitleaks" {
		t.Errorf("expected name 'gitleaks', got %q", a.Name())
	}
}

func TestAdapterInputFormats(t *testing.T) {
	a := NewAdapter()
	formats := a.InputFormats()
	if len(formats) != 2 || formats[0] != "gitleaks" || formats[1] != "json" {
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

	if !a.CanConvert(sampleGitleaksJSON) {
		t.Error("expected CanConvert to return true for valid Gitleaks JSON")
	}

	if a.CanConvert([]byte(`[]`)) {
		t.Error("expected CanConvert to return false for empty array")
	}

	if a.CanConvert([]byte(`{"invalid": true}`)) {
		t.Error("expected CanConvert to return false for non-array JSON")
	}

	if a.CanConvert([]byte(`not json`)) {
		t.Error("expected CanConvert to return false for invalid JSON")
	}
}

func TestConvert(t *testing.T) {
	a := NewAdapter()
	report, err := a.Convert(context.Background(), sampleGitleaksJSON, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if report == nil {
		t.Fatal("expected non-nil report")
	}

	if report.Tool == nil {
		t.Fatal("expected non-nil tool")
	}

	if report.Tool.Name != "gitleaks" {
		t.Errorf("expected tool name 'gitleaks', got %q", report.Tool.Name)
	}

	if len(report.Findings) != 4 {
		t.Fatalf("expected 4 findings, got %d", len(report.Findings))
	}
}

func TestConvertAWSKey(t *testing.T) {
	a := NewAdapter()
	report, err := a.Convert(context.Background(), sampleGitleaksJSON, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	f := report.Findings[0]
	if f.Type != ctis.FindingTypeSecret {
		t.Errorf("expected finding type secret, got %q", f.Type)
	}
	if f.Severity != ctis.SeverityCritical {
		t.Errorf("expected severity critical for AWS key, got %q", f.Severity)
	}
	if f.Title != "AWS Access Key" {
		t.Errorf("expected title 'AWS Access Key', got %q", f.Title)
	}
	if f.RuleID != "aws-access-key-id" {
		t.Errorf("expected rule ID 'aws-access-key-id', got %q", f.RuleID)
	}
	if f.Location == nil {
		t.Fatal("expected non-nil location")
	}
	if f.Location.Path != "config.yml" {
		t.Errorf("expected path 'config.yml', got %q", f.Location.Path)
	}
	if f.Location.StartLine != 10 {
		t.Errorf("expected start line 10, got %d", f.Location.StartLine)
	}
	if f.Location.CommitSHA != "abc123def456" {
		t.Errorf("expected commit SHA 'abc123def456', got %q", f.Location.CommitSHA)
	}
	if f.Secret == nil {
		t.Fatal("expected non-nil secret details")
	}
	if f.Secret.SecretType != "credential" {
		t.Errorf("expected secret type 'credential', got %q", f.Secret.SecretType)
	}
	if f.Secret.Service != "aws" {
		t.Errorf("expected service 'aws', got %q", f.Secret.Service)
	}
	if f.Secret.Length != 20 {
		t.Errorf("expected secret length 20, got %d", f.Secret.Length)
	}
	if f.Secret.MaskedValue == "" {
		t.Error("expected non-empty masked value")
	}
	if f.Fingerprint != "config.yml:aws-access-key-id:10" {
		t.Errorf("expected fingerprint from gitleaks, got %q", f.Fingerprint)
	}
	if f.Author != "dev@example.com" {
		t.Errorf("expected author 'dev@example.com', got %q", f.Author)
	}
	if f.Confidence != 85 {
		t.Errorf("expected confidence 85, got %d", f.Confidence)
	}
}

func TestConvertGitHubPAT(t *testing.T) {
	a := NewAdapter()
	report, err := a.Convert(context.Background(), sampleGitleaksJSON, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	f := report.Findings[2]
	if f.Severity != ctis.SeverityCritical {
		t.Errorf("expected severity critical for github-pat, got %q", f.Severity)
	}
	if f.Secret == nil {
		t.Fatal("expected non-nil secret details")
	}
	if f.Secret.Service != "github" {
		t.Errorf("expected service 'github', got %q", f.Secret.Service)
	}
	// Tags from gitleaks
	foundGithubTag := false
	for _, tag := range f.Tags {
		if tag == "github" {
			foundGithubTag = true
			break
		}
	}
	if !foundGithubTag {
		t.Errorf("expected 'github' tag from gitleaks Tags field, got %v", f.Tags)
	}
}

func TestConvertStripeKey(t *testing.T) {
	a := NewAdapter()
	report, err := a.Convert(context.Background(), sampleGitleaksJSON, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	f := report.Findings[3]
	if f.Severity != ctis.SeverityHigh {
		t.Errorf("expected severity high for stripe-api-key, got %q", f.Severity)
	}
	if f.Secret == nil {
		t.Fatal("expected non-nil secret details")
	}
	if f.Secret.Service != "stripe" {
		t.Errorf("expected service 'stripe', got %q", f.Secret.Service)
	}
}

func TestConvertWithMinSeverity(t *testing.T) {
	a := NewAdapter()
	opts := &core.AdapterOptions{
		MinSeverity: "critical",
	}
	report, err := a.Convert(context.Background(), sampleGitleaksJSON, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// AWS key + GitHub PAT = 2 critical findings
	if len(report.Findings) != 2 {
		t.Errorf("expected 2 critical findings, got %d", len(report.Findings))
	}
}

func TestConvertWithRepository(t *testing.T) {
	a := NewAdapter()
	opts := &core.AdapterOptions{
		Repository: "github.com/org/repo",
	}
	report, err := a.Convert(context.Background(), sampleGitleaksJSON, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if report.Metadata.Scope == nil {
		t.Fatal("expected non-nil scope")
	}
	if report.Metadata.Scope.Name != "github.com/org/repo" {
		t.Errorf("expected scope name 'github.com/org/repo', got %q", report.Metadata.Scope.Name)
	}
}

func TestConvertInvalidJSON(t *testing.T) {
	a := NewAdapter()
	_, err := a.Convert(context.Background(), []byte(`not json`), nil)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestMaskSecret(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"AKIAIOSFODNN7EXAMPLE", "AKIA************MPLE"},
		{"short", "*****"},
		{"12345678", "********"},
		{"123456789", "1234*6789"},
	}

	for _, tt := range tests {
		result := maskSecret(tt.input)
		if result != tt.expected {
			t.Errorf("maskSecret(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestMapGitleaksSeverity(t *testing.T) {
	tests := []struct {
		ruleID   string
		expected ctis.Severity
	}{
		{"aws-access-key-id", ctis.SeverityCritical},
		{"github-pat", ctis.SeverityCritical},
		{"private-key", ctis.SeverityCritical},
		{"generic-api-key", ctis.SeverityHigh},
		{"stripe-api-key", ctis.SeverityHigh},
		{"unknown-rule", ctis.SeverityHigh},
	}

	for _, tt := range tests {
		result := mapGitleaksSeverity(tt.ruleID)
		if result != tt.expected {
			t.Errorf("mapGitleaksSeverity(%q) = %q, want %q", tt.ruleID, result, tt.expected)
		}
	}
}

func TestRuleIDToService(t *testing.T) {
	tests := []struct {
		ruleID   string
		expected string
	}{
		{"aws-access-key-id", "aws"},
		{"github-pat", "github"},
		{"stripe-api-key", "stripe"},
		{"generic-api-key", ""},
	}

	for _, tt := range tests {
		result := ruleIDToService(tt.ruleID)
		if result != tt.expected {
			t.Errorf("ruleIDToService(%q) = %q, want %q", tt.ruleID, result, tt.expected)
		}
	}
}

func TestParseToCTIS(t *testing.T) {
	report, err := ParseToCTIS(sampleGitleaksJSON, &core.ParseOptions{
		AssetValue: "github.com/org/repo",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report == nil {
		t.Fatal("expected non-nil report")
	}
	if len(report.Findings) != 4 {
		t.Errorf("expected 4 findings, got %d", len(report.Findings))
	}
}
