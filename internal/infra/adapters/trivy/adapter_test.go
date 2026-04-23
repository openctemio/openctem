package trivy

import (
	"context"
	"testing"

	"github.com/openctemio/api/internal/infra/adapters/core"
	"github.com/openctemio/ctis"
)

var sampleTrivyJSON = []byte(`{
  "SchemaVersion": 2,
  "ArtifactName": "alpine:3.18.0",
  "ArtifactType": "container_image",
  "Results": [
    {
      "Target": "alpine:3.18.0 (alpine 3.18.0)",
      "Class": "os-pkgs",
      "Type": "alpine",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2023-1234",
          "PkgName": "openssl",
          "PkgPath": "lib/apk/db/installed",
          "InstalledVersion": "1.1.1",
          "FixedVersion": "1.1.2",
          "Severity": "HIGH",
          "Title": "OpenSSL Buffer Overflow",
          "Description": "A buffer overflow vulnerability in OpenSSL allows remote attackers to execute arbitrary code.",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-1234",
          "CVSS": {
            "nvd": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
              "V3Score": 7.5
            }
          },
          "CweIDs": ["CWE-120"],
          "References": [
            "https://nvd.nist.gov/vuln/detail/CVE-2023-1234",
            "https://www.openssl.org/news/secadv/20230101.txt"
          ]
        },
        {
          "VulnerabilityID": "CVE-2023-5678",
          "PkgName": "curl",
          "InstalledVersion": "7.88.0",
          "FixedVersion": "",
          "Severity": "CRITICAL",
          "Title": "curl: HSTS bypass via IDN",
          "Description": "A vulnerability in curl allows HSTS bypass.",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-5678",
          "CVSS": {
            "nvd": {
              "V3Score": 9.8
            }
          },
          "References": []
        }
      ]
    },
    {
      "Target": "Dockerfile",
      "Class": "config",
      "Misconfigurations": [
        {
          "Type": "dockerfile",
          "ID": "DS002",
          "AVDID": "AVD-DS-0002",
          "Title": "Image user should not be 'root'",
          "Description": "Running as root increases the risk of container escape.",
          "Message": "Specify at least 1 USER command in Dockerfile",
          "Namespace": "builtin.dockerfile.DS002",
          "Severity": "HIGH",
          "PrimaryURL": "https://avd.aquasec.com/misconfig/ds002",
          "References": ["https://docs.docker.com/engine/reference/builder/#user"],
          "CauseMetadata": {
            "Provider": "Dockerfile",
            "Service": "general",
            "StartLine": 1,
            "EndLine": 1
          }
        }
      ]
    }
  ]
}`)

func TestAdapterName(t *testing.T) {
	a := NewAdapter()
	if a.Name() != "trivy" {
		t.Errorf("expected name 'trivy', got %q", a.Name())
	}
}

func TestAdapterInputFormats(t *testing.T) {
	a := NewAdapter()
	formats := a.InputFormats()
	if len(formats) != 2 || formats[0] != "trivy" || formats[1] != "json" {
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

	if !a.CanConvert(sampleTrivyJSON) {
		t.Error("expected CanConvert to return true for valid Trivy JSON")
	}

	if a.CanConvert([]byte(`{"invalid": true}`)) {
		t.Error("expected CanConvert to return false for non-Trivy JSON")
	}

	if a.CanConvert([]byte(`not json`)) {
		t.Error("expected CanConvert to return false for invalid JSON")
	}
}

func TestConvert(t *testing.T) {
	a := NewAdapter()
	report, err := a.Convert(context.Background(), sampleTrivyJSON, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if report == nil {
		t.Fatal("expected non-nil report")
	}

	if report.Tool == nil {
		t.Fatal("expected non-nil tool")
	}

	if report.Tool.Name != "trivy" {
		t.Errorf("expected tool name 'trivy', got %q", report.Tool.Name)
	}

	// 2 vulnerabilities + 1 misconfiguration = 3 findings
	if len(report.Findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(report.Findings))
	}
}

func TestConvertVulnerabilities(t *testing.T) {
	a := NewAdapter()
	report, err := a.Convert(context.Background(), sampleTrivyJSON, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// First vulnerability: CVE-2023-1234 (HIGH)
	f := report.Findings[0]
	if f.Type != ctis.FindingTypeVulnerability {
		t.Errorf("expected finding type vulnerability, got %q", f.Type)
	}
	if f.Severity != ctis.SeverityHigh {
		t.Errorf("expected severity high, got %q", f.Severity)
	}
	if f.Title != "OpenSSL Buffer Overflow" {
		t.Errorf("expected title 'OpenSSL Buffer Overflow', got %q", f.Title)
	}
	if f.RuleID != "CVE-2023-1234" {
		t.Errorf("expected rule ID 'CVE-2023-1234', got %q", f.RuleID)
	}
	if f.Vulnerability == nil {
		t.Fatal("expected non-nil vulnerability details")
	}
	if f.Vulnerability.CVEID != "CVE-2023-1234" {
		t.Errorf("expected CVE ID 'CVE-2023-1234', got %q", f.Vulnerability.CVEID)
	}
	if f.Vulnerability.Package != "openssl" {
		t.Errorf("expected package 'openssl', got %q", f.Vulnerability.Package)
	}
	if f.Vulnerability.AffectedVersion != "1.1.1" {
		t.Errorf("expected affected version '1.1.1', got %q", f.Vulnerability.AffectedVersion)
	}
	if f.Vulnerability.FixedVersion != "1.1.2" {
		t.Errorf("expected fixed version '1.1.2', got %q", f.Vulnerability.FixedVersion)
	}
	if f.Vulnerability.CVSSScore != 7.5 {
		t.Errorf("expected CVSS score 7.5, got %f", f.Vulnerability.CVSSScore)
	}
	if f.Fingerprint == "" {
		t.Error("expected non-empty fingerprint")
	}
	if len(f.References) == 0 {
		t.Error("expected references")
	}

	// Second vulnerability: CVE-2023-5678 (CRITICAL)
	f2 := report.Findings[1]
	if f2.Severity != ctis.SeverityCritical {
		t.Errorf("expected severity critical, got %q", f2.Severity)
	}
}

func TestConvertMisconfigurations(t *testing.T) {
	a := NewAdapter()
	report, err := a.Convert(context.Background(), sampleTrivyJSON, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Third finding is the misconfiguration
	f := report.Findings[2]
	if f.Type != ctis.FindingTypeMisconfiguration {
		t.Errorf("expected finding type misconfiguration, got %q", f.Type)
	}
	if f.Severity != ctis.SeverityHigh {
		t.Errorf("expected severity high, got %q", f.Severity)
	}
	if f.RuleID != "DS002" {
		t.Errorf("expected rule ID 'DS002', got %q", f.RuleID)
	}
	if f.Misconfiguration == nil {
		t.Fatal("expected non-nil misconfiguration details")
	}
	if f.Misconfiguration.AVDID != "AVD-DS-0002" {
		t.Errorf("expected AVD ID 'AVD-DS-0002', got %q", f.Misconfiguration.AVDID)
	}
	if f.Location == nil {
		t.Fatal("expected non-nil location")
	}
	if f.Location.StartLine != 1 {
		t.Errorf("expected start line 1, got %d", f.Location.StartLine)
	}
	if f.Fingerprint == "" {
		t.Error("expected non-empty fingerprint")
	}
}

func TestConvertWithOptions(t *testing.T) {
	a := NewAdapter()
	opts := &core.AdapterOptions{
		Repository:  "github.com/org/repo",
		MinSeverity: "critical",
	}
	report, err := a.Convert(context.Background(), sampleTrivyJSON, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Only the CRITICAL vulnerability should remain
	if len(report.Findings) != 1 {
		t.Errorf("expected 1 finding with min severity critical, got %d", len(report.Findings))
	}
	if len(report.Findings) > 0 && report.Findings[0].Severity != ctis.SeverityCritical {
		t.Errorf("expected critical finding, got %q", report.Findings[0].Severity)
	}
}

func TestConvertInvalidJSON(t *testing.T) {
	a := NewAdapter()
	_, err := a.Convert(context.Background(), []byte(`not json`), nil)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestMapTrivySeverity(t *testing.T) {
	tests := []struct {
		input    string
		expected ctis.Severity
	}{
		{"CRITICAL", ctis.SeverityCritical},
		{"HIGH", ctis.SeverityHigh},
		{"MEDIUM", ctis.SeverityMedium},
		{"LOW", ctis.SeverityLow},
		{"UNKNOWN", ctis.SeverityInfo},
		{"critical", ctis.SeverityCritical},
		{"high", ctis.SeverityHigh},
	}

	for _, tt := range tests {
		result := mapTrivySeverity(tt.input)
		if result != tt.expected {
			t.Errorf("mapTrivySeverity(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestParseToCTIS(t *testing.T) {
	report, err := ParseToCTIS(sampleTrivyJSON, &core.ParseOptions{
		AssetValue: "alpine:3.18.0",
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
