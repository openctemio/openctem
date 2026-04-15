package vuls

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/openctemio/api/internal/infra/adapters/core"
	"github.com/openctemio/ctis"
)

func buildTestReport() VulsReport {
	return VulsReport{
		JSONVersion: 4,
		ServerName:  "web-server-01",
		Family:      "ubuntu",
		Release:     "22.04",
		RunningKernel: VulsKernel{
			Version: "6.8.0-85",
			Release: "generic",
		},
		ScannedIPv4: []string{"10.10.10.1"},
		Packages: VulsPackages{
			"linux": {
				Name:    "linux",
				Version: "6.8.0",
				Release: "85",
				Arch:    "amd64",
			},
			"openssl": {
				Name:    "openssl",
				Version: "3.0.2",
				Release: "0ubuntu1.15",
				Arch:    "amd64",
			},
		},
		ScannedCves: []VulsCveResult{
			{
				CveID: "CVE-2024-1234",
				Confidences: []VulsConfidence{
					{Score: 100, DetectionMethod: "ChangelogExactMatch"},
				},
				CveContents: VulsCveContents{
					"nvd": {
						{
							Type:        "nvd",
							CveID:       "CVE-2024-1234",
							Title:       "Critical vulnerability in Linux kernel",
							Summary:     "A buffer overflow in the Linux kernel allows privilege escalation.",
							Cvss3Score:  9.8,
							Cvss3Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
							CweIDs:      []string{"CWE-120"},
							References: []VulsRef{
								{Source: "nvd", Link: "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"},
							},
							SourceLink: "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
						},
					},
				},
				AffectedPackages: []VulsAffectedPkg{
					{Name: "linux", FixedIn: "6.8.0-90"},
				},
			},
			{
				CveID: "CVE-2024-5678",
				CveContents: VulsCveContents{
					"ubuntu": {
						{
							Type:        "ubuntu",
							CveID:       "CVE-2024-5678",
							Title:       "OpenSSL timing side-channel",
							Summary:     "A timing side-channel in OpenSSL RSA implementation.",
							Cvss3Score:  5.3,
							Cvss3Vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
						},
					},
				},
				AffectedPackages: []VulsAffectedPkg{
					{Name: "openssl", NotFixedYet: true},
				},
			},
		},
	}
}

func TestAdapter_Name(t *testing.T) {
	a := NewAdapter()
	if a.Name() != "vuls" {
		t.Errorf("expected 'vuls', got %q", a.Name())
	}
}

func TestAdapter_CanConvert(t *testing.T) {
	a := NewAdapter()

	report := buildTestReport()
	data, _ := json.Marshal(report)

	if !a.CanConvert(data) {
		t.Error("expected CanConvert to return true for valid Vuls report")
	}

	if a.CanConvert([]byte(`{"invalid": true}`)) {
		t.Error("expected CanConvert to return false for invalid data")
	}

	if a.CanConvert([]byte(`not json`)) {
		t.Error("expected CanConvert to return false for non-JSON")
	}
}

func TestAdapter_Convert_Basic(t *testing.T) {
	a := NewAdapter()
	report := buildTestReport()
	data, _ := json.Marshal(report)

	result, err := a.Convert(context.Background(), data, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check tool info
	if result.Tool == nil || result.Tool.Name != "vuls" {
		t.Error("expected tool name 'vuls'")
	}

	// Check asset
	if len(result.Assets) != 1 {
		t.Fatalf("expected 1 asset, got %d", len(result.Assets))
	}
	asset := result.Assets[0]
	if asset.Value != "10.10.10.1" {
		t.Errorf("expected asset value '10.10.10.1', got %q", asset.Value)
	}
	if asset.Name != "web-server-01" {
		t.Errorf("expected asset name 'web-server-01', got %q", asset.Name)
	}

	// Check dependencies
	if len(result.Dependencies) != 2 {
		t.Fatalf("expected 2 dependencies, got %d", len(result.Dependencies))
	}

	// Check findings (2 CVEs = 2 findings)
	if len(result.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(result.Findings))
	}
}

func TestAdapter_Convert_CVEDetails(t *testing.T) {
	a := NewAdapter()
	report := buildTestReport()
	data, _ := json.Marshal(report)

	result, err := a.Convert(context.Background(), data, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// First finding: CVE-2024-1234 (critical, has fix)
	f1 := result.Findings[0]
	if f1.RuleID != "CVE-2024-1234" {
		t.Errorf("expected rule_id 'CVE-2024-1234', got %q", f1.RuleID)
	}
	if f1.Severity != ctis.SeverityCritical {
		t.Errorf("expected severity critical, got %q", f1.Severity)
	}
	if f1.Vulnerability == nil {
		t.Fatal("expected vulnerability details")
	}
	if f1.Vulnerability.CVEID != "CVE-2024-1234" {
		t.Errorf("expected CVE ID 'CVE-2024-1234', got %q", f1.Vulnerability.CVEID)
	}
	if f1.Vulnerability.CVSSScore != 9.8 {
		t.Errorf("expected CVSS score 9.8, got %f", f1.Vulnerability.CVSSScore)
	}
	if f1.Vulnerability.FixedVersion != "6.8.0-90" {
		t.Errorf("expected fixed version '6.8.0-90', got %q", f1.Vulnerability.FixedVersion)
	}
	if f1.Vulnerability.Package != "linux" {
		t.Errorf("expected package 'linux', got %q", f1.Vulnerability.Package)
	}
	if f1.Remediation == nil || f1.Remediation.Recommendation == "" {
		t.Error("expected remediation for finding with fix")
	}
	if f1.Fingerprint == "" {
		t.Error("expected non-empty fingerprint")
	}

	// Second finding: CVE-2024-5678 (medium, no fix)
	f2 := result.Findings[1]
	if f2.Severity != ctis.SeverityMedium {
		t.Errorf("expected severity medium, got %q", f2.Severity)
	}
	if f2.Remediation == nil {
		t.Error("expected remediation message for unfixed CVE")
	}
}

func TestAdapter_Convert_PURL(t *testing.T) {
	a := NewAdapter()
	report := buildTestReport()
	data, _ := json.Marshal(report)

	result, err := a.Convert(context.Background(), data, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check PURL for linux package
	f1 := result.Findings[0]
	purl := f1.Vulnerability.PURL
	if purl == "" {
		t.Fatal("expected PURL for vulnerability")
	}
	if !contains(purl, "pkg:deb/ubuntu/linux@") {
		t.Errorf("expected PURL to start with 'pkg:deb/ubuntu/linux@', got %q", purl)
	}
	if !contains(purl, "arch=amd64") {
		t.Errorf("expected PURL to contain 'arch=amd64', got %q", purl)
	}
}

func TestAdapter_Convert_Dependencies(t *testing.T) {
	a := NewAdapter()
	report := buildTestReport()
	data, _ := json.Marshal(report)

	result, err := a.Convert(context.Background(), data, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	depMap := make(map[string]ctis.Dependency)
	for _, d := range result.Dependencies {
		depMap[d.Name] = d
	}

	linux, ok := depMap["linux"]
	if !ok {
		t.Fatal("expected linux dependency")
	}
	if linux.Version != "6.8.0-85" {
		t.Errorf("expected version '6.8.0-85', got %q", linux.Version)
	}
	if linux.Ecosystem != "deb" {
		t.Errorf("expected ecosystem 'deb', got %q", linux.Ecosystem)
	}
	if !contains(linux.PURL, "pkg:deb/ubuntu/linux@6.8.0-85") {
		t.Errorf("expected PURL 'pkg:deb/ubuntu/linux@6.8.0-85...', got %q", linux.PURL)
	}
}

func TestAdapter_Convert_MinSeverityFilter(t *testing.T) {
	a := NewAdapter()
	report := buildTestReport()
	data, _ := json.Marshal(report)

	opts := &core.AdapterOptions{
		MinSeverity: "high",
	}

	result, err := a.Convert(context.Background(), data, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Only CVE-2024-1234 (critical) should pass the high filter
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding after high filter, got %d", len(result.Findings))
	}
	if result.Findings[0].RuleID != "CVE-2024-1234" {
		t.Errorf("expected CVE-2024-1234, got %q", result.Findings[0].RuleID)
	}
}

func TestAdapter_Convert_NoIPv4(t *testing.T) {
	a := NewAdapter()
	report := buildTestReport()
	report.ScannedIPv4 = nil // No IPs
	data, _ := json.Marshal(report)

	result, err := a.Convert(context.Background(), data, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should fall back to server name as asset value
	if result.Assets[0].Value != "web-server-01" {
		t.Errorf("expected fallback to server name, got %q", result.Assets[0].Value)
	}
}

func TestAdapter_Convert_EmptyCves(t *testing.T) {
	a := NewAdapter()
	report := buildTestReport()
	report.ScannedCves = nil
	data, _ := json.Marshal(report)

	result, err := a.Convert(context.Background(), data, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(result.Findings))
	}
}

func TestAdapter_Interface(t *testing.T) {
	var _ core.Adapter = (*Adapter)(nil)
}

func TestBuildPURL(t *testing.T) {
	tests := []struct {
		family, release, name, version, arch string
		want                                 string
	}{
		{"ubuntu", "22.04", "linux", "6.8.0-85", "amd64", "pkg:deb/ubuntu/linux@6.8.0-85?arch=amd64&distro=22.04"},
		{"redhat", "9", "openssl", "3.0.7", "x86_64", "pkg:rpm/redhat/openssl@3.0.7?arch=x86_64&distro=9"},
		{"alpine", "3.18", "musl", "1.2.4", "", "pkg:apk/alpine/musl@1.2.4?distro=3.18"},
		{"amazon", "2", "curl", "7.88", "x86_64", "pkg:rpm/amzn/curl@7.88?arch=x86_64&distro=2"},
	}

	for _, tt := range tests {
		got := buildPURL(tt.family, tt.release, tt.name, tt.version, tt.arch)
		if got != tt.want {
			t.Errorf("buildPURL(%s, %s, %s, %s, %s) = %q, want %q",
				tt.family, tt.release, tt.name, tt.version, tt.arch, got, tt.want)
		}
	}
}

func TestCvssToSeverity(t *testing.T) {
	tests := []struct {
		score    float64
		expected ctis.Severity
	}{
		{9.8, ctis.SeverityCritical},
		{9.0, ctis.SeverityCritical},
		{8.5, ctis.SeverityHigh},
		{7.0, ctis.SeverityHigh},
		{5.5, ctis.SeverityMedium},
		{4.0, ctis.SeverityMedium},
		{2.0, ctis.SeverityLow},
		{0.1, ctis.SeverityLow},
		{0.0, ctis.SeverityInfo},
	}

	for _, tt := range tests {
		got := cvssToSeverity(tt.score)
		if got != tt.expected {
			t.Errorf("cvssToSeverity(%f) = %q, want %q", tt.score, got, tt.expected)
		}
	}
}

func TestParseToCTIS(t *testing.T) {
	report := buildTestReport()
	data, _ := json.Marshal(report)

	result, err := ParseToCTIS(data, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(result.Findings))
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
