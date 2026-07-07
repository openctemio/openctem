package defectdojo

import (
	"encoding/json"
	"testing"

	"github.com/openctemio/ctis"
)

// A representative slice of a DefectDojo /api/v2/findings/ response.
const sampleDDFindings = `[
  {
    "id": 101,
    "title": "SQL Injection in login",
    "description": "User input reaches the query unsanitized.",
    "severity": "High",
    "mitigation": "Use parameterized queries.",
    "cwe": 89,
    "cve": "CVE-2021-1234",
    "vulnerability_ids": [{"vulnerability_id": "CVE-2021-1234"}, {"vulnerability_id": "cve-2021-9999"}],
    "cvssv3_score": 8.6,
    "cvssv3": "CVSS:3.1/AV:N/AC:L",
    "file_path": "app/auth/login.go",
    "line": 42,
    "unique_id_from_tool": "sqli-login-1",
    "hash_code": "abc123hash",
    "references": "https://owasp.org/a03\nhttps://cwe.mitre.org/89",
    "tags": ["sast"],
    "risk_accepted": true,
    "endpoint_hosts": ["app.example.com"]
  },
  {
    "id": 102,
    "title": "Info: server banner",
    "severity": "Info",
    "hash_code": "def456"
  }
]`

func mustConvert(t *testing.T, opts ConvertOptions) *ctis.Report {
	t.Helper()
	var findings []Finding
	if err := json.Unmarshal([]byte(sampleDDFindings), &findings); err != nil {
		t.Fatalf("unmarshal sample: %v", err)
	}
	return Convert(findings, opts)
}

func TestConvert_MapsCoreFields(t *testing.T) {
	report := mustConvert(t, ConvertOptions{SourceRef: "test-7", ProductName: "acme/app"})

	if report.Metadata.CoverageType != "partial" {
		t.Fatalf("coverage_type = %q, want partial (must not auto-resolve)", report.Metadata.CoverageType)
	}
	if report.Metadata.SourceType != "integration" || report.Tool == nil || report.Tool.Name != "defectdojo" {
		t.Fatalf("metadata/tool wrong: %+v tool=%+v", report.Metadata, report.Tool)
	}
	if len(report.Findings) != 2 {
		t.Fatalf("findings = %d, want 2", len(report.Findings))
	}

	f := report.Findings[0]
	if f.Severity != ctis.SeverityHigh {
		t.Errorf("severity = %q, want high", f.Severity)
	}
	if f.Vulnerability == nil || f.Vulnerability.CVEID != "CVE-2021-1234" {
		t.Errorf("primary CVE wrong: %+v", f.Vulnerability)
	}
	if len(f.Vulnerability.CVEIDs) != 2 { // dedup + uppercased
		t.Errorf("CVEIDs = %v, want 2 (deduped, uppercased)", f.Vulnerability.CVEIDs)
	}
	if f.Vulnerability.CWEID != "CWE-89" {
		t.Errorf("CWE = %q, want CWE-89", f.Vulnerability.CWEID)
	}
	if f.Vulnerability.CVSSScore != 8.6 {
		t.Errorf("CVSS = %v, want 8.6", f.Vulnerability.CVSSScore)
	}
	if f.Location == nil || f.Location.Path != "app/auth/login.go" || f.Location.StartLine != 42 {
		t.Errorf("location wrong: %+v", f.Location)
	}
	if f.AssetValue != "app.example.com" || f.AssetType != ctis.AssetTypeWebsite {
		t.Errorf("asset = %q/%q, want endpoint host → website", f.AssetValue, f.AssetType)
	}
	if f.Remediation == nil || f.Remediation.Recommendation == "" {
		t.Errorf("remediation not mapped from mitigation")
	}
}

// The dedup/idempotency invariant: every finding carries DefectDojo's stable
// identity and a deterministic fingerprint, so re-imports don't double-dedup.
func TestConvert_CarriesExternalRefAndStableFingerprint(t *testing.T) {
	r1 := mustConvert(t, ConvertOptions{ProductName: "acme/app"})
	r2 := mustConvert(t, ConvertOptions{ProductName: "acme/app"})

	f := r1.Findings[0]
	if f.Fingerprint != "defectdojo:abc123hash" {
		t.Errorf("fingerprint = %q, want defectdojo:abc123hash", f.Fingerprint)
	}
	if f.PartialFingerprints["defectdojo/finding_id"] != "101" ||
		f.PartialFingerprints["defectdojo/hash_code"] != "abc123hash" {
		t.Errorf("external refs missing: %v", f.PartialFingerprints)
	}
	// Deterministic across re-convert (idempotent).
	if r1.Findings[0].Fingerprint != r2.Findings[0].Fingerprint {
		t.Error("fingerprint not stable across re-convert")
	}
}

// DefectDojo triage is a hint (tag), never an authoritative status.
func TestConvert_TriageBecomesTagsNotStatus(t *testing.T) {
	report := mustConvert(t, ConvertOptions{})
	f := report.Findings[0]
	found := false
	for _, tag := range f.Tags {
		if tag == "dd:risk_accepted" {
			found = true
		}
	}
	if !found {
		t.Errorf("risk_accepted should surface as a tag hint, got tags=%v", f.Tags)
	}
	if f.Status != "" {
		t.Errorf("DefectDojo import must not set an authoritative status, got %q", f.Status)
	}
}

func TestConvert_MinSeverityFilter(t *testing.T) {
	report := mustConvert(t, ConvertOptions{MinSeverity: ctis.SeverityMedium})
	if len(report.Findings) != 1 {
		t.Fatalf("with MinSeverity=medium, findings = %d, want 1 (Info dropped)", len(report.Findings))
	}
}
