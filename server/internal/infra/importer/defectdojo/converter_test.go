package defectdojo

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/openctemio/ctis/v2"
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

	if report.Metadata.CoverageType != ctis.CoveragePartial {
		t.Fatalf("coverage_type = %q, want partial (must not auto-resolve)", report.Metadata.CoverageType)
	}
	if report.Metadata.Channel != ctis.ChannelIntegration || report.Tool == nil || report.Tool.Name != "defectdojo" {
		t.Fatalf("metadata/tool wrong: %+v tool=%+v", report.Metadata, report.Tool)
	}
	if len(report.Findings) != 2 {
		t.Fatalf("findings = %d, want 2", len(report.Findings))
	}

	f := report.Findings[0]
	if f.Severity != ctis.SeverityHigh {
		t.Errorf("severity = %q, want high", f.Severity)
	}
	if f.Vulnerability == nil || len(f.Vulnerability.IDs) != 2 { // dedup + uppercased
		t.Fatalf("vulnerability ids = %+v, want 2 (deduped, uppercased)", f.Vulnerability)
	}
	if cves := ctis.CVEs(f.Vulnerability); cves[0] != "CVE-2021-1234" || cves[1] != "CVE-2021-9999" {
		t.Errorf("CVEs = %v, want CVE-2021-1234, CVE-2021-9999", cves)
	}
	if len(f.Vulnerability.CWEIDs) != 1 || f.Vulnerability.CWEIDs[0] != "CWE-89" {
		t.Errorf("CWEIDs = %v, want [CWE-89]", f.Vulnerability.CWEIDs)
	}
	if len(f.Scores) != 1 {
		t.Fatalf("scores = %+v, want one CVSS score", f.Scores)
	}
	if sc := f.Scores[0]; sc.System != ctis.ScoreSystemCVSS || sc.Value == nil || *sc.Value != 8.6 ||
		sc.Vector != "CVSS:3.1/AV:N/AC:L" || sc.Version != "3.1" || sc.Source != "defectdojo" {
		t.Errorf("CVSS score wrong: %+v", sc)
	}
	if f.Location == nil || f.Location.Path != "app/auth/login.go" || f.Location.StartLine != 42 {
		t.Errorf("location wrong: %+v", f.Location)
	}
	if f.Remediation == nil || f.Remediation.Recommendation == "" {
		t.Errorf("remediation not mapped from mitigation")
	}
	// The endpoint host becomes a domain_name asset the finding refers to.
	a := assetByID(report, f.AssetRef)
	if a == nil || a.Type != ctis.AssetTypeDomainName || a.Value != "app.example.com" {
		t.Errorf("asset = %+v, want endpoint host -> domain_name app.example.com", a)
	}
}

func assetByID(r *ctis.Report, id string) *ctis.Asset {
	for i := range r.Assets {
		if r.Assets[i].ID == id {
			return &r.Assets[i]
		}
	}
	return nil
}

// A converted report is a valid CTIS 2.0 document that carries no OpenCTEM id:
// metadata.id is a producer UUIDv7, DefectDojo's id is a source_ref, and every
// finding names an asset of the document.
func TestConvert_ReportIsValidAndCarriesNoReceiverKey(t *testing.T) {
	report := mustConvert(t, ConvertOptions{SourceRef: "test-7", ProductName: "acme/app"})

	if report.Version != ctis.SchemaVersion {
		t.Errorf("version = %q, want %q", report.Version, ctis.SchemaVersion)
	}
	if !ctis.IsReportID(report.Metadata.ID) {
		t.Errorf("metadata.id %q is not a UUIDv7", report.Metadata.ID)
	}
	if len(report.Metadata.SourceRefs) != 1 || report.Metadata.SourceRefs[0] != (ctis.SourceRef{System: "defectdojo", ID: "test-7"}) {
		t.Errorf("metadata.source_refs = %+v, want defectdojo/test-7", report.Metadata.SourceRefs)
	}
	for i, f := range report.Findings {
		if f.AssetRef == "" || assetByID(report, f.AssetRef) == nil {
			t.Errorf("finding %d has no asset_ref of the document: %q", i, f.AssetRef)
		}
	}
	// The asset-less info finding falls back to the product asset.
	if a := assetByID(report, report.Findings[1].AssetRef); a == nil || a.Type != ctis.AssetTypeUnclassified || a.Value != "acme/app" {
		t.Errorf("fallback asset = %+v, want unclassified acme/app", a)
	}
	if err := report.Validate(); err != nil {
		t.Fatalf("converted report does not validate: %v", err)
	}
	// No OpenCTEM id (tenant, run, scan) anywhere in the document.
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"tenant_id", "scan_id", "run_id", "program_id"} {
		if strings.Contains(string(raw), `"`+key+`"`) {
			t.Errorf("document carries %q", key)
		}
	}
}

// A URL endpoint is a web_origin asset, an address an ip_address asset.
func TestConvert_EndpointKinds(t *testing.T) {
	findings := []Finding{
		{ID: 1, Title: "a", Severity: "High", Endpoints: []string{"https://App.Example.com:443/login?x=1"}},
		{ID: 2, Title: "b", Severity: "High", Endpoints: []string{"203.0.113.5"}},
		{ID: 3, Title: "c", Severity: "High", Endpoints: []string{"app.example.com"}},
	}
	report := Convert(findings, ConvertOptions{})
	want := []struct {
		typ ctis.AssetType
		val string
	}{
		{ctis.AssetTypeWebOrigin, "https://app.example.com"},
		{ctis.AssetTypeIPAddress, "203.0.113.5"},
		{ctis.AssetTypeDomainName, "app.example.com"},
	}
	for i, w := range want {
		a := assetByID(report, report.Findings[i].AssetRef)
		if a == nil || a.Type != w.typ || a.Value != w.val {
			t.Errorf("finding %d asset = %+v, want %s %s", i, a, w.typ, w.val)
		}
	}
	if err := report.Validate(); err != nil {
		t.Fatalf("report does not validate: %v", err)
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
