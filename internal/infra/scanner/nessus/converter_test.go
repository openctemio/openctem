package nessus

import (
	"strings"
	"testing"
	"time"

	"github.com/openctemio/ctis"
)

// sampleNessus is a trimmed but representative NessusClientData_v2 export with
// two hosts: one with a critical CVE finding + an info item, one clean.
const sampleNessus = `<?xml version="1.0" ?>
<NessusClientData_v2>
  <Report name="Rolling batch 1">
    <ReportHost name="10.0.0.5">
      <HostProperties>
        <tag name="host-ip">10.0.0.5</tag>
        <tag name="host-fqdn">web01.corp.local</tag>
        <tag name="operating-system">Linux Kernel 5.4</tag>
        <tag name="mac-address">00:11:22:33:44:55</tag>
      </HostProperties>
      <ReportItem port="443" svc_name="https" protocol="tcp" severity="4" pluginID="98765" pluginName="OpenSSL Heartbleed" pluginFamily="General">
        <synopsis>The remote service is affected by an information disclosure vulnerability.</synopsis>
        <description>The version of OpenSSL is vulnerable to Heartbleed.</description>
        <solution>Upgrade OpenSSL to 1.0.1g or later.</solution>
        <risk_factor>Critical</risk_factor>
        <cvss_base_score>5.0</cvss_base_score>
        <cvss_vector>AV:N/AC:L/Au:N/C:P/I:N/A:N</cvss_vector>
        <cvss3_base_score>7.5</cvss3_base_score>
        <cvss3_vector>CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N</cvss3_vector>
        <cve>CVE-2014-0160</cve>
        <see_also>https://heartbleed.com
https://www.openssl.org/news/secadv/20140407.txt</see_also>
        <plugin_output>TLSv1.1 is enabled and the server supports the heartbeat extension.</plugin_output>
      </ReportItem>
      <ReportItem port="0" svc_name="general" protocol="tcp" severity="0" pluginID="19506" pluginName="Nessus Scan Information" pluginFamily="Settings">
        <synopsis>Information about the Nessus scan.</synopsis>
        <description>This plugin displays scan settings.</description>
      </ReportItem>
    </ReportHost>
    <ReportHost name="10.0.0.6">
      <HostProperties>
        <tag name="host-ip">10.0.0.6</tag>
      </HostProperties>
    </ReportHost>
  </Report>
</NessusClientData_v2>`

func convert(t *testing.T, opts ConvertOptions) *ctis.Report {
	t.Helper()
	rep, err := Convert(strings.NewReader(sampleNessus), opts)
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}
	return rep
}

// TestConvert_SafetyCriticalReportShape is the most important test: it asserts
// the report carries everything the ingest pipeline needs to scope auto-resolve
// to THIS batch (tool name + scan id + coverage + default branch), so a batch
// can never resolve another batch's findings.
func TestConvert_SafetyCriticalReportShape(t *testing.T) {
	rep := convert(t, ConvertOptions{ScanSessionID: "batch-1-uuid", ToolName: "tenable"})

	if rep.Tool == nil || rep.Tool.Name != "tenable" {
		t.Fatalf("tool name must be set for auto-resolve scoping, got %+v", rep.Tool)
	}
	if rep.Metadata.ID != "batch-1-uuid" {
		t.Fatalf("metadata.id must carry the batch session id, got %q", rep.Metadata.ID)
	}
	if rep.Metadata.CoverageType != "full" {
		t.Fatalf("coverage must be full to enable auto-resolve, got %q", rep.Metadata.CoverageType)
	}
	if rep.Metadata.Branch == nil || !rep.Metadata.Branch.IsDefaultBranch {
		t.Fatal("a synthetic default branch is required for the git-centric auto-resolve gate")
	}
}

func TestConvert_DefaultToolName(t *testing.T) {
	rep := convert(t, ConvertOptions{ScanSessionID: "x"})
	if rep.Tool.Name != "tenable" {
		t.Fatalf("default tool name should be tenable, got %q", rep.Tool.Name)
	}
}

func TestConvert_AssetsExtracted(t *testing.T) {
	rep := convert(t, ConvertOptions{ScanSessionID: "x"})
	if len(rep.Assets) != 2 {
		t.Fatalf("expected 2 host assets, got %d", len(rep.Assets))
	}
	a := rep.Assets[0]
	if a.Value != "web01.corp.local" {
		t.Fatalf("expected FQDN as canonical value, got %q", a.Value)
	}
	if a.Properties["ip_address"] != "10.0.0.5" {
		t.Fatalf("expected ip in properties, got %v", a.Properties["ip_address"])
	}
	if a.Properties["os"] != "Linux Kernel 5.4" {
		t.Fatalf("expected os in properties, got %v", a.Properties["os"])
	}
	// Host with only an IP becomes an ip_address asset.
	if rep.Assets[1].Type != ctis.AssetTypeIPAddress || rep.Assets[1].Value != "10.0.0.6" {
		t.Fatalf("ip-only host should be ip_address/10.0.0.6, got %s/%s", rep.Assets[1].Type, rep.Assets[1].Value)
	}
}

func TestConvert_FindingMapping(t *testing.T) {
	rep := convert(t, ConvertOptions{ScanSessionID: "x"}) // MinSeverity 0 → includes info item
	if len(rep.Findings) != 2 {
		t.Fatalf("expected 2 findings (critical + info), got %d", len(rep.Findings))
	}

	var crit *ctis.Finding
	for i := range rep.Findings {
		if rep.Findings[i].RuleID == "98765" {
			crit = &rep.Findings[i]
		}
	}
	if crit == nil {
		t.Fatal("heartbleed finding not found")
	}
	if crit.Severity != ctis.SeverityCritical {
		t.Fatalf("severity 4 must map to critical, got %q", crit.Severity)
	}
	if crit.Type != ctis.FindingTypeVulnerability {
		t.Fatalf("expected vulnerability type, got %q", crit.Type)
	}
	if crit.AssetRef != "host-web01.corp.local" {
		t.Fatalf("finding must reference its host asset, got %q", crit.AssetRef)
	}
	if crit.Vulnerability == nil || crit.Vulnerability.CVEID != "CVE-2014-0160" {
		t.Fatalf("expected CVE-2014-0160, got %+v", crit.Vulnerability)
	}
	// CVSS v3 preferred over v2.
	if crit.Vulnerability.CVSSScore != 7.5 || crit.Vulnerability.CVSSVersion != "3.x" {
		t.Fatalf("expected CVSS v3 7.5, got %v %q", crit.Vulnerability.CVSSScore, crit.Vulnerability.CVSSVersion)
	}
	if crit.Remediation == nil || !strings.Contains(crit.Remediation.Recommendation, "Upgrade OpenSSL") {
		t.Fatalf("expected remediation from solution, got %+v", crit.Remediation)
	}
	if len(crit.References) != 2 {
		t.Fatalf("expected 2 see_also references, got %d", len(crit.References))
	}
	if crit.Properties["port"] != 443 {
		t.Fatalf("expected port 443 in properties, got %v", crit.Properties["port"])
	}
	if crit.Fingerprint != "nessus:web01.corp.local:98765:443/tcp" {
		t.Fatalf("unexpected fingerprint %q", crit.Fingerprint)
	}
}

func TestConvert_MinSeverityFilter(t *testing.T) {
	rep := convert(t, ConvertOptions{ScanSessionID: "x", MinSeverity: 1})
	if len(rep.Findings) != 1 {
		t.Fatalf("MinSeverity=1 should drop the info item, got %d findings", len(rep.Findings))
	}
	if rep.Findings[0].Severity == ctis.SeverityInfo {
		t.Fatal("info finding should have been filtered out")
	}
}

func TestConvert_FixedTimestamp(t *testing.T) {
	now := time.Date(2026, 6, 4, 10, 0, 0, 0, time.UTC)
	rep := convert(t, ConvertOptions{ScanSessionID: "x", Now: now})
	if !rep.Metadata.Timestamp.Equal(now) {
		t.Fatalf("expected fixed timestamp, got %v", rep.Metadata.Timestamp)
	}
}

func TestConvert_InvalidXML(t *testing.T) {
	if _, err := Convert(strings.NewReader("not xml at all <<<"), ConvertOptions{}); err == nil {
		t.Fatal("expected error on invalid XML")
	}
}

func TestConvert_EmptyReport(t *testing.T) {
	const empty = `<?xml version="1.0" ?><NessusClientData_v2><Report name="empty"></Report></NessusClientData_v2>`
	rep, err := Convert(strings.NewReader(empty), ConvertOptions{ScanSessionID: "x"})
	if err != nil {
		t.Fatalf("empty report should parse: %v", err)
	}
	if len(rep.Assets) != 0 || len(rep.Findings) != 0 {
		t.Fatalf("expected no assets/findings, got %d/%d", len(rep.Assets), len(rep.Findings))
	}
}
