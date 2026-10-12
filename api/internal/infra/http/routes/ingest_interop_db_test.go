package routes

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// interopSegment is a CTIS 1.4 report as a Nessus import would send it: the
// CVE only in vulnerability.ids, the plugin ID only in native.vuln_id, CVSS
// v3.1 and v4.0 together, VPR, EPSS and SSVC, the source lifecycle, solution
// metadata, unmapped fields, identity hints and a VEX statement.
const interopSegment = `{
  "version": "1.4",
  "metadata": {"timestamp": "2026-10-05T08:00:00Z"},
  "tool": {"name": "nessus"},
  "assets": [{"id": "db01", "type": "host", "value": "10.20.0.15",
    "identity_hints": {"fqdn": "db01.corp.example.com", "netbios_name": "DB01",
      "os_cpe": "cpe:/o:canonical:ubuntu_linux:22.04", "agent_id": "9f3c2a1e-6d7b-4b8e-a1f0-2c4d5e6f7a8b"}}],
  "findings": [
    {"type": "vulnerability", "title": "OpenSSH regreSSHion", "severity": "high", "asset_ref": "db01",
     "network": {"port": 22, "protocol": "tcp", "service": "ssh"},
     "vulnerability": {"cvss_version": "3.1", "cvss_score": 8.1, "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", "cvss_source": "nvd",
       "ids": [{"type": "cve", "id": "CVE-2024-6387"}, {"type": "vendor", "id": "USN-6859-1", "source": "ubuntu"}]},
     "native": {"scheme": "nessus", "vuln_id": "201194", "family": "Misc.", "severity": "3", "status": "reopened",
       "detection_type": "confirmed", "credentialed": true, "raw_ref": "ReportHost[10.20.0.15]/ReportItem[201194:22:tcp]"},
     "scores": [
       {"system": "cvss", "version": "4.0", "vector": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "value": 9.2, "source": "vendor"},
       {"system": "vpr", "value": 7.4, "source": "tenable"},
       {"system": "epss", "value": 0.42, "source": "first"},
       {"system": "ssvc", "version": "2", "vector": "SSVCv2/E:P/A:N/T:T/", "label": "Attend", "source": "cisa"}],
     "source_lifecycle": {"first_found": "2024-07-03T10:00:00Z", "last_found": "2026-10-05T07:55:00Z", "times_found": 41, "state": "reopened"},
     "remediation": {"recommendation": "Upgrade OpenSSH.", "solution_type": "upgrade", "patch_published_at": "2024-07-01T00:00:00Z",
       "advisories": [{"id": "USN-6859-1", "url": "https://ubuntu.com/security/notices/USN-6859-1"}]},
     "source_extra": {"plugin_type": "remote"}},
    {"type": "vulnerability", "title": "liblzma backdoor", "severity": "critical", "asset_ref": "db01",
     "vulnerability": {"package": "xz-utils", "purl": "pkg:deb/ubuntu/xz-utils@5.6.0", "ids": [{"type": "cve", "id": "CVE-2024-3094"}]},
     "vex": {"status": "not_affected", "justification": "vulnerable_code_not_in_execute_path", "native_justification": "code_not_reachable",
       "statement": "sshd is not linked against liblzma.", "source": "https://vex.example.com/xz.cdx.json"}}
  ]
}`

// A CTIS 1.4 report goes through the real protocol v2 receiver and worker
// into the database: the CVE from vulnerability.ids keys and labels the
// finding, the native id becomes its rule, every score and the VEX statement
// are stored, the asset keeps its identity hints, and the default VEX mode
// (dry_run, report not command-bound) closes nothing. Then a 1.3 report of
// the same CVE from another tool lands on the same finding.
func TestIngest_CTIS14Interop_DB(t *testing.T) {
	h := newV2Harness(t, v2HarnessOpts{})
	ctx := context.Background()
	t.Cleanup(func() {
		for _, q := range []string{`DELETE FROM findings WHERE tenant_id = $1`, `DELETE FROM asset_identifiers WHERE tenant_id = $1`,
			`DELETE FROM assets WHERE tenant_id = $1`, `DELETE FROM audit_logs WHERE tenant_id = $1`} {
			_, _ = h.db.ExecContext(context.Background(), q, h.tenantID)
		}
	})

	// Asset identity matching, wired as the server wires it.
	pdb := &postgres.DB{DB: h.db}
	h.ingest.SetIdentityStore(postgres.NewAssetIdentifierRepository(pdb, postgres.NewAssetRepository(pdb)),
		postgres.NewAssetDedupRepository(pdb))

	// The harness sensor reports semgrep; this one also runs the two VA tools.
	if _, err := h.db.ExecContext(ctx, `UPDATE sensors SET
		reported_tools = '[{"name":"semgrep","installed":true},{"name":"nessus","installed":true},{"name":"openvas","installed":true}]',
		reported_tool_names = ARRAY['semgrep','nessus','openvas'], reported_at = NOW()
		WHERE id = $1`, h.sensorID); err != nil {
		t.Fatal(err)
	}

	id := newReportID()
	resp, raw := h.do(http.MethodPut, "/api/v2/sensor/results/"+id, []byte(interopSegment))
	h.expect(resp, raw, 202, "")
	h.work(id)

	var findingID, cve, rule, status, nativeID, loc string
	var scores, vids, meta []byte
	if err := h.db.QueryRow(`SELECT id, COALESCE(cve_id, ''), COALESCE(rule_id, ''), status, COALESCE(native_vuln_id, ''),
			COALESCE(location_key, ''), scores, vulnerability_ids, source_meta
		FROM findings WHERE tenant_id = $1 AND title = 'OpenSSH regreSSHion'`, h.tenantID).
		Scan(&findingID, &cve, &rule, &status, &nativeID, &loc, &scores, &vids, &meta); err != nil {
		t.Fatalf("network finding not stored: %v", err)
	}
	if cve != "CVE-2024-6387" || rule != "201194" || nativeID != "201194" || loc != "net:22/tcp" {
		t.Errorf("cve %q rule %q native %q location %q", cve, rule, nativeID, loc)
	}
	var gotScores []map[string]any
	_ = json.Unmarshal(scores, &gotScores)
	if len(gotScores) != 5 {
		t.Fatalf("scores = %s (want 4 sent + the legacy CVSS 3.1)", scores)
	}
	systems := map[string]bool{}
	for _, s := range gotScores {
		systems[s["system"].(string)+":"+stringOr(s["version"])] = true
	}
	for _, want := range []string{"cvss:4.0", "cvss:3.1", "vpr:", "epss:", "ssvc:2"} {
		if !systems[want] {
			t.Errorf("score %s missing from %s", want, scores)
		}
	}

	repo := postgres.NewFindingRepository(pdb)
	d, err := repo.GetInterop(ctx, shared.MustIDFromString(h.tenantID), shared.MustIDFromString(findingID))
	if err != nil || d == nil {
		t.Fatalf("GetInterop: %v %v", d, err)
	}
	if d.Native == nil || d.Native.Severity != "3" || d.Native.Credentialed == nil || !*d.Native.Credentialed ||
		d.Lifecycle == nil || d.Lifecycle.TimesFound != 41 || d.Solution == nil || d.Solution.Type != "upgrade" ||
		d.SourceExtra["plugin_type"] != "remote" || len(d.VulnerabilityIDs) != 2 {
		t.Errorf("interop data = %+v", d)
	}

	var vexStatus, vexJust, pkgStatus string
	if err := h.db.QueryRow(`SELECT COALESCE(vex_status, ''), COALESCE(vex_justification, ''), status
		FROM findings WHERE tenant_id = $1 AND title = 'liblzma backdoor'`, h.tenantID).Scan(&vexStatus, &vexJust, &pkgStatus); err != nil {
		t.Fatalf("package finding not stored: %v", err)
	}
	if vexStatus != "not_affected" || vexJust != "vulnerable_code_not_in_execute_path" {
		t.Errorf("vex %q / %q", vexStatus, vexJust)
	}
	if pkgStatus == "false_positive" {
		t.Error("dry_run (the default) closed a finding")
	}

	var hints []byte
	if err := h.db.QueryRow(`SELECT properties->'identity_hints' FROM assets WHERE tenant_id = $1 AND name = '10.20.0.15'`,
		h.tenantID).Scan(&hints); err != nil {
		t.Fatalf("asset: %v", err)
	}
	var hm map[string]any
	_ = json.Unmarshal(hints, &hm)
	if hm["agent_id"] != "9f3c2a1e-6d7b-4b8e-a1f0-2c4d5e6f7a8b" || hm["netbios_name"] != "DB01" {
		t.Errorf("identity hints = %s", hints)
	}
	var fqdnIDs int
	if err := h.db.QueryRow(`SELECT count(*) FROM asset_identifiers WHERE tenant_id = $1 AND kind = 'fqdn' AND value = 'db01.corp.example.com'`,
		h.tenantID).Scan(&fqdnIDs); err != nil {
		t.Fatal(err)
	}
	if fqdnIDs != 1 {
		t.Errorf("the FQDN hint was not recorded as an identifier (%d rows)", fqdnIDs)
	}

	// Another tool (1.3, no interop members) reports the same CVE on the same
	// host and port: one finding, not two.
	legacy := `{"version": "1.3", "metadata": {"timestamp": "2026-10-05T09:00:00Z"}, "tool": {"name": "openvas"},
	  "assets": [{"id": "h", "type": "host", "value": "10.20.0.15"}],
	  "findings": [{"type": "vulnerability", "title": "OpenSSH race", "severity": "high", "asset_ref": "h", "rule_id": "1.3.6.1.4.1.25623",
	    "network": {"port": 22, "protocol": "tcp"}, "vulnerability": {"cve_id": "CVE-2024-6387"}}]}`
	id2 := newReportID()
	resp, raw = h.do(http.MethodPut, "/api/v2/sensor/results/"+id2, []byte(legacy))
	h.expect(resp, raw, 202, "")
	h.work(id2)
	var n int
	if err := h.db.QueryRow(`SELECT count(*) FROM findings WHERE tenant_id = $1 AND cve_id = 'CVE-2024-6387'`, h.tenantID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("%d findings for CVE-2024-6387 on one host and port, want 1 (cross-tool correlation)", n)
	}
	// The second sighting carried no native identity; the first one's stays.
	if err := h.db.QueryRow(`SELECT COALESCE(native_vuln_id, '') FROM findings WHERE id = $1`, findingID).Scan(&nativeID); err != nil || nativeID != "201194" {
		t.Errorf("native id after a 1.3 sighting: %q %v", nativeID, err)
	}
}

func stringOr(v any) string {
	s, _ := v.(string)
	return s
}
