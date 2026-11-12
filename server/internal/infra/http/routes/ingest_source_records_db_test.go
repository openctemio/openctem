package routes

import (
	"context"
	"net/http"
	"testing"

	"github.com/openctemio/openctem/server/internal/infra/postgres"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
)

// openvasSegment reports the same CVE on the same host and port as
// interopSegment, from another tool, with its own title, text, native
// identity, vendor severity, scores, ids and unmapped fields.
const openvasSegment = `{"version": "2.0",
  "metadata": {"id": "01936f4e-7b8c-7d4e-9f00-0123456789ad", "generated_at": "2026-10-05T09:00:00Z", "channel": "scanner"},
  "tool": {"name": "openvas"},
  "assets": [{"id": "h", "type": "host", "value": "10.20.0.15"}],
  "findings": [{"type": "vulnerability", "title": "OpenSSH 8.5p1 - 9.7p1 RCE", "severity": "critical", "asset_ref": "h",
    "description": "openvas description", "message": "openvas message",
    "network": {"port": 22, "transport": "tcp"},
    "vulnerability": {"ids": [{"type": "cve", "id": "CVE-2024-6387"}, {"type": "vendor", "id": "1.3.6.1.4.1.25623.1.0.114674"}]},
    "native": {"scheme": "openvas", "vuln_id": "1.3.6.1.4.1.25623.1.0.114674", "family": "General", "severity": "8.1"},
    "scores": [{"system": "cvss", "version": "3.1", "value": 8.1, "source": "openvas"}],
    "remediation": {"recommendation": "Update to 9.8p1.", "solution_type": "vendor_fix"},
    "source_extra": {"qod": "80"}}]}`

// The owner rule end to end: two tools report the same finding through
// the real receiver and worker. The finding row keeps the first (primary)
// tool's values; the second tool's values survive in its own source record
// for every field family; the sources disagree on vendor severity, shown
// side by side; another tenant reads nothing.
func TestIngest_SecondSourceSurvives_DB(t *testing.T) {
	h := newV2Harness(t, v2HarnessOpts{})
	ctx := context.Background()
	t.Cleanup(func() {
		for _, q := range []string{`DELETE FROM findings WHERE tenant_id = $1`, `DELETE FROM asset_identifiers WHERE tenant_id = $1`,
			`DELETE FROM assets WHERE tenant_id = $1`, `DELETE FROM audit_logs WHERE tenant_id = $1`} {
			_, _ = h.db.ExecContext(context.Background(), q, h.tenantID)
		}
	})
	pdb := &postgres.DB{DB: h.db}
	if _, err := h.db.ExecContext(ctx, `UPDATE sensors SET
		reported_tools = '[{"name":"semgrep","installed":true},{"name":"nessus","installed":true},{"name":"openvas","installed":true}]',
		reported_tool_names = ARRAY['semgrep','nessus','openvas'], reported_at = NOW()
		WHERE id = $1`, h.sensorID); err != nil {
		t.Fatal(err)
	}
	for _, seg := range []string{interopSegment, openvasSegment} {
		id := newReportID()
		resp, raw := h.do(http.MethodPut, "/api/v2/sensor/results/"+id, []byte(seg))
		h.expect(resp, raw, 202, "")
		h.work(id)
	}

	var findingID, title, nativeID, recommendation string
	var meta []byte
	if err := h.db.QueryRowContext(ctx, `SELECT id, title, COALESCE(native_vuln_id, ''), COALESCE(remediation->>'recommendation', ''), source_meta
		FROM findings WHERE tenant_id = $1 AND cve_id = 'CVE-2024-6387'`, h.tenantID).
		Scan(&findingID, &title, &nativeID, &recommendation, &meta); err != nil {
		t.Fatalf("finding: %v", err)
	}
	// The merged row: the primary tool's values, never the last writer's.
	if title != "OpenSSH regreSSHion" || nativeID != "201194" || recommendation != "Upgrade OpenSSH." {
		t.Errorf("finding row took the second tool's values: title %q native %q recommendation %q", title, nativeID, recommendation)
	}

	repo := postgres.NewFindingRepository(pdb)
	tenant, finding := shared.MustIDFromString(h.tenantID), shared.MustIDFromString(findingID)
	recs, err := repo.ListSourceRecords(ctx, tenant, finding)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("%d source records, want 2: %+v", len(recs), recs)
	}
	nessus, openvas := recs[0], recs[1]
	if nessus.Tool != "nessus" || !nessus.Primary || openvas.Tool != "openvas" || openvas.Primary {
		t.Fatalf("records: %s/%v %s/%v", nessus.Tool, nessus.Primary, openvas.Tool, openvas.Primary)
	}
	if nessus.Channel != "sensor" || nessus.SensorID == nil || nessus.SensorID.String() != h.sensorID {
		t.Errorf("source of the sensor report: %+v", nessus)
	}
	// Every field family of the second source survived.
	o := openvas.Values
	for name, ok := range map[string]bool{
		"title":           o.Title == "OpenSSH 8.5p1 - 9.7p1 RCE",
		"description":     o.Description == "openvas description",
		"recommendation":  o.Recommendation == "Update to 9.8p1.",
		"severity":        o.Severity == "critical",
		"native":          o.Interop.Native != nil && o.Interop.Native.VulnID == "1.3.6.1.4.1.25623.1.0.114674" && o.Interop.Native.Scheme == "openvas" && o.Interop.Native.Family == "General",
		"vendor severity": o.Interop.Native != nil && o.Interop.Native.Severity == "8.1",
		"solution":        o.Interop.Solution != nil && o.Interop.Solution.Type == "vendor_fix",
		"scores":          len(o.Interop.Scores) >= 1 && o.Interop.Scores[0].Source == "openvas",
		"ids":             len(o.Interop.VulnerabilityIDs) == 2,
		"source extra":    o.Interop.SourceExtra["qod"] == "80",
		"location key":    o.Interop.LocationKey == "net:22/tcp",
	} {
		if !ok {
			t.Errorf("second source lost %s: %+v", name, o)
		}
	}
	// And the first source's own record is intact.
	n := nessus.Values
	if n.Title != "OpenSSH regreSSHion" || n.Interop.Native == nil || n.Interop.Native.VulnID != "201194" ||
		n.Interop.Native.Severity != "3" || n.Interop.SourceExtra["plugin_type"] != "remote" || len(n.Interop.Scores) != 5 {
		t.Errorf("first source's record changed: %+v", n)
	}
	fields := map[string]bool{}
	for _, d := range vulnerability.SourceRecordDifferences(recs) {
		fields[d.Field] = true
	}
	for _, want := range []string{"severity", "vendor_severity", "native_id", "title", "solution_type"} {
		if !fields[want] {
			t.Errorf("difference %s not shown", want)
		}
	}

	// A re-run of the first tool keeps one record per source.
	id := newReportID()
	resp, raw := h.do(http.MethodPut, "/api/v2/sensor/results/"+id, []byte(interopSegment))
	h.expect(resp, raw, 202, "")
	h.work(id)
	if recs, _ = repo.ListSourceRecords(ctx, tenant, finding); len(recs) != 2 {
		t.Errorf("%d records after a re-run, want 2", len(recs))
	}

	// Another tenant: not found.
	other := shared.NewID()
	if _, err := repo.ListSourceRecords(ctx, other, finding); err == nil {
		t.Error("another tenant read the finding's source records")
	}
}
