package routes

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/internal/app/ingest"
	"github.com/openctemio/openctem/server/internal/infra/postgres"
)

// Compliance check state from a Nessus import
// (docs/architecture/compliance-checks.md). Synthetic file: a documentation
// address (RFC 5737), a made-up benchmark.

type ccItem struct{ id, result string }

func ccFile(ip string, end time.Time, items ...ccItem) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0"?><NessusClientData_v2 xmlns:cm="http://www.nessus.org/cm">`)
	fmt.Fprintf(&b, `<Policy><policyName>p</policyName><Preferences><ServerPreferences><preference><name>plugin_set</name><value>21157</value></preference></ServerPreferences></Preferences>
<FamilySelection><FamilyItem><FamilyName>Policy Compliance</FamilyName><Status>enabled</Status></FamilyItem></FamilySelection></Policy><Report name="r">`)
	fmt.Fprintf(&b, `<ReportHost name="%s"><HostProperties><tag name="host-ip">%s</tag><tag name="Credentialed_Scan">true</tag><tag name="HOST_START_TIMESTAMP">%d</tag><tag name="HOST_END_TIMESTAMP">%d</tag></HostProperties>`,
		ip, ip, end.Add(-time.Hour).Unix(), end.Unix())
	for _, it := range items {
		fmt.Fprintf(&b, `<ReportItem port="0" svc_name="general" protocol="tcp" severity="3" pluginID="21157" pluginName="Unix Compliance Checks" pluginFamily="Policy Compliance"><description>Example check %[1]s.</description>
<cm:compliance-check-name>%[1]s Ensure example setting %[1]s</cm:compliance-check-name><cm:compliance-check-id>chk-%[1]s</cm:compliance-check-id><cm:compliance-control-id>%[1]s</cm:compliance-control-id>
<cm:compliance-benchmark-name>CIS Example Linux</cm:compliance-benchmark-name><cm:compliance-benchmark-version>1.0.0</cm:compliance-benchmark-version><cm:compliance-benchmark-profile>Level 1 - Server</cm:compliance-benchmark-profile>
<cm:compliance-policy-value>1</cm:compliance-policy-value><cm:compliance-actual-value>value-%[2]s</cm:compliance-actual-value><cm:compliance-result>%[2]s</cm:compliance-result></ReportItem>`, it.id, it.result)
	}
	b.WriteString(`</ReportHost></Report></NessusClientData_v2>`)
	return b.String()
}

// Every result is the state of its control; only FAILED and WARNING are
// findings; ERROR keeps its own state; a later PASSED resolves the failure,
// keeps its link and appends history; nothing is deleted.
func TestComplianceChecks_NessusImport_DB(t *testing.T) {
	ih := newImportHarness(t, ingest.SourceResolveDryRun)
	ih.ingest.SetComplianceCheckRecorder(postgres.NewComplianceCheckRepository(&postgres.DB{DB: ih.db}))
	const ip = "192.0.2.91"
	t1 := time.Date(2025, 11, 1, 0, 0, 0, 0, time.UTC)

	r := ih.nsUpload(t, "", true, ccFile(ip, t1,
		ccItem{"1.1", "FAILED"}, ccItem{"1.2", "PASSED"}, ccItem{"1.3", "WARNING"}, ccItem{"1.4", "ERROR"}, ccItem{"1.5", "SKIPPED"}))
	if r.Outcomes["compliance_passed"] != 1 || r.Outcomes["compliance_state"] != 2 {
		t.Fatalf("outcomes = %+v", r.Outcomes)
	}
	if n := ih.count(t, `SELECT count(*) FROM findings WHERE tenant_id = $1 AND finding_type = 'compliance'`, ih.tenantID); n != 2 {
		t.Fatalf("%d compliance findings, want 2 (failed and warning)", n)
	}
	if n := ih.count(t, `SELECT count(*) FROM findings WHERE tenant_id = $1 AND finding_type = 'compliance' AND compliance_level = 1`, ih.tenantID); n != 2 {
		t.Fatalf("%d findings carry level 1", n)
	}
	results := ccResults(t, ih)
	want := map[string]string{"1.1": "fail", "1.2": "pass", "1.3": "manual", "1.4": "error", "1.5": "not_applicable"}
	for c, res := range want {
		if results[c] != res {
			t.Fatalf("states = %v, want %v", results, want)
		}
	}
	if n := ih.count(t, `SELECT count(*) FROM compliance_check_states s JOIN findings f ON f.id = s.finding_id
		WHERE s.tenant_id = $1 AND s.control_id = '1.1' AND f.compliance_result = 'fail'`, ih.tenantID); n != 1 {
		t.Fatal("the failed state does not link its finding")
	}
	if n := ih.count(t, `SELECT count(*) FROM compliance_check_states WHERE tenant_id = $1 AND control_id = '1.1'
		AND evidence->>'actual' = 'value-FAILED' AND evidence->>'expected' = '1' AND scanner_severity = 'high'`, ih.tenantID); n != 1 {
		t.Fatal("the state lost its evidence or the scanner's severity")
	}

	// A later scan: the failure passes.
	t2 := t1.Add(24 * time.Hour)
	r = ih.nsUpload(t, "", true, ccFile(ip, t2, ccItem{"1.1", "PASSED"}))
	// The warning absent from this file is kept: a compliance result
	// never closes by absence.
	wantClosing(t, r, 2, map[string]int{"compliance_passed": 1}, map[string]int{"guard": 1})
	if n := ih.count(t, `SELECT count(*) FROM findings WHERE tenant_id = $1 AND finding_type = 'compliance' AND status = 'resolved'`, ih.tenantID); n != 1 {
		t.Fatal("the passed check did not resolve its finding")
	}
	if n := ih.count(t, `SELECT count(*) FROM compliance_check_states WHERE tenant_id = $1 AND control_id = '1.1'
		AND result = 'pass' AND finding_id IS NOT NULL`, ih.tenantID); n != 1 {
		t.Fatal("the passed state lost its finding link")
	}
	if n := ih.count(t, `SELECT count(*) FROM compliance_check_results h JOIN compliance_check_states s ON s.id = h.state_id
		WHERE s.tenant_id = $1 AND s.control_id = '1.1'`, ih.tenantID); n != 2 {
		t.Fatalf("history of 1.1 has %d rows, want 2", n)
	}
	if n := ih.count(t, `SELECT count(*) FROM compliance_check_results h JOIN compliance_check_states s ON s.id = h.state_id
		WHERE s.tenant_id = $1 AND s.control_id = '1.1' AND h.result = 'fail' AND h.evidence->>'actual' = 'value-FAILED'`, ih.tenantID); n != 1 {
		t.Fatal("the failure's evidence is not kept in the history")
	}
}

func ccResults(t *testing.T, ih *importHarness) map[string]string {
	t.Helper()
	results := map[string]string{}
	rows, err := ih.db.QueryContext(context.Background(), `SELECT control_id, result FROM compliance_check_states WHERE tenant_id = $1`, ih.tenantID)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var c, res string
		if err := rows.Scan(&c, &res); err != nil {
			t.Fatal(err)
		}
		results[c] = res
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return results
}
