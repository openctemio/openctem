package routes

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	evidenceapp "github.com/openctemio/openctem/api/internal/app/evidence"
	"github.com/openctemio/openctem/api/internal/app/findingimport"
	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// What a Nessus import closes (docs/architecture/finding-import.md, "What a
// Nessus import closes"): the file's own coverage decides, per host and
// check, with no declaration from the uploader. Synthetic files only:
// documentation addresses (RFC 5737), made-up plugin ids.

// Scan ends, one day apart, in the past.
var (
	nsT1 = time.Date(2025, 11, 1, 0, 0, 0, 0, time.UTC)
	nsT2 = nsT1.Add(24 * time.Hour)
	nsT3 = nsT2.Add(24 * time.Hour)
	nsT4 = nsT3.Add(24 * time.Hour)
)

type nsItem struct {
	plugin, family string
	severity       int
	port           int
	// compliance result (PASSED, FAILED, WARNING, ERROR) of check 0c1;
	// empty for a plugin result.
	result string
	// output is the plugin output (evidence).
	output string
}

type nsHost struct {
	ip           string
	end          time.Time // zero: the host's scan did not finish
	credentialed bool
	authFailed   bool
	items        []nsItem
}

// The checks a scan ran: three network plugins, the Ubuntu local family and
// compliance. noPolicy leaves the plugin selection out (the file then proves
// nothing).
func nessusFile(noPolicy bool, plugins string, hosts ...nsHost) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0"?><NessusClientData_v2 xmlns:cm="http://www.nessus.org/cm">`)
	if !noPolicy {
		fmt.Fprintf(&b, `<Policy><policyName>p</policyName><Preferences><ServerPreferences><preference><name>plugin_set</name><value>%s</value></preference></ServerPreferences></Preferences>
<FamilySelection><FamilyItem><FamilyName>Ubuntu Local Security Checks</FamilyName><Status>enabled</Status></FamilyItem><FamilyItem><FamilyName>Policy Compliance</FamilyName><Status>enabled</Status></FamilyItem></FamilySelection></Policy>`, plugins)
	}
	b.WriteString(`<Report name="r">`)
	for _, h := range hosts {
		start := nsT1.Add(-time.Hour)
		if !h.end.IsZero() {
			start = h.end.Add(-time.Hour)
		}
		fmt.Fprintf(&b, `<ReportHost name="%s"><HostProperties><tag name="host-ip">%s</tag><tag name="Credentialed_Scan">%t</tag><tag name="HOST_START_TIMESTAMP">%d</tag>`,
			h.ip, h.ip, h.credentialed, start.Unix())
		if !h.end.IsZero() {
			fmt.Fprintf(&b, `<tag name="HOST_END_TIMESTAMP">%d</tag>`, h.end.Unix())
		}
		b.WriteString(`</HostProperties>`)
		if h.authFailed {
			b.WriteString(`<ReportItem port="0" svc_name="general" protocol="tcp" severity="0" pluginID="21745" pluginName="OS Security Patch Assessment Failed" pluginFamily="Settings"><description>Local checks did not run.</description></ReportItem>`)
		}
		for _, it := range h.items {
			if it.result != "" {
				fmt.Fprintf(&b, `<ReportItem port="0" svc_name="general" protocol="tcp" severity="2" pluginID="21157" pluginName="Unix Compliance Checks" pluginFamily="Policy Compliance"><description>Example check.</description>
<cm:compliance-check-name>1.1 Ensure example setting</cm:compliance-check-name><cm:compliance-check-id>0c1</cm:compliance-check-id><cm:compliance-result>%s</cm:compliance-result></ReportItem>`, it.result)
				continue
			}
			out := ""
			if it.output != "" {
				out = "<plugin_output>" + it.output + "</plugin_output>"
			}
			fmt.Fprintf(&b, `<ReportItem port="%d" svc_name="general" protocol="tcp" severity="%d" pluginID="%s" pluginName="Example %s" pluginFamily="%s"><description>Example issue %s.</description><solution>Upgrade.</solution>%s</ReportItem>`,
				it.port, it.severity, it.plugin, it.plugin, it.family, it.plugin, out)
		}
		b.WriteString(`</ReportHost>`)
	}
	b.WriteString(`</Report></NessusClientData_v2>`)
	return b.String()
}

const nsPlugins = "7001;7002;7003;21157"

var (
	nsNet1  = nsItem{plugin: "7001", family: "General", severity: 2, port: 443}
	nsNet2  = nsItem{plugin: "7002", family: "General", severity: 2, port: 80}
	nsNet3  = nsItem{plugin: "7003", family: "General", severity: 1, port: 22}
	nsCrit  = nsItem{plugin: "7002", family: "General", severity: 4, port: 80}
	nsLocal = nsItem{plugin: "8001", family: "Ubuntu Local Security Checks", severity: 2}
)

func nsPerms(verify bool) []string {
	p := []string{permission.FindingsWrite.String(), permission.AssetsWrite.String(), permission.AssetsImport.String()}
	if verify {
		p = append(p, permission.FindingsVerify.String())
	}
	return p
}

type nsState struct{ status, resolvedAt, lastSeen string }

// state of the tenant's finding of plugin on ip (rule id; compliance by check id).
func (ih *importHarness) nsFinding(t *testing.T, tenant, ip, rule string) nsState {
	t.Helper()
	var s nsState
	err := ih.db.QueryRowContext(context.Background(), `SELECT f.status, COALESCE(to_char(f.resolved_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI'), ''),
		to_char(f.last_seen_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI')
		FROM findings f JOIN assets a ON a.id = f.asset_id AND a.tenant_id = f.tenant_id
		WHERE f.tenant_id = $1 AND a.name = $2 AND f.rule_id = $3`, tenant, ip, rule).Scan(&s.status, &s.resolvedAt, &s.lastSeen)
	if err != nil {
		t.Fatalf("finding %s %s: %v", ip, rule, err)
	}
	return s
}

func nsAt(ts time.Time) string { return ts.UTC().Format("2006-01-02T15:04") }

func (ih *importHarness) nsUpload(t *testing.T, query string, verify bool, doc string) *handler.ReceiptResponse {
	t.Helper()
	rec, resp := ih.uploadAs(t, query, nsPerms(verify), doc)
	if rec.Code != http.StatusAccepted || resp.Receipt == nil {
		t.Fatalf("upload %d %s", rec.Code, rec.Body.String())
	}
	return resp.Receipt
}

func wantClosing(t *testing.T, r *handler.ReceiptResponse, considered int, closed, kept map[string]int) {
	t.Helper()
	c := r.Closing
	if c == nil {
		t.Fatalf("no closing on the receipt: %+v", r)
	}
	n := c.Proposed
	for _, v := range c.Closed {
		n += v
	}
	for _, v := range c.Kept {
		n += v
	}
	if n != c.Considered {
		t.Fatalf("closing does not reconcile: %+v", c)
	}
	if c.Considered != considered {
		t.Fatalf("considered = %d, want %d (%+v)", c.Considered, considered, c)
	}
	for k, v := range closed {
		if c.Closed[k] != v {
			t.Fatalf("closed[%s] = %d, want %d (%+v)", k, c.Closed[k], v, c)
		}
	}
	for k, v := range kept {
		if c.Kept[k] != v {
			t.Fatalf("kept[%s] = %d, want %d (%+v)", k, c.Kept[k], v, c)
		}
	}
}

// A complete file closes, without any declaration, the open findings of its
// hosts it no longer reports, dated when it scanned the host; last seen is
// the file's time, never the upload's.
func TestNessusClose_FileCoverageClosesWithoutDeclaration_DB(t *testing.T) {
	ih := newImportHarness(t, ingest.SourceResolveDryRun)
	const ip = "192.0.2.81"
	ih.nsUpload(t, "", true, nessusFile(false, nsPlugins, nsHost{ip: ip, end: nsT1, credentialed: true, items: []nsItem{nsNet1, nsNet2}}))
	if s := ih.nsFinding(t, ih.tenantID, ip, "7002"); s.lastSeen != nsAt(nsT1) {
		t.Fatalf("last seen = %s, want the file's %s", s.lastSeen, nsAt(nsT1))
	}
	r := ih.nsUpload(t, "", true, nessusFile(false, nsPlugins, nsHost{ip: ip, end: nsT2, credentialed: true, items: []nsItem{nsNet1}}))
	wantClosing(t, r, 1, map[string]int{"not_in_scan": 1}, nil)
	if r.Coverage.Type != "full" || r.Coverage.Note != "resolved" || r.Counts.Closed != 1 {
		t.Fatalf("receipt = %+v", r)
	}
	if s := ih.nsFinding(t, ih.tenantID, ip, "7002"); s.status != "resolved" || s.resolvedAt != nsAt(nsT2) {
		t.Fatalf("7002 = %+v, want resolved at the scan end %s", s, nsAt(nsT2))
	}
	if s := ih.nsFinding(t, ih.tenantID, ip, "7001"); s.status == "resolved" || s.lastSeen != nsAt(nsT2) {
		t.Fatalf("7001 = %+v", s)
	}
}

// The guards: no findings:verify closes nothing; a critical finding stays;
// an upload that dropped records (min_severity) proves nothing; a file
// without a plugin selection proves nothing.
func TestNessusClose_Guards_DB(t *testing.T) {
	ih := newImportHarness(t, ingest.SourceResolveDryRun)
	const ip = "192.0.2.82"
	ih.nsUpload(t, "", true, nessusFile(false, nsPlugins, nsHost{ip: ip, end: nsT1, credentialed: true, items: []nsItem{nsNet1, nsCrit, nsNet3}}))
	later := nessusFile(false, nsPlugins, nsHost{ip: ip, end: nsT2, credentialed: true, items: []nsItem{nsNet1}})

	r := ih.nsUpload(t, "", false, later)
	wantClosing(t, r, 2, nil, map[string]int{"needs_verify": 1, "guard": 1})
	if r.Coverage.Note != "needs_verify" || r.Counts.Closed != 0 {
		t.Fatalf("receipt = %+v", r)
	}
	r = ih.nsUpload(t, "?min_severity=low", true, later)
	wantClosing(t, r, 2, nil, map[string]int{"file_incomplete": 2})
	r = ih.nsUpload(t, "", true, nessusFile(true, "", nsHost{ip: ip, end: nsT2, credentialed: true, items: []nsItem{nsNet1}}))
	wantClosing(t, r, 2, nil, map[string]int{"file_incomplete": 2})
	if s := ih.nsFinding(t, ih.tenantID, ip, "7003"); s.status == "resolved" {
		t.Fatal("an incomplete upload closed a finding")
	}

	r = ih.nsUpload(t, "", true, later)
	wantClosing(t, r, 2, map[string]int{"not_in_scan": 1}, map[string]int{"guard": 1})
	if s := ih.nsFinding(t, ih.tenantID, ip, "7002"); s.status == "resolved" {
		t.Fatal("a critical finding was closed by a file")
	}
	if s := ih.nsFinding(t, ih.tenantID, ip, "7003"); s.status != "resolved" {
		t.Fatalf("7003 = %+v", s)
	}
}

// A host whose scan did not finish, a local check on a host the scan could
// not log in to, and a check the scan did not run, close nothing; the
// receipt counts the hosts the import could not log in to.
func TestNessusClose_HostAndCheckCoverage_DB(t *testing.T) {
	ih := newImportHarness(t, ingest.SourceResolveDryRun)
	const a, b = "192.0.2.83", "192.0.2.84"
	ih.nsUpload(t, "", true, nessusFile(false, nsPlugins,
		nsHost{ip: a, end: nsT1, credentialed: true, items: []nsItem{nsNet1, nsNet2}},
		nsHost{ip: b, end: nsT1, credentialed: true, items: []nsItem{nsNet1, nsNet3, nsLocal}}))

	// a: unfinished. b: authentication failed (the local check stays, the
	// network check closes); 7001 is no longer in the plugin selection.
	r := ih.nsUpload(t, "", true, nessusFile(false, "7002;7003",
		nsHost{ip: a, credentialed: true},
		nsHost{ip: b, end: nsT2, credentialed: false, authFailed: true}))
	wantClosing(t, r, 5, map[string]int{"not_in_scan": 1},
		map[string]int{"host_not_finished": 2, "local_checks_not_run": 1, "check_not_run": 1})
	if r.Closing.HostsLocalChecksFailed != 1 || r.Closing.HostsUnfinished != 1 || r.Closing.Hosts != 2 {
		t.Fatalf("hosts = %+v", r.Closing)
	}
	for _, c := range []struct{ ip, rule, status string }{{a, "7001", "new"}, {a, "7002", "new"}, {b, "8001", "new"}, {b, "7001", "new"}, {b, "7003", "resolved"}} {
		if s := ih.nsFinding(t, ih.tenantID, c.ip, c.rule); (s.status == "resolved") != (c.status == "resolved") {
			t.Fatalf("%s %s = %+v", c.ip, c.rule, s)
		}
	}
}

// Files arrive out of order: an older file never closes what a newer one
// saw, never reopens what was closed after it, and never moves last seen
// back; a newer one reopens. The same file twice gives the same result.
func TestNessusClose_TimeOrderingAndIdempotence_DB(t *testing.T) {
	ih := newImportHarness(t, ingest.SourceResolveDryRun)
	const ip = "192.0.2.85"
	with := func(at time.Time) string {
		return nessusFile(false, nsPlugins, nsHost{ip: ip, end: at, credentialed: true, items: []nsItem{nsNet1, nsNet2}})
	}
	without := func(at time.Time) string {
		return nessusFile(false, nsPlugins, nsHost{ip: ip, end: at, credentialed: true, items: []nsItem{nsNet1}})
	}
	ih.nsUpload(t, "", true, with(nsT2))
	// Older file without the finding: seen later, kept.
	r := ih.nsUpload(t, "", true, without(nsT1))
	wantClosing(t, r, 1, nil, map[string]int{"seen_later": 1})
	if s := ih.nsFinding(t, ih.tenantID, ip, "7002"); s.status == "resolved" || s.lastSeen != nsAt(nsT2) {
		t.Fatalf("after an older file: %+v", s)
	}
	// Newer file without it closes it at T3; importing it again changes nothing.
	ih.nsUpload(t, "", true, without(nsT3))
	first := ih.nsFinding(t, ih.tenantID, ip, "7002")
	r = ih.nsUpload(t, "", true, without(nsT3))
	wantClosing(t, r, 0, nil, nil)
	if again := ih.nsFinding(t, ih.tenantID, ip, "7002"); again != first || first.status != "resolved" || first.resolvedAt != nsAt(nsT3) {
		t.Fatalf("same file twice: %+v then %+v", first, again)
	}
	// An older file that still had it (T2 < T3) does not reopen it.
	ih.nsUpload(t, "", true, with(nsT2))
	if s := ih.nsFinding(t, ih.tenantID, ip, "7002"); s.status != "resolved" || s.lastSeen != nsAt(nsT2) {
		t.Fatalf("an older file reopened or moved last seen: %+v", s)
	}
	// A newer one does.
	ih.nsUpload(t, "", true, with(nsT4))
	if s := ih.nsFinding(t, ih.tenantID, ip, "7002"); s.status == "resolved" || s.lastSeen != nsAt(nsT4) {
		t.Fatalf("a newer file did not reopen: %+v", s)
	}
}

// A PASSED compliance result resolves the open FAILED finding of the same
// host and check; WARNING and ERROR never do, nor an older PASSED.
func TestNessusClose_CompliancePassed_DB(t *testing.T) {
	ih := newImportHarness(t, ingest.SourceResolveDryRun)
	const ip = "192.0.2.86"
	file := func(at time.Time, result string) string {
		return nessusFile(false, nsPlugins, nsHost{ip: ip, end: at, credentialed: true, items: []nsItem{nsNet1, {result: result}}})
	}
	ih.nsUpload(t, "", true, file(nsT2, "FAILED"))
	for _, res := range []string{"WARNING", "ERROR"} {
		ih.nsUpload(t, "", true, file(nsT3, res))
		if s := ih.nsFinding(t, ih.tenantID, ip, "0c1"); s.status == "resolved" {
			t.Fatalf("%s resolved the failure", res)
		}
	}
	r := ih.nsUpload(t, "", true, file(nsT1, "PASSED"))
	wantClosing(t, r, 1, nil, map[string]int{"seen_later": 1})
	r = ih.nsUpload(t, "", true, file(nsT4, "PASSED"))
	wantClosing(t, r, 1, map[string]int{"compliance_passed": 1}, nil)
	if s := ih.nsFinding(t, ih.tenantID, ip, "0c1"); s.status != "resolved" || s.resolvedAt != nsAt(nsT4) {
		t.Fatalf("PASSED did not resolve: %+v", s)
	}
	if n := ih.count(t, `SELECT count(*) FROM findings WHERE tenant_id = $1 AND compliance_result = 'pass'`, ih.tenantID); n != 0 {
		t.Fatalf("%d passed checks stored as findings", n)
	}
	if r.Outcomes["compliance_passed"] != 1 {
		t.Fatalf("outcomes = %+v", r.Outcomes)
	}
}

// A file never touches another tenant's findings, nor a host outside the
// uploader's scope.
func TestNessusClose_TenantAndScopeIsolation_DB(t *testing.T) {
	other := newImportHarness(t, ingest.SourceResolveDryRun)
	ih := newImportHarness(t, ingest.SourceResolveDryRun)
	const ip = "192.0.2.87"
	first := nessusFile(false, nsPlugins, nsHost{ip: ip, end: nsT1, credentialed: true, items: []nsItem{nsNet1, nsNet2, {result: "FAILED"}}})
	later := nessusFile(false, nsPlugins, nsHost{ip: ip, end: nsT2, credentialed: true, items: []nsItem{nsNet1, {result: "PASSED"}}})
	other.nsUpload(t, "", true, first)
	ih.nsUpload(t, "", true, first)

	// A restricted uploader whose scope does not hold the host closes nothing.
	ih.h.SetActorResolver(func(context.Context, shared.ID) (ingest.ActorScope, error) { return onlyScope{}, nil })
	ih.wire(ih.svc, func(context.Context, shared.ID, findingimport.Caller) (ingest.ActorScope, ingest.ActorScope, error) {
		return onlyScope{}, onlyScope{}, nil
	})
	r := ih.nsUpload(t, "", true, later)
	wantClosing(t, r, 0, nil, nil)
	if s := ih.nsFinding(t, ih.tenantID, ip, "7002"); s.status == "resolved" {
		t.Fatal("a host outside the uploader's scope was closed")
	}
	ih.wire(ih.svc, nil)
	ih.h.SetActorResolver(func(context.Context, shared.ID) (ingest.ActorScope, error) { return nil, nil })

	r = ih.nsUpload(t, "", true, later)
	wantClosing(t, r, 2, map[string]int{"not_in_scan": 1, "compliance_passed": 1}, nil)
	for _, rule := range []string{"7002", "0c1"} {
		if s := other.nsFinding(t, other.tenantID, ip, rule); s.status == "resolved" {
			t.Fatalf("another tenant's %s was closed", rule)
		}
		if s := ih.nsFinding(t, ih.tenantID, ip, rule); s.status != "resolved" {
			t.Fatalf("%s = %+v", rule, s)
		}
	}
}

// No information is lost: each sighting's evidence (the plugin output of
// every file) stays on the finding after a later file sees it again and
// after a file closes it, and the timeline says why it closed.
func TestNessusClose_KeepsEverySightingsEvidence_DB(t *testing.T) {
	ih := newImportHarness(t, ingest.SourceResolveDryRun)
	cipher, err := crypto.NewCipher([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	ih.ingest.SetEvidenceStore(evidenceapp.NewService(postgres.NewFindingEvidenceRepository(&postgres.DB{DB: ih.db}),
		cipher, nil, nil, nil, logger.NewNop()))
	const ip = "192.0.2.88"
	file := func(at time.Time, out string) string {
		items := []nsItem{nsNet1}
		if out != "" {
			items = append(items, nsItem{plugin: "7002", family: "General", severity: 2, port: 80, output: out})
		}
		return nessusFile(false, nsPlugins, nsHost{ip: ip, end: at, credentialed: true, items: items})
	}
	ih.nsUpload(t, "", true, file(nsT1, "Example banner from the first scan"))
	ih.nsUpload(t, "", true, file(nsT2, "Example banner from the second scan"))
	var id string
	if err := ih.db.QueryRowContext(context.Background(), `SELECT f.id::text FROM findings f JOIN assets a ON a.id = f.asset_id
		WHERE f.tenant_id = $1 AND a.name = $2 AND f.rule_id = '7002'`, ih.tenantID, ip).Scan(&id); err != nil {
		t.Fatal(err)
	}
	evidence := func() int {
		return ih.count(t, `SELECT count(*) FROM finding_evidence WHERE tenant_id = $1 AND finding_id = $2`, ih.tenantID, id)
	}
	if n := evidence(); n != 2 {
		t.Fatalf("%d evidence records after two sightings, want one per sighting", n)
	}
	r := ih.nsUpload(t, "", true, file(nsT3, ""))
	wantClosing(t, r, 1, map[string]int{"not_in_scan": 1}, nil)
	if n := evidence(); n != 2 {
		t.Fatalf("closing left %d evidence records, want 2", n)
	}
	if n := ih.count(t, `SELECT count(*) FROM findings WHERE tenant_id = $1 AND id = $2 AND status = 'resolved'
		AND source_meta->'native'->>'family' = 'General' AND native_vuln_id = '7002'`, ih.tenantID, id); n != 1 {
		t.Fatal("the closed finding lost its source data")
	}
	if n := ih.count(t, `SELECT count(*) FROM finding_activities WHERE tenant_id = $1 AND finding_id = $2
		AND activity_type = 'auto_resolved' AND changes::text LIKE '%not_in_scan_file%'`, ih.tenantID, id); n != 1 {
		t.Fatal("the timeline does not say why the finding closed")
	}
}
