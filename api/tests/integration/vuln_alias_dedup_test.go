package integration

// Canonical vulnerability ids across tools (RFC-043 §17.2): a finding that
// names only an advisory id (GHSA, OSV) is keyed on the CVE the signed feed
// ties it to, so it meets the same finding from a tool that names the CVE.
// A finding stored under the advisory key keeps its triage when it takes the
// CVE key; a CVE key another finding already holds links the two, never
// merges them. A report's own ids never canonicalise another finding, and
// an advisory that leads to two CVEs fuses nothing.

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

const ghsaAlphabet = "23456789cfghjmpqrvwx"

// randomGHSA returns a well-formed GHSA id no other test uses (the alias
// table is platform-wide).
func randomGHSA(t *testing.T) string {
	t.Helper()
	b := make([]byte, 12)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(ghsaAlphabet))))
		if err != nil {
			t.Fatal(err)
		}
		b[i] = ghsaAlphabet[n.Int64()]
	}
	return fmt.Sprintf("GHSA-%s-%s-%s", b[0:4], b[4:8], b[8:12])
}

func randomCVE(t *testing.T) string {
	t.Helper()
	n, err := rand.Int(rand.Reader, big.NewInt(90_000_000))
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("CVE-2098-%d", 10_000_000+n.Int64())
}

type aliasRig struct {
	r      *v2Rig
	links  *postgres.FindingIssueLinkRepository
	corpus *postgres.CVECorpusRepository
}

func newAliasRig(t *testing.T) *aliasRig {
	t.Helper()
	ar := &aliasRig{}
	ar.r = newV2RigWith(t, ingest.DefaultBlindingGuard(), func(svc *ingest.Service, db *postgres.DB) {
		ar.links = postgres.NewFindingIssueLinkRepository(db)
		ar.corpus = postgres.NewCVECorpusRepository(db)
		svc.SetIssueLinkStore(ar.links)
		svc.SetVulnAliasResolver(ar.corpus)
	})
	return ar
}

func (a *aliasRig) alias(t *testing.T, id, cve string) {
	t.Helper()
	if _, err := a.r.db.Exec(`INSERT INTO vuln_id_aliases (alias_id, cve_id, source, version) VALUES ($1, $2, 'ghsa', 1)
		ON CONFLICT (alias_id) DO UPDATE SET cve_id = EXCLUDED.cve_id`, id, cve); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = a.r.db.Exec(`DELETE FROM vuln_id_aliases WHERE alias_id = $1`, id) })
}

func (a *aliasRig) scan(t *testing.T, tn v2Tenant, tool, asset string, fs ...ctis.Finding) {
	t.Helper()
	tid := tn.tenant
	agt := &sensor.Sensor{ID: tn.sensor, TenantID: &tid, Type: sensor.SensorTypeWorker, Status: sensor.SensorStatusActive}
	for i := range fs {
		fs[i].AssetRef = "a"
	}
	rep := &ctis.Report{Version: "1.0", Tool: &ctis.Tool{Name: tool},
		Metadata: ctis.ReportMetadata{ID: shared.NewID().String(), Timestamp: time.Now().UTC()},
		Assets:   []ctis.Asset{{ID: "a", Type: ctis.AssetTypeRepository, Value: "github.com/acme/" + asset + "-" + tn.tenant.String()[:8]}},
		Findings: fs}
	if out, err := a.r.svc.Ingest(context.Background(), agt, ingest.Input{Report: rep}); err != nil || len(out.Errors) > 0 {
		t.Fatalf("ingest %s: %v %+v", tool, err, out)
	}
}

// ghsaOnly is an SCA finding that names only an advisory id.
func ghsaOnly(ghsa string) ctis.Finding {
	return ctis.Finding{Type: ctis.FindingTypeVulnerability, Title: "lodash prototype pollution", Severity: ctis.SeverityHigh, RuleID: ghsa,
		Vulnerability: &ctis.VulnerabilityDetails{Package: "lodash", PURL: "pkg:npm/lodash@4.17.15", Ecosystem: "npm",
			IDs: []ctis.VulnerabilityID{{Type: ctis.VulnerabilityIDGHSA, ID: ghsa}}}}
}

func cveSCA(cve string) ctis.Finding {
	return ctis.Finding{Type: ctis.FindingTypeVulnerability, Title: cve + " in lodash", Severity: ctis.SeverityHigh, RuleID: cve,
		Vulnerability: &ctis.VulnerabilityDetails{Package: "lodash", PURL: "pkg:npm/lodash@4.17.15", Ecosystem: "npm", CVEID: cve}}
}

type aliasRow struct{ id, status, cve, vuln string }

func (a *aliasRig) rows(t *testing.T, tn v2Tenant) []aliasRow {
	t.Helper()
	rs, err := a.r.db.Query(`SELECT id, status, COALESCE(cve_id, ''), COALESCE(identity_key->'fields'->2->>'v', '') FROM findings
		WHERE tenant_id = $1 AND status <> 'duplicate' ORDER BY created_at, id`, tn.tenant.String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rs.Close() }()
	var out []aliasRow
	for rs.Next() {
		var r aliasRow
		if err := rs.Scan(&r.id, &r.status, &r.cve, &r.vuln); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	if err := rs.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func (a *aliasRig) count(t *testing.T, q string, args ...any) int {
	t.Helper()
	var n int
	if err := a.r.db.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return n
}

func TestVulnAlias_GHSAOnlyReportMeetsTheCVEReport(t *testing.T) {
	a := newAliasRig(t)
	tn := a.r.newTenant("osv-scanner", "trivy")
	ghsa, cve := randomGHSA(t), randomCVE(t)
	a.alias(t, ghsa, cve)
	a.scan(t, tn, "osv-scanner", "shop", ghsaOnly(ghsa))
	a.scan(t, tn, "trivy", "shop", cveSCA(cve))
	rows := a.rows(t, tn)
	if len(rows) != 1 || rows[0].vuln != cve || rows[0].cve != cve {
		t.Fatalf("want one finding keyed on %s, got %+v", cve, rows)
	}
}

func TestVulnAlias_StoredAdvisoryFindingKeepsItsTriage(t *testing.T) {
	a := newAliasRig(t)
	tn := a.r.newTenant("osv-scanner", "trivy")
	ghsa, cve := randomGHSA(t), randomCVE(t)
	// Before the feed knows the alias: keyed on the advisory, triaged.
	a.scan(t, tn, "osv-scanner", "shop", ghsaOnly(ghsa))
	before := a.rows(t, tn)
	if len(before) != 1 || before[0].vuln != "rule:"+ghsa {
		t.Fatalf("advisory key: %+v", before)
	}
	if _, err := a.r.db.Exec(`UPDATE findings SET status = 'false_positive' WHERE id = $1`, before[0].id); err != nil {
		t.Fatal(err)
	}
	a.alias(t, ghsa, cve)
	// The next sighting re-keys it in place; the CVE report then lands on it.
	a.scan(t, tn, "osv-scanner", "shop", ghsaOnly(ghsa))
	a.scan(t, tn, "trivy", "shop", cveSCA(cve))
	after := a.rows(t, tn)
	if len(after) != 1 || after[0].id != before[0].id || after[0].status != "false_positive" || after[0].vuln != cve {
		t.Fatalf("want the same triaged finding keyed on the CVE, got %+v", after)
	}
}

func TestVulnAlias_HeldCVEKeyLinksNeverMerges(t *testing.T) {
	a := newAliasRig(t)
	tn := a.r.newTenant("osv-scanner", "trivy")
	ghsa, cve := randomGHSA(t), randomCVE(t)
	a.scan(t, tn, "osv-scanner", "shop", ghsaOnly(ghsa))
	a.scan(t, tn, "trivy", "shop", cveSCA(cve))
	rows := a.rows(t, tn)
	if len(rows) != 2 {
		t.Fatalf("two findings before the alias, got %+v", rows)
	}
	if _, err := a.r.db.Exec(`UPDATE findings SET status = 'accepted' WHERE id = $1`, rows[0].id); err != nil {
		t.Fatal(err)
	}
	a.alias(t, ghsa, cve)
	a.scan(t, tn, "osv-scanner", "shop", ghsaOnly(ghsa))
	after := a.rows(t, tn)
	if len(after) != 2 {
		t.Fatalf("an alias change merged two existing findings: %+v", after)
	}
	if after[0].status != "accepted" || after[1].status == "accepted" {
		t.Fatalf("a decision moved across findings: %+v", after)
	}
	if a.count(t, `SELECT count(*) FROM finding_issue_links WHERE tenant_id = $1 AND rule = 'vuln_alias' AND state = 'active'
		AND primary_id = $2 AND member_id = $3`, tn.tenant.String(), rows[0].id, rows[1].id) != 1 {
		t.Fatal("the two findings are not linked as the same issue")
	}
}

// After the collision the advisory tool's report lands on the CVE finding;
// the advisory finding takes that sighting too (scan, tool, time), so a
// coverage auto-resolve of its tool does not close it as fixed while the
// vulnerability is still reported. Its status never moves.
func TestVulnAlias_CollisionKeepsTheAdvisoryFindingSighted(t *testing.T) {
	a := newAliasRig(t)
	tn := a.r.newTenant("osv-scanner", "trivy")
	ghsa, cve := randomGHSA(t), randomCVE(t)
	a.scan(t, tn, "osv-scanner", "shop", ghsaOnly(ghsa))
	a.scan(t, tn, "trivy", "shop", cveSCA(cve))
	rows := a.rows(t, tn)
	if len(rows) != 2 {
		t.Fatalf("two findings before the alias, got %+v", rows)
	}
	scanOf := func(id string) (scan, tool string) {
		if err := a.r.db.QueryRow(`SELECT COALESCE(scan_id, ''), COALESCE(last_seen_tool, '') FROM findings WHERE id = $1`, id).Scan(&scan, &tool); err != nil {
			t.Fatal(err)
		}
		return scan, tool
	}
	before, _ := scanOf(rows[0].id)
	a.alias(t, ghsa, cve)
	a.scan(t, tn, "osv-scanner", "shop", ghsaOnly(ghsa))
	advScan, advTool := scanOf(rows[0].id)
	cveScan, _ := scanOf(rows[1].id)
	if advScan == before || advScan != cveScan || advTool != "osv-scanner" {
		t.Fatalf("the advisory finding was not sighted by the run (scan %q -> %q, CVE finding %q, tool %q)", before, advScan, cveScan, advTool)
	}
	if after := a.rows(t, tn); after[0].status != rows[0].status || after[1].status != rows[1].status {
		t.Fatalf("a carried sighting changed a status: %+v -> %+v", rows, after)
	}
}

func TestVulnAlias_ReportIDsNeverCanonicaliseAnotherFinding(t *testing.T) {
	a := newAliasRig(t)
	tn := a.r.newTenant("tool-a", "tool-b")
	ghsa, cve := randomGHSA(t), randomCVE(t)
	// Tool A asserts GHSA = CVE in its own ids; the feed knows nothing.
	both := ghsaOnly(ghsa)
	both.Vulnerability.IDs = append(both.Vulnerability.IDs, ctis.VulnerabilityID{Type: ctis.VulnerabilityIDCVE, ID: cve})
	a.scan(t, tn, "tool-a", "shop", both)
	// Tool B names only the GHSA: it keeps its advisory key.
	a.scan(t, tn, "tool-b", "shop", ghsaOnly(ghsa))
	rows := a.rows(t, tn)
	if len(rows) != 2 || rows[0].vuln != cve || rows[1].vuln != "rule:"+ghsa {
		t.Fatalf("a report's alias reached another finding: %+v", rows)
	}
}

func TestVulnAlias_TwoCVEsAreNeverFused(t *testing.T) {
	a := newAliasRig(t)
	tn := a.r.newTenant("tool-a")
	g1, g2, c1, c2 := randomGHSA(t), randomGHSA(t), randomCVE(t), randomCVE(t)
	a.alias(t, g1, c1)
	a.alias(t, g2, c2)
	f := ghsaOnly(g1)
	f.Vulnerability.IDs = append(f.Vulnerability.IDs, ctis.VulnerabilityID{Type: ctis.VulnerabilityIDGHSA, ID: g2})
	a.scan(t, tn, "tool-a", "shop", f)
	rows := a.rows(t, tn)
	if len(rows) != 1 || rows[0].vuln == c1 || rows[0].vuln == c2 {
		t.Fatalf("ids of two CVEs were keyed on one: %+v", rows)
	}
}

func TestVulnAlias_MultiCVESCAAdvisorySplitsPerCVE(t *testing.T) {
	a := newAliasRig(t)
	tn := a.r.newTenant("tool-a", "trivy")
	c1, c2 := randomCVE(t), randomCVE(t)
	f := cveSCA(c1)
	f.RuleID = "VENDOR-JS-LODASH-1040724"
	f.Vulnerability.IDs = []ctis.VulnerabilityID{{Type: ctis.VulnerabilityIDCVE, ID: c1}, {Type: ctis.VulnerabilityIDCVE, ID: c2}}
	a.scan(t, tn, "tool-a", "shop", f)
	a.scan(t, tn, "trivy", "shop", cveSCA(c2))
	rows := a.rows(t, tn)
	if len(rows) != 2 {
		t.Fatalf("want one finding per CVE, the second shared with trivy: %+v", rows)
	}
	got := map[string]bool{rows[0].vuln: true, rows[1].vuln: true}
	if !got[c1] || !got[c2] {
		t.Fatalf("keys %+v", rows)
	}
}

func TestVulnAlias_BackfillRekeysOrLinksStoredFindings(t *testing.T) {
	a := newAliasRig(t)
	ctx := context.Background()
	tn := a.r.newTenant("osv-scanner", "trivy")
	g1, c1, g2, c2 := randomGHSA(t), randomCVE(t), randomGHSA(t), randomCVE(t)
	a.scan(t, tn, "osv-scanner", "shop", ghsaOnly(g1))
	a.scan(t, tn, "osv-scanner", "web", ghsaOnly(g2))
	a.scan(t, tn, "trivy", "web", cveSCA(c2))
	before := a.rows(t, tn)
	if _, err := a.r.db.Exec(`UPDATE findings SET status = 'false_positive' WHERE id = $1`, before[0].id); err != nil {
		t.Fatal(err)
	}
	a.alias(t, g1, c1)
	a.alias(t, g2, c2)
	dry, err := a.links.RekeyVulnAliases(ctx, tn.tenant, a.corpus, false, 1)
	if err != nil || dry.Rekeyed != 1 || dry.Linked != 1 {
		t.Fatalf("dry run: %+v %v", dry, err)
	}
	if a.count(t, `SELECT count(*) FROM findings WHERE tenant_id = $1 AND identity_key->'fields'->2->>'v' = $2`, tn.tenant.String(), c1) != 0 {
		t.Fatal("the dry run wrote")
	}
	rep, err := a.links.RekeyVulnAliases(ctx, tn.tenant, a.corpus, true, 1)
	if err != nil || rep.Rekeyed != 1 || rep.Linked != 1 {
		t.Fatalf("apply: %+v %v", rep, err)
	}
	var status, vuln string
	if err := a.r.db.QueryRow(`SELECT status, identity_key->'fields'->2->>'v' FROM findings WHERE id = $1`, before[0].id).Scan(&status, &vuln); err != nil {
		t.Fatal(err)
	}
	if status != "false_positive" || vuln != c1 {
		t.Fatalf("re-keyed finding: %s %s", status, vuln)
	}
	// Its old key resolves to it: the advisory report lands on it.
	a.scan(t, tn, "osv-scanner", "shop", ghsaOnly(g1))
	if a.count(t, `SELECT count(*) FROM findings WHERE tenant_id = $1 AND status <> 'duplicate'`, tn.tenant.String()) != 3 {
		t.Fatal("a re-sighting after the re-key created a finding")
	}
	again, err := a.links.RekeyVulnAliases(ctx, tn.tenant, a.corpus, true, 1)
	if err != nil || again.Rekeyed != 0 || again.Linked != 0 {
		t.Fatalf("second run is not idempotent: %+v %v", again, err)
	}
	// Another tenant's findings are untouched.
	tn2 := a.r.newTenant("osv-scanner")
	a.scan(t, tn2, "osv-scanner", "shop", ghsaOnly(randomGHSA(t)))
	if r, err := a.links.RekeyVulnAliases(ctx, tn2.tenant, a.corpus, true, 10); err != nil || r.Rekeyed != 0 {
		t.Fatalf("tenant 2: %+v %v", r, err)
	}
}

func TestVulnAlias_ImporterAppliesTheMapWithAGuard(t *testing.T) {
	db := setupTestDB(t)
	t.Cleanup(func() { _ = db.Close() })
	repo := postgres.NewCVECorpusRepository(&postgres.DB{DB: db})
	ctx := context.Background()
	g1, g2, c1, c2 := randomGHSA(t), randomGHSA(t), randomCVE(t), randomCVE(t)
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM vuln_id_aliases WHERE alias_id IN ($1, $2)`, g1, g2) })
	var base int64
	if err := db.QueryRow(`SELECT COALESCE(max(version), 0) FROM vuln_id_aliases`).Scan(&base); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DELETE FROM vuln_id_aliases`); err != nil {
		t.Fatal(err)
	}
	v := uint64(base) + 1
	res, err := repo.ApplyVulnIDAliases(ctx, []vulnerability.VulnIDAlias{{ID: g1, CVE: c1, Source: "ghsa"}, {ID: g2, CVE: c2, Source: "ghsa"}}, v, 0.05, 500)
	if err != nil || res.Written != 2 {
		t.Fatalf("apply: %+v %v", res, err)
	}
	got, err := repo.ResolveVulnIDAliases(ctx, []string{g1, g2, "GHSA-2222-3333-4444"})
	if err != nil || got[g1] != c1 || got[g2] != c2 || len(got) != 2 {
		t.Fatalf("resolve: %+v %v", got, err)
	}
	// A snapshot that drops more than the guard allows is refused whole.
	if _, err := repo.ApplyVulnIDAliases(ctx, []vulnerability.VulnIDAlias{{ID: g1, CVE: c1, Source: "ghsa"}}, v+1, 0.05, 0); err == nil {
		t.Fatal("a snapshot removing half the map was applied")
	}
	if got, _ := repo.ResolveVulnIDAliases(ctx, []string{g2}); got[g2] != c2 {
		t.Fatal("a refused snapshot removed an entry")
	}
	// Within the guard: applied, the dropped entry removed.
	if res, err := repo.ApplyVulnIDAliases(ctx, []vulnerability.VulnIDAlias{{ID: g1, CVE: c1, Source: "ghsa"}}, v+1, 0.05, 500); err != nil || res.Removed != 1 {
		t.Fatalf("apply within the guard: %+v %v", res, err)
	}
}
