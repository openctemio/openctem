package integration

// Cross-rule correlation of DAST findings (research/134 section 12):
// correlation may reduce noise, never coverage. The golden corpus holds the
// owner's open-redirect pair (one issue) and one negative pair for each
// guardrail; any wrong merge fails. Further tests: another asset, reversal,
// a member seen without its primary, triage of the primary, group
// severity, the kill switch, and that a released finding takes the
// new-finding path.

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

type corrRig struct {
	r       *v2Rig
	repo    *postgres.FindingCorrelationRepository
	created []string
}

func newCorrRig(t *testing.T) *corrRig {
	t.Helper()
	cr := &corrRig{}
	cr.r = newV2RigWith(t, ingest.DefaultBlindingGuard(), func(svc *ingest.Service, db *postgres.DB) {
		cr.repo = postgres.NewFindingCorrelationRepository(db)
		svc.SetCorrelationStore(cr.repo)
		svc.SetFindingCreatedCallback(func(_ context.Context, _ shared.ID, fs []*vulnerability.Finding) {
			for _, f := range fs {
				cr.created = append(cr.created, f.RuleID())
			}
		})
	})
	return cr
}

// scan ingests one report of findings on asset (a domain).
func (c *corrRig) scan(t *testing.T, tn v2Tenant, asset string, fs ...ctis.Finding) {
	t.Helper()
	tid := tn.tenant
	agt := &sensor.Sensor{ID: tn.sensor, TenantID: &tid, Type: sensor.SensorTypeWorker, Status: sensor.SensorStatusActive}
	for i := range fs {
		fs[i].AssetRef = "a"
	}
	rep := &ctis.Report{Version: "1.0", Tool: &ctis.Tool{Name: "nuclei"},
		Metadata: ctis.ReportMetadata{ID: shared.NewID().String(), Timestamp: time.Now().UTC()},
		Assets:   []ctis.Asset{{ID: "a", Type: ctis.AssetTypeDomain, Value: tn.tenant.String()[:8] + "." + asset}},
		Findings: fs}
	if out, err := c.r.svc.Ingest(context.Background(), agt, ingest.Input{Report: rep}); err != nil || len(out.Errors) > 0 {
		t.Fatalf("ingest: %v %+v", err, out)
	}
}

type corrRow struct{ id, status, dupOf, severity string }

func (c *corrRig) rows(t *testing.T, tn v2Tenant) map[string]corrRow {
	t.Helper()
	rows, err := c.r.db.QueryContext(context.Background(), `SELECT id, rule_id, status, COALESCE(duplicate_of::text, ''), severity
		FROM findings WHERE tenant_id = $1`, tn.tenant.String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]corrRow{}
	for rows.Next() {
		var r corrRow
		var rule string
		if err := rows.Scan(&r.id, &rule, &r.status, &r.dupOf, &r.severity); err != nil {
			t.Fatal(err)
		}
		out[rule] = r
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func (c *corrRig) count(t *testing.T, q string, args ...any) int {
	t.Helper()
	var n int
	if err := c.r.db.QueryRowContext(context.Background(), q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

type corrCase struct {
	Name         string       `json:"name"`
	Expect       string       `json:"expect"`
	Primary      string       `json:"primary"`
	NoSuggestion bool         `json:"no_suggestion"`
	A            ctis.Finding `json:"a"`
	B            ctis.Finding `json:"b"`
}

func TestCorrelationGolden(t *testing.T) {
	raw, err := os.ReadFile("testdata/correlation/dast.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Asset string     `json:"asset"`
		Cases []corrCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	c := newCorrRig(t)
	for _, tc := range file.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			tn := c.r.newTenant()
			c.scan(t, tn, file.Asset, tc.A, tc.B)
			rows := c.rows(t, tn)
			a, b := rows[tc.A.RuleID], rows[tc.B.RuleID]
			if a.id == "" || b.id == "" {
				t.Fatalf("findings not stored: %+v", rows)
			}
			// Every detection has its injection point: a negative pair must
			// fail the rules, not miss the data.
			if n := c.count(t, `SELECT count(*) FROM finding_injection_points WHERE tenant_id = $1`, tn.tenant.String()); n != 2 {
				t.Fatalf("injection points stored: %d, want 2", n)
			}
			merged := (a.status == "duplicate" && a.dupOf == b.id) || (b.status == "duplicate" && b.dupOf == a.id)
			switch tc.Expect {
			case "merged":
				prim, mem := b, a
				if tc.Primary == "a" {
					prim, mem = a, b
				}
				if mem.status != "duplicate" || mem.dupOf != prim.id || prim.status == "duplicate" {
					t.Fatalf("want %s primary: a=%+v b=%+v", tc.Primary, a, b)
				}
			case "not_merged":
				if merged || a.status == "duplicate" || b.status == "duplicate" {
					t.Fatalf("WRONG MERGE: a=%+v b=%+v", a, b)
				}
				if tc.NoSuggestion && c.count(t, `SELECT count(*) FROM finding_correlations WHERE tenant_id = $1`, tn.tenant.String()) != 0 {
					t.Fatal("a pair that must never be related was suggested")
				}
			default:
				t.Fatalf("unknown expectation %q", tc.Expect)
			}
		})
	}
}

func corrPair(sevA, sevB string) (generic, specific ctis.Finding) {
	mk := func(rule, path, cve, loc, sev string) ctis.Finding {
		u := "https://shop.example.com" + path
		f := ctis.Finding{Type: ctis.FindingTypeVulnerability, Title: rule, Severity: ctis.Severity(sev), RuleID: rule,
			Location: &ctis.FindingLocation{Path: u}, Web: &ctis.WebLocation{URL: u, Method: "GET"},
			Vulnerability: &ctis.VulnerabilityDetails{CWEID: "CWE-601", CWEIDs: []string{"CWE-601"}, CVEID: cve},
			EvidenceItems: []ctis.EvidenceItem{{Kind: "http_exchange", Version: 1, HTTP: &ctis.EvidenceHTTP{
				Request:  &ctis.EvidenceRequest{Method: "GET", URL: u},
				Response: &ctis.EvidenceResponse{Status: 302, Headers: []ctis.EvidenceHeader{{Name: "Location", Value: loc}}}}}}}
		return f
	}
	return mk("open-redirect-generic", "/oast.me", "", "//oast.me", sevA),
		mk("CVE-2025-54793", "/interact.sh/en", "CVE-2025-54793", "//interact.sh/en/", sevB)
}

func TestCorrelation_Lifecycle(t *testing.T) {
	c := newCorrRig(t)
	ctx := context.Background()
	generic, specific := corrPair("high", "medium")

	// Another asset: never merged across assets.
	tn := c.r.newTenant()
	c.scan(t, tn, "a.example.com", generic)
	c.scan(t, tn, "b.example.com", specific)
	if n := c.count(t, `SELECT count(*) FROM findings WHERE tenant_id = $1 AND status = 'duplicate'`, tn.tenant.String()); n != 0 {
		t.Fatal("WRONG MERGE across assets")
	}

	tn = c.r.newTenant()
	c.scan(t, tn, "shop.example.com", generic, specific)
	rows := c.rows(t, tn)
	g, s := rows["open-redirect-generic"], rows["CVE-2025-54793"]
	if g.status != "duplicate" || g.dupOf != s.id {
		t.Fatalf("the generic detection is not the CVE finding's duplicate: %+v %+v", g, s)
	}
	// Group severity is the worst of the group.
	if s.severity != "high" {
		t.Fatalf("primary severity %q, want high (the member's)", s.severity)
	}
	if c.count(t, `SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'finding.duplicate_marked' AND resource_id = $2`, tn.tenant.String(), g.id) != 1 {
		t.Fatal("correlation not audited")
	}
	// The primary exposes both detections.
	pid, _ := shared.IDFromString(s.id)
	dets, _, err := c.repo.Detections(ctx, tn.tenant, pid)
	if err != nil || len(dets) != 2 {
		t.Fatalf("detections %+v %v", dets, err)
	}

	// The CVE is patched; the generic detection still fires: released, its
	// own open finding again, through the new-finding path.
	c.created = nil
	c.scan(t, tn, "shop.example.com", generic)
	rows = c.rows(t, tn)
	if rows["open-redirect-generic"].status != "new" || rows["open-redirect-generic"].dupOf != "" {
		t.Fatalf("not released when its primary was not seen: %+v", rows["open-redirect-generic"])
	}
	if rows["CVE-2025-54793"].severity != "medium" {
		t.Fatalf("primary severity not restored: %q", rows["CVE-2025-54793"].severity)
	}
	if len(c.created) != 1 || c.created[0] != "open-redirect-generic" {
		t.Fatalf("released finding did not take the new-finding path: %v", c.created)
	}

	// Both seen again: correlated again.
	c.scan(t, tn, "shop.example.com", generic, specific)
	if c.rows(t, tn)["open-redirect-generic"].status != "duplicate" {
		t.Fatal("not re-correlated")
	}
	// Triage of the primary never propagates: it leaves the open statuses,
	// the duplicate is released and stands alone.
	if _, err := c.r.db.ExecContext(ctx, `UPDATE findings SET status = 'false_positive' WHERE id = $1`, s.id); err != nil {
		t.Fatal(err)
	}
	c.scan(t, tn, "shop.example.com", generic, specific)
	rows = c.rows(t, tn)
	if rows["open-redirect-generic"].status != "new" || rows["CVE-2025-54793"].status != "false_positive" {
		t.Fatalf("after the primary was triaged: %+v", rows)
	}

	// Un-duplicate by a person: restored at once and never linked again.
	tn = c.r.newTenant()
	c.scan(t, tn, "shop.example.com", generic, specific)
	g = c.rows(t, tn)["open-redirect-generic"]
	gid, _ := shared.IDFromString(g.id)
	if ok, err := c.repo.ReleaseByUser(ctx, tn.tenant, gid, shared.ID{}); err != nil || !ok {
		t.Fatalf("release: %v %v", ok, err)
	}
	c.scan(t, tn, "shop.example.com", generic, specific)
	if st := c.rows(t, tn)["open-redirect-generic"].status; st != "new" {
		t.Fatalf("re-linked after a person released it: %s", st)
	}

	// The kill switch: no automatic correlation.
	tn = c.r.newTenant()
	if _, err := c.r.db.ExecContext(ctx, `UPDATE tenants SET settings = COALESCE(settings, '{}'::jsonb) ||
		'{"finding_correlation": {"auto_disabled": true}}'::jsonb WHERE id = $1`, tn.tenant.String()); err != nil {
		t.Fatal(err)
	}
	c.scan(t, tn, "shop.example.com", generic, specific)
	if n := c.count(t, `SELECT count(*) FROM findings WHERE tenant_id = $1 AND status = 'duplicate'`, tn.tenant.String()); n != 0 {
		t.Fatal("auto correlation ran with the switch off")
	}
}
