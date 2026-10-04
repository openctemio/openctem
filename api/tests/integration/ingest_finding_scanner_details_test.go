package integration

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/lib/pq"
	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Research 17 R2: ingest kept the rule family, exploit verdict, VPR, CVSS
// version, the extra CVEs and the patch date only in the report and dropped
// them. Checked through the real ingest on a migrated database: stored on
// create, merged on a re-sighting (family/patch first wins, exploit sticky,
// VPR latest, CVEs union), a multi-CVE network plugin still splits into one
// finding per CVE (RFC-043 D3), and odd values are normalized, not stored.
func TestIngest_FindingStoresScannerDetails(t *testing.T) {
	ctx := context.Background()
	r := newV2Rig(t, ingest.DefaultBlindingGuard())
	tn := r.newTenant("nessus")
	db := &postgres.DB{DB: r.db}
	svc := ingest.NewService(
		postgres.NewAssetRepository(db), postgres.NewFindingRepository(db),
		postgres.NewVulnerabilityRepository(db), postgres.NewComponentRepository(db),
		postgres.NewSensorRepository(db), postgres.NewBranchRepository(db), postgres.NewTenantRepository(db),
		postgres.NewAuditRepository(db), logger.NewNop())
	tid := tn.tenant
	agt := &sensor.Sensor{ID: tn.sensor, TenantID: &tid, Type: sensor.SensorTypeWorker, Status: sensor.SensorStatusActive}

	send := func(findings ...ctis.Finding) {
		t.Helper()
		rep := &ctis.Report{Version: "1.0", Tool: &ctis.Tool{Name: "nessus"},
			Metadata: ctis.ReportMetadata{Timestamp: time.Now().UTC()},
			Assets:   []ctis.Asset{{ID: "h", Type: ctis.AssetTypeHost, Value: "app-1.example.com"}},
			Findings: findings}
		for i := range rep.Findings {
			rep.Findings[i].AssetRef = "h"
		}
		out, err := svc.Ingest(ctx, agt, ingest.Input{Report: rep})
		if err != nil || len(out.Errors) > 0 {
			t.Fatalf("Ingest: %v %v", err, out.Errors)
		}
	}
	type row struct {
		family, cvssVersion sql.NullString
		exploit             bool
		vpr                 sql.NullFloat64
		cves                pq.StringArray
		patch               sql.NullTime
	}
	readWhere := func(where string, args ...any) []row {
		t.Helper()
		rows, err := r.db.QueryContext(ctx, `SELECT family, cvss_version, exploit_available, vpr_score, cve_ids, patch_published_at
			FROM findings WHERE tenant_id = $1 AND `+where+` ORDER BY cve_id`, append([]any{tn.tenant.String()}, args...)...)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = rows.Close() }()
		var out []row
		for rows.Next() {
			var x row
			if err := rows.Scan(&x.family, &x.cvssVersion, &x.exploit, &x.vpr, &x.cves, &x.patch); err != nil {
				t.Fatal(err)
			}
			out = append(out, x)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}

	// An SCA-style finding (package set, so not a network VA) naming 2 CVEs.
	sca := ctis.Finding{Type: ctis.FindingTypeVulnerability, Severity: ctis.SeverityHigh,
		Title: "log4j-core vulnerable", RuleID: "sca-log4j", Category: "Java\x00 Libraries",
		Vulnerability: &ctis.VulnerabilityDetails{CVEID: "cve-2021-44228", CVEIDs: []string{"CVE-2021-44228", "CVE-2021-45046"},
			Package: "log4j-core", CVSSScore: 10, CVSSVersion: "3.1", VPRScore: 9.4, ExploitAvailable: true},
		Properties: ctis.Properties{"patch_publication_date": "2021/12/10"}}
	send(sca)
	got := readWhere("rule_id = 'sca-log4j'")
	if len(got) != 1 {
		t.Fatalf("rows %d", len(got))
	}
	g := got[0]
	if g.family.String != "Java Libraries" || g.cvssVersion.String != "3.1" || !g.exploit || g.vpr.Float64 != 9.4 ||
		strings.Join(g.cves, ",") != "CVE-2021-44228,CVE-2021-45046" || !g.patch.Valid || g.patch.Time.Format("2006-01-02") != "2021-12-10" {
		t.Fatalf("stored details: %+v", g)
	}

	// Re-sighting: no exploit now (sticky), new VPR (latest wins), a third
	// CVE (union), another family and patch date (first wins).
	again := sca
	v := *sca.Vulnerability
	v.ExploitAvailable = false
	v.VPRScore = 6.1
	v.CVEIDs = []string{"CVE-2021-45105"}
	again.Vulnerability = &v
	again.Category = "Other"
	again.Properties = ctis.Properties{"patch_publication_date": "2022-01-01"}
	send(again)
	g = readWhere("rule_id = 'sca-log4j'")[0]
	if g.family.String != "Java Libraries" || !g.exploit || g.vpr.Float64 != 6.1 ||
		strings.Join(g.cves, ",") != "CVE-2021-44228,CVE-2021-45046,CVE-2021-45105" || g.patch.Time.Format("2006-01-02") != "2021-12-10" {
		t.Fatalf("merged details: %+v", g)
	}

	// A multi-CVE network plugin is split into one finding per CVE, each
	// with its own CVE; the Tenable.sc connector's property names work.
	netva := ctis.Finding{Type: ctis.FindingTypeVulnerability, Severity: ctis.SeverityCritical,
		Title: "Log4Shell", RuleID: "156860", Category: "CGI abuses",
		Network: &ctis.NetworkLocation{Host: "app-1.example.com", Port: 8443, Protocol: "tcp"},
		Vulnerability: &ctis.VulnerabilityDetails{CVEID: "CVE-2021-44228", CVEIDs: []string{"CVE-2021-44228", "CVE-2021-45046"},
			CVSSScore: 10, CVSSVersion: "3.x", VPRScore: 42 /* out of range: dropped */},
		Properties: ctis.Properties{"tenable_patch_pub_date": "2021-12-10T00:00:00Z"}}
	send(netva)
	split := readWhere("rule_id = '156860'")
	if len(split) != 2 {
		t.Fatalf("network plugin rows %d, want one per CVE", len(split))
	}
	for i, want := range []string{"CVE-2021-44228", "CVE-2021-45046"} {
		s := split[i]
		if strings.Join(s.cves, ",") != want || s.family.String != "CGI abuses" || s.vpr.Valid || s.cvssVersion.String != "3.x" || !s.patch.Valid {
			t.Fatalf("split finding %d: %+v", i, s)
		}
	}

	// A finding with none of it stores NULLs and false.
	send(ctis.Finding{Type: ctis.FindingTypeVulnerability, Severity: ctis.SeverityLow, Title: "plain", RuleID: "plain-1"})
	p := readWhere("rule_id = 'plain-1'")[0]
	if p.family.Valid || p.exploit || p.vpr.Valid || p.cvssVersion.Valid || len(p.cves) != 0 || p.patch.Valid {
		t.Fatalf("plain finding stored details: %+v", p)
	}
}
