package integration

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/app/certmonitor"
	"github.com/openctemio/openctem/api/internal/app/easm"
	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Certificate SAN promotion through the real ingest (research/333 D5): a
// certificate a sensor reports turns the names below the tenant's roots into
// candidate subdomains with certificate_san evidence naming the certificate;
// foreign names, wildcards, addresses, excluded names (also through a
// dedicated address), tombstoned names and other tenants get nothing; an
// existing asset keeps its standing.
func TestIngest_CertificateSANPromotion(t *testing.T) {
	r := newV2Rig(t, ingest.DefaultBlindingGuard())
	tn := r.newTenant("httpx")
	other := r.newTenant("httpx")
	db := &postgres.DB{DB: r.db}
	ctx := context.Background()
	log := logger.NewNop()
	assets := postgres.NewAssetRepository(db)
	attr := postgres.NewAttributionRepository(db)
	targets := postgres.NewScopeTargetRepository(db)
	scopeSvc := scope.NewService(targets, postgres.NewScopeExclusionRepository(db), assets, log)
	svc := r.svc
	svc.SetExclusionSource(scopeSvc)
	svc.SetScanAttributionStamper(easm.NewScanStamper(attr, postgres.NewVerifiedDomainNameRepository(db)))
	cm := certmonitor.NewService(assets, nil, "", log)
	cm.SetDomainSources(postgres.NewVerifiedDomainRepository(db), targets)
	cm.SetExclusions(scopeSvc)
	cm.SetPromotion(svc, assets, attr)
	cm.SetTombstones(attr)
	cm.SetNameAddresses(attr)
	svc.SetCertificateNamePromoter(cm)

	tid, oid := tn.tenant, other.tenant
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := r.db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	seed := func(tenant shared.ID, name, typ string) string {
		id := shared.NewID().String()
		exec(`INSERT INTO assets (id, tenant_id, name, asset_type, criticality, status) VALUES ($1, $2, $3, $4, 'high', 'active')`,
			id, tenant.String(), name, typ)
		return id
	}
	const root = "acme-san.example.org"
	seed(tid, root, "domain")
	keepID := seed(tid, "keep."+root, "subdomain") // legacy: no record
	vpnID := seed(tid, "vpn."+root, "subdomain")
	ipID := seed(tid, "203.0.113.10", "ip_address")
	exec(`INSERT INTO asset_relationships (tenant_id, source_asset_id, target_asset_id, relationship_type) VALUES ($1, $2, $3, 'resolves_to')`,
		tid.String(), vpnID, ipID)
	for _, ex := range [][2]string{{"ip_address", "203.0.113.10"}, {"domain", "secret." + root}} {
		exec(`INSERT INTO scope_exclusions (tenant_id, exclusion_type, pattern, reason, status, approved_at, approved_by, created_by)
			VALUES ($1, $2, $3, 'test', 'active', now(), 'approver', 'test')`, tid.String(), ex[0], ex[1])
	}
	exec(`INSERT INTO easm_tombstones (tenant_id, name, rules) VALUES ($1, $2, '{fqdn_under_asserted_root}')`, tid.String(), "dead."+root)

	report := func() *ctis.Report {
		na := time.Now().Add(120 * 24 * time.Hour).UTC()
		return &ctis.Report{Version: "1.0", Tool: &ctis.Tool{Name: "httpx"},
			Metadata: ctis.ReportMetadata{ID: "rep-san-" + shared.NewID().String(), Timestamp: time.Now().UTC()},
			Assets: []ctis.Asset{{ID: "cert", Type: ctis.AssetTypeCertificate, Value: "aa:bb:cc:" + shared.NewID().String()[:8],
				Technical: &ctis.AssetTechnical{Certificate: &ctis.CertificateTechnical{
					SubjectCN: "WWW." + root + ".",
					SANs: []string{"www." + root, "*.wild." + root, "cdn.foreign-cdn.net", root, "198.51.100.1",
						"keep." + root, "vpn." + root, "secret." + root, "dead." + root},
					IssuerOrg: "Test CA", NotAfter: &na,
				}}}}}
	}
	ingestAs := func(tenant, sensorID shared.ID) {
		t.Helper()
		agt := &sensor.Sensor{ID: sensorID, TenantID: &tenant, Type: sensor.SensorTypeWorker, Status: sensor.SensorStatusActive}
		out, err := svc.Ingest(ctx, agt, ingest.Input{Report: report()})
		if err != nil || len(out.Errors) > 0 {
			t.Fatalf("Ingest: %v %v", err, out.Errors)
		}
	}
	idIn := func(tenant shared.ID, name string) string {
		var id string
		_ = r.db.QueryRowContext(ctx, `SELECT id FROM assets WHERE tenant_id = $1 AND name = $2 AND deleted_at IS NULL`, tenant.String(), name).Scan(&id)
		return id
	}
	evidenceRows := func(tenant shared.ID, id string) int {
		var n int
		_ = r.db.QueryRowContext(ctx, `SELECT count(*) FROM easm_evidence WHERE tenant_id = $1 AND asset_id = $2 AND rule = 'certificate_san'`,
			tenant.String(), id).Scan(&n)
		return n
	}

	ingestAs(tid, tn.sensor)

	wwwID := idIn(tid, "www."+root)
	if wwwID == "" {
		t.Fatal("the SAN under the root was not promoted")
	}
	var typ, src, tool, certRef, technique string
	if err := r.db.QueryRowContext(ctx, `SELECT a.asset_type, a.discovery_source, a.discovery_tool, e.observed->>'certificate_asset_id', e.technique
		FROM assets a JOIN easm_evidence e ON e.asset_id = a.id AND e.tenant_id = a.tenant_id AND e.rule = 'certificate_san'
		WHERE a.tenant_id = $1 AND a.id = $2`, tid.String(), wwwID).Scan(&typ, &src, &tool, &certRef, &technique); err != nil {
		t.Fatalf("lineage: %v", err)
	}
	var certID string
	_ = r.db.QueryRowContext(ctx, `SELECT id FROM assets WHERE tenant_id = $1 AND asset_type = 'certificate'`, tid.String()).Scan(&certID)
	if typ != "subdomain" || src != "certificate" || tool != "httpx" || technique != "certificate" || certRef == "" || certRef != certID {
		t.Errorf("lineage = type %q source %q tool %q technique %q certificate %q (cert asset %q)", typ, src, tool, technique, certRef, certID)
	}
	recs, err := attr.Records(ctx, tid, []string{wwwID, keepID})
	if err != nil {
		t.Fatal(err)
	}
	if got := recs[wwwID].State; got != attribution.StateCandidate {
		t.Errorf("promoted SAN state = %q, want candidate (never auto-scoped)", got)
	}
	if _, ok := recs[keepID]; ok {
		t.Errorf("the existing legacy asset got a record %+v", recs[keepID])
	}
	if evidenceRows(tid, keepID) != 1 {
		t.Error("the existing asset got no certificate_san evidence")
	}
	if evidenceRows(tid, vpnID) != 0 {
		t.Error("an asset on an excluded dedicated address got evidence")
	}
	for _, n := range []string{"wild." + root, "cdn.foreign-cdn.net", "198.51.100.1", "secret." + root, "dead." + root} {
		if idIn(tid, n) != "" {
			t.Errorf("%s was created", n)
		}
	}

	// The same certificate in another organization without roots: nothing,
	// and the first organization's assets are untouched.
	ingestAs(oid, other.sensor)
	if idIn(oid, "www."+root) != "" {
		t.Error("a SAN created an asset in an organization without the root")
	}
	var cnt int
	_ = r.db.QueryRowContext(ctx, `SELECT count(*) FROM easm_evidence WHERE tenant_id = $1`, oid.String()).Scan(&cnt)
	if cnt != 0 {
		t.Errorf("the other organization has %d evidence rows", cnt)
	}

	// A re-ingest is idempotent: no second asset, still one evidence row.
	ingestAs(tid, tn.sensor)
	_ = r.db.QueryRowContext(ctx, `SELECT count(*) FROM assets WHERE tenant_id = $1 AND name = $2`, tid.String(), "www."+root).Scan(&cnt)
	if cnt != 1 || evidenceRows(tid, wwwID) != 1 {
		t.Errorf("re-ingest: %d assets, %d evidence rows", cnt, evidenceRows(tid, wwwID))
	}
}
