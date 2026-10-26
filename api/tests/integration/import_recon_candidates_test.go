package integration

// A recon directory import on a migrated database with the production gate
// (docs/architecture/finding-import.md, "Recon results"):
//   - a host the organization's scope does not cover is created as a
//     candidate and is refused by the active-scan gate;
//   - a host it covers is created without a candidate hold;
//   - an asset the organization already had is never held by an import;
//   - nothing crosses tenants (the same name in another tenant);
//   - endpoints land only under origins the uploader may change.

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/ctis"

	easmapp "github.com/openctemio/openctem/api/internal/app/easm"
	"github.com/openctemio/openctem/api/internal/app/ingest"
	scansvc "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/ingestreceipt"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type onlyIDs map[shared.ID]bool

func (o onlyIDs) AssetsInScope(_ context.Context, ids []shared.ID) ([]shared.ID, error) {
	var out []shared.ID
	for _, id := range ids {
		if o[id] {
			out = append(out, id)
		}
	}
	return out, nil
}

func TestImportRecon_CandidatesAreNeverTargeted(t *testing.T) {
	db := openLifecycleDB(t)
	ctx := context.Background()
	tenantA := seedLifecycleTenant(ctx, t, db)
	tenantB := seedLifecycleTenant(ctx, t, db)
	seedScopeTarget(t, db, tenantA, "domain", "*.corp-recon.example.org")
	// The organization already had this host; the file calls it outside.
	existing := seedOwnedAsset(t, db, tenantA, "old.elsewhere-recon.net", "subdomain")

	pg := &postgres.DB{DB: db}
	attr := postgres.NewAttributionRepository(pg)
	ing := ingest.NewService(
		postgres.NewAssetRepository(pg), postgres.NewFindingRepository(pg),
		postgres.NewVulnerabilityRepository(pg), postgres.NewComponentRepository(pg),
		postgres.NewSensorRepository(pg), postgres.NewBranchRepository(pg), postgres.NewTenantRepository(pg),
		postgres.NewAuditRepository(pg), logger.NewNop())
	ing.SetReceiptRecorder(postgres.NewIngestReceiptRepository(pg))
	ing.SetWebEndpointRepository(postgres.NewWebEndpointRepository(pg))
	ing.SetImportCandidateHolder(easmapp.NewScanStamper(attr, postgres.NewVerifiedDomainNameRepository(pg)))

	importFor := func(tenant shared.ID, actor ingest.ActorScope, assets []ctis.Asset, eps []ctis.Endpoint) *ingest.Output {
		t.Helper()
		rep := &ctis.Report{Version: "1.0", Tool: &ctis.Tool{Name: "reconftw"}, Assets: assets, Endpoints: eps,
			Metadata: ctis.ReportMetadata{ID: shared.NewID().String(), Timestamp: time.Now().UTC(), CoverageType: "partial"}}
		tid := tenant
		out, err := ing.Ingest(ctx, &sensor.Sensor{TenantID: &tid, Status: sensor.SensorStatusActive}, ingest.Input{
			Report: rep, CoverageType: ingest.CoverageTypePartial,
			Options: ingest.Options{Actor: actor, SourceKind: "import", SourceName: "import:reconftw",
				Receipt: &ingestreceipt.Source{Kind: ingestreceipt.SourceUpload, Ref: shared.NewID().String()}},
		})
		if err != nil || len(out.Errors) > 0 {
			t.Fatalf("ingest: %v %v", err, out)
		}
		return out
	}
	host := func(id, name, scope string) ctis.Asset {
		return ctis.Asset{ID: id, Type: ctis.AssetTypeSubdomain, Value: name, Properties: ctis.Properties{"import_scope": scope}}
	}
	idIn := func(tenant shared.ID, name string) string {
		var id string
		_ = db.QueryRowContext(ctx, `SELECT id FROM assets WHERE tenant_id = $1 AND name = $2`, tenant.String(), name).Scan(&id)
		return id
	}
	state := func(tenant shared.ID, name string) attribution.State {
		t.Helper()
		id := idIn(tenant, name)
		if id == "" {
			t.Fatalf("asset %s missing in %s", name, tenant)
		}
		recs, err := attr.Records(ctx, tenant, []string{id})
		if err != nil {
			t.Fatal(err)
		}
		return recs[id].State
	}

	importFor(tenantA, nil, []ctis.Asset{
		host("a", "www.corp-recon.example.org", "in_target"),
		host("b", "partner.third-party-recon.net", "outside_target"),
		host("c", "old.elsewhere-recon.net", "outside_target"),
	}, nil)
	// The same names in another tenant: no record, nothing shared.
	importFor(tenantB, nil, []ctis.Asset{host("a", "partner.third-party-recon.net", "in_target")}, nil)

	if got := state(tenantA, "partner.third-party-recon.net"); got != attribution.StateCandidate {
		t.Fatalf("outside host record = %q, want candidate", got)
	}
	if got := state(tenantA, "www.corp-recon.example.org"); got != "" {
		t.Fatalf("in-scope host got record %q", got)
	}
	if got := state(tenantA, "old.elsewhere-recon.net"); got != "" {
		t.Fatalf("an asset the organization already had was held: %q", got)
	}
	if idIn(tenantA, "old.elsewhere-recon.net") != existing.String() {
		t.Fatal("existing asset replaced")
	}
	if got := state(tenantB, "partner.third-party-recon.net"); got != "" {
		t.Fatalf("tenant B's in_target host got record %q", got)
	}

	// The production active-scan gate: the candidate is never targeted; a
	// covered host is.
	gate := easmapp.NewActiveGate(attr, postgres.NewAssetRepository(pg), scopeService(db), postgres.NewVerifiedDomainNameRepository(pg))
	svc := newTriggerServiceWith(db, scansvc.WithScopeExclusionFilter(scopeService(db)), scansvc.WithAttributionGate(gate))
	scan := func(target string) error {
		_, err := svc.CreateScan(ctx, scansvc.CreateScanInput{
			TenantID: tenantA.String(), Name: "recon " + shared.NewID().String(), ScanType: "single",
			ScannerName: "nuclei", Targets: []string{target}, TenantRunner: true,
		})
		return err
	}
	if err := scan("partner.third-party-recon.net"); err == nil {
		t.Error("a candidate host was admitted as a scan target")
	}
	if err := scan("www.corp-recon.example.org"); err != nil {
		t.Errorf("a covered host was refused: %v", err)
	}
}

func TestImportRecon_EndpointsOnlyUnderOriginsTheUploaderMayChange(t *testing.T) {
	db := openLifecycleDB(t)
	ctx := context.Background()
	tenant := seedLifecycleTenant(ctx, t, db)
	other := seedLifecycleTenant(ctx, t, db)
	pg := &postgres.DB{DB: db}
	ing := ingest.NewService(
		postgres.NewAssetRepository(pg), postgres.NewFindingRepository(pg),
		postgres.NewVulnerabilityRepository(pg), postgres.NewComponentRepository(pg),
		postgres.NewSensorRepository(pg), postgres.NewBranchRepository(pg), postgres.NewTenantRepository(pg),
		postgres.NewAuditRepository(pg), logger.NewNop())
	ing.SetReceiptRecorder(postgres.NewIngestReceiptRepository(pg))
	ing.SetWebEndpointRepository(postgres.NewWebEndpointRepository(pg))

	// An origin asset the uploader may not change (outside their data scope).
	locked := shared.NewID()
	if _, err := db.ExecContext(ctx, `INSERT INTO assets (id, tenant_id, name, asset_type, sub_type, status) VALUES ($1, $2, 'https://locked.example.org', 'service', 'http', 'active')`,
		locked.String(), tenant.String()); err != nil {
		t.Fatal(err)
	}
	run := func(tid shared.ID, actor ingest.ActorScope, origin string) *ingest.Output {
		rep := &ctis.Report{Version: "1.0", Tool: &ctis.Tool{Name: "reconftw"},
			Endpoints: []ctis.Endpoint{{Origin: origin, Method: "GET", Path: "/a", Source: ctis.EndpointSourceImport}},
			Metadata:  ctis.ReportMetadata{ID: shared.NewID().String(), Timestamp: time.Now().UTC(), CoverageType: "partial"}}
		tt := tid
		out, err := ing.Ingest(ctx, &sensor.Sensor{TenantID: &tt, Status: sensor.SensorStatusActive}, ingest.Input{
			Report: rep, CoverageType: ingest.CoverageTypePartial,
			Options: ingest.Options{Actor: actor, SourceKind: "import", SourceName: "import:reconftw",
				Receipt: &ingestreceipt.Source{Kind: ingestreceipt.SourceUpload, Ref: shared.NewID().String()}},
		})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	count := func(tid shared.ID) (n int) {
		_ = db.QueryRowContext(ctx, `SELECT count(*) FROM web_endpoints WHERE tenant_id = $1`, tid.String()).Scan(&n)
		return n
	}
	// A restricted uploader (sees no asset) cannot add endpoints under the
	// existing origin, nor create a new origin.
	out := run(tenant, onlyIDs{}, "https://locked.example.org")
	if out.EndpointsCreated != 0 || out.EndpointsRefused == 0 || count(tenant) != 0 {
		t.Fatalf("restricted uploader wrote endpoints: %+v", out)
	}
	// An unrestricted uploader may.
	out = run(tenant, nil, "https://fresh.example.org")
	if out.EndpointsCreated != 1 || count(tenant) != 1 {
		t.Fatalf("unrestricted import: %+v", out)
	}
	if count(other) != 0 {
		t.Fatal("endpoints crossed tenants")
	}
}
