package integration

// Automatic asset enrichment (docs/architecture/asset-freshness.md) on a
// migrated database: one request per asset, cooldown and manual re-open,
// tenant-isolated requests and claims, and the enricher starting a passive
// run of the built-in profile for in-scope names only.

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	assetapp "github.com/openctemio/openctem/api/internal/app/asset"
	freshapp "github.com/openctemio/openctem/api/internal/app/assetfreshness"
	scansvc "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/assetfreshness"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func seedTypedAsset(t *testing.T, db *sql.DB, tenantID shared.ID, name, typ string) shared.ID {
	t.Helper()
	id := shared.NewID()
	if _, err := db.ExecContext(context.Background(),
		`INSERT INTO assets (id, tenant_id, name, asset_type, status) VALUES ($1, $2, $3, $4, 'active')`,
		id.String(), tenantID.String(), name, typ); err != nil {
		t.Fatalf("seed asset %s: %v", name, err)
	}
	return id
}

func TestEnrichmentRequests_IdempotentCooldownAndTenantIsolation(t *testing.T) {
	db := openLifecycleDB(t)
	ctx := context.Background()
	repo := postgres.NewAssetEnrichmentRequestRepository(&postgres.DB{DB: db})
	tenantA := seedLifecycleTenant(ctx, t, db)
	tenantB := seedLifecycleTenant(ctx, t, db)
	a1 := seedTypedAsset(t, db, tenantA, "er-a1.example.com", "subdomain")
	b1 := seedTypedAsset(t, db, tenantB, "er-b1.example.com", "subdomain")

	// Tenant A asking for tenant B's asset opens nothing.
	if n, err := repo.Request(ctx, tenantA, []shared.ID{b1}, assetfreshness.ReasonNewAsset, time.Hour); err != nil || n != 0 {
		t.Fatalf("cross-tenant request opened %d (%v)", n, err)
	}
	if q, _ := repo.Get(ctx, tenantB, b1); q != nil {
		t.Fatalf("cross-tenant request stored: %+v", q)
	}

	// One row per asset: a second request while pending changes nothing.
	if n, _ := repo.Request(ctx, tenantA, []shared.ID{a1}, assetfreshness.ReasonNewAsset, time.Hour); n != 1 {
		t.Fatalf("first request opened %d", n)
	}
	if n, _ := repo.Request(ctx, tenantA, []shared.ID{a1}, assetfreshness.ReasonNewAsset, time.Hour); n != 0 {
		t.Fatalf("pending request re-opened %d", n)
	}

	// Debounce: not due yet with a long debounce, due with zero.
	if due, _ := repo.TenantsDue(ctx, time.Hour, 1000); containsID(due, tenantA) {
		t.Fatal("tenant due before the debounce")
	}
	if due, _ := repo.TenantsDue(ctx, 0, 1000); !containsID(due, tenantA) {
		t.Fatal("tenant not due after the debounce")
	}

	// Tenant B claims nothing of tenant A.
	if ids, _ := repo.Claim(ctx, tenantB, 10); len(ids) != 0 {
		t.Fatalf("tenant B claimed %v", ids)
	}
	ids, err := repo.Claim(ctx, tenantA, 10)
	if err != nil || len(ids) != 1 || ids[0] != a1 {
		t.Fatalf("claim = %v %v", ids, err)
	}
	run := shared.NewID()
	if err := repo.Settle(ctx, tenantA, ids, assetfreshness.OutcomeDispatched, &run); err != nil {
		t.Fatal(err)
	}
	if n, _ := repo.DispatchedSince(ctx, tenantA, time.Now().Add(-time.Hour)); n != 1 {
		t.Fatalf("dispatched since = %d", n)
	}
	if n, _ := repo.DispatchedSince(ctx, tenantB, time.Now().Add(-time.Hour)); n != 0 {
		t.Fatalf("tenant B dispatched since = %d", n)
	}

	// Within the cooldown a new_asset request does not re-open; manual does.
	if n, _ := repo.Request(ctx, tenantA, []shared.ID{a1}, assetfreshness.ReasonNewAsset, time.Hour); n != 0 {
		t.Fatalf("re-opened within cooldown: %d", n)
	}
	if n, _ := repo.Request(ctx, tenantA, []shared.ID{a1}, assetfreshness.ReasonManual, time.Hour); n != 1 {
		t.Fatalf("manual did not re-open: %d", n)
	}
	q, _ := repo.Get(ctx, tenantA, a1)
	if q == nil || !q.Pending() || q.Reason != assetfreshness.ReasonManual || q.LastRunID == nil || *q.LastRunID != run {
		t.Fatalf("request after manual = %+v", q)
	}
}

func containsID(ids []shared.ID, id shared.ID) bool {
	for _, x := range ids {
		if x == id {
			return true
		}
	}
	return false
}

type fixedEASM struct{ disabled bool }

func (f fixedEASM) GetEASMSettings(context.Context, string) (*tenant.EASMSettings, error) {
	return &tenant.EASMSettings{EnrichmentDisabled: f.disabled}, nil
}

func TestEnricher_StartsPassiveRunForInScopeNamesOnly(t *testing.T) {
	db := openLifecycleDB(t)
	ctx := context.Background()
	pg := &postgres.DB{DB: db}
	tenantA := seedLifecycleTenant(ctx, t, db)
	tenantB := seedLifecycleTenant(ctx, t, db)
	seedScopeTarget(t, db, tenantA, "domain", "*.enrich.example.com")
	inScope := seedTypedAsset(t, db, tenantA, "app.enrich.example.com", "subdomain")
	internal := seedTypedAsset(t, db, tenantA, "localhost", "subdomain")
	repo := seedTypedAsset(t, db, tenantA, "github.com/acme/enrich", "repository")
	foreign := seedTypedAsset(t, db, tenantB, "b.enrich.example.com", "subdomain")
	// An inventory name no scope entry of the tenant covers.
	unscoped := seedTypedAsset(t, db, tenantA, "third-party.example.net", "subdomain")

	svc := newTriggerServiceWith(db, scansvc.WithScopeExclusionFilter(scopeService(db)),
		scansvc.WithActScope(actScopeChecker(db)), scansvc.WithAttributionGate(ownershipGate(db)))
	requests := postgres.NewAssetEnrichmentRequestRepository(pg)
	en := freshapp.NewEnricher(requests, postgres.NewAssetRepository(pg), fixedEASM{}, svc,
		freshapp.EnricherConfig{Debounce: time.Nanosecond}, logger.NewNop())

	if _, err := requests.Request(ctx, tenantA, []shared.ID{inScope, internal, repo, foreign, unscoped}, assetfreshness.ReasonNewAsset, time.Hour); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	if _, err := en.Run(ctx); err != nil {
		t.Fatal(err)
	}

	got := func(id shared.ID) *assetfreshness.Request {
		q, err := requests.Get(ctx, tenantA, id)
		if err != nil {
			t.Fatal(err)
		}
		return q
	}
	q := got(inScope)
	if q == nil || q.Outcome != assetfreshness.OutcomeDispatched || q.LastRunID == nil {
		t.Fatalf("in-scope request = %+v", q)
	}
	if q := got(internal); q == nil || q.Outcome != assetfreshness.OutcomeRefused {
		t.Fatalf("internal name request = %+v", q)
	}
	if q := got(unscoped); q == nil || q.Outcome != assetfreshness.OutcomeRefused {
		t.Fatalf("unscoped name request = %+v", q)
	}
	// A repository has no profile: settled without a run. Another tenant's
	// asset id was never stored for tenant A.
	if q := got(repo); q == nil || q.Outcome != assetfreshness.OutcomeNoProfile || q.LastRunID != nil {
		t.Fatalf("repository request = %+v", q)
	}
	if q := got(foreign); q != nil {
		t.Fatalf("foreign asset request = %+v", q)
	}

	// The run: passive, tagged, of the host-names profile, in tenant A, with
	// only the in-scope name.
	var intensity, workflow, tenantOf string
	var targets []byte
	if err := db.QueryRowContext(ctx, `
		SELECT s.intensity, s.scan_workflow_id::text, r.tenant_id::text, to_json(s.targets)::text
		  FROM scan_runs r JOIN scans s ON s.id = r.scan_id
		 WHERE r.id = $1`, q.LastRunID.String()).Scan(&intensity, &workflow, &tenantOf, &targets); err != nil {
		t.Fatalf("read run: %v", err)
	}
	if intensity != "passive" || workflow != "a0000003-0000-0000-0000-000000000002" || tenantOf != tenantA.String() ||
		string(targets) != `["app.enrich.example.com"]` {
		t.Fatalf("run = intensity %s workflow %s tenant %s targets %s", intensity, workflow, tenantOf, targets)
	}
}

func TestEnricher_DisabledTenantDrainsWithoutRun(t *testing.T) {
	db := openLifecycleDB(t)
	ctx := context.Background()
	pg := &postgres.DB{DB: db}
	tenantA := seedLifecycleTenant(ctx, t, db)
	id := seedTypedAsset(t, db, tenantA, "off.enrich.example.com", "subdomain")
	requests := postgres.NewAssetEnrichmentRequestRepository(pg)
	en := freshapp.NewEnricher(requests, postgres.NewAssetRepository(pg), fixedEASM{disabled: true}, nil,
		freshapp.EnricherConfig{Debounce: time.Nanosecond}, logger.NewNop())
	if _, err := requests.Request(ctx, tenantA, []shared.ID{id}, assetfreshness.ReasonNewAsset, time.Hour); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	if _, err := en.Run(ctx); err != nil {
		t.Fatal(err)
	}
	q, _ := requests.Get(ctx, tenantA, id)
	if q == nil || q.Outcome != assetfreshness.OutcomeDisabled || q.LastRunID != nil {
		t.Fatalf("disabled tenant request = %+v", q)
	}
}

// Assets a person creates (manual create, CSV import) are requested like the
// ones an ingest finds.
func TestEnrichment_ManualAndCSVCreatesAreRequested(t *testing.T) {
	db := openLifecycleDB(t)
	ctx := context.Background()
	pg := &postgres.DB{DB: db}
	tenantA := seedLifecycleTenant(ctx, t, db)
	requests := postgres.NewAssetEnrichmentRequestRepository(pg)
	en := freshapp.NewEnricher(requests, postgres.NewAssetRepository(pg), fixedEASM{}, nil, freshapp.EnricherConfig{}, logger.NewNop())
	hook := func(ctx context.Context, tenantID shared.ID, assets []*assetdom.Asset) {
		en.RequestAssets(ctx, tenantID, assets, assetfreshness.ReasonNewAsset)
	}
	svc := assetapp.NewAssetService(postgres.NewAssetRepository(pg), logger.NewNop())
	svc.SetCreatedAssetsHook(hook)
	imp := assetapp.NewAssetImportService(postgres.NewAssetRepository(pg), logger.NewNop())
	imp.SetCreatedAssetsHook(hook)

	a, err := svc.CreateAsset(ctx, assetapp.CreateAssetInput{TenantID: tenantA.String(), Name: "manual.enrich.example.com", Type: "subdomain", Criticality: "medium"})
	if err != nil {
		t.Fatal(err)
	}
	if q, _ := requests.Get(ctx, tenantA, a.ID()); q == nil || q.Reason != assetfreshness.ReasonNewAsset || !q.Pending() {
		t.Fatalf("manual create request = %+v", q)
	}
	if _, err := imp.ImportCSVAssets(ctx, tenantA.String(), strings.NewReader("name,type\ncsv.enrich.example.com,subdomain\n")); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = db.QueryRowContext(ctx, `SELECT count(*) FROM asset_enrichment_requests r JOIN assets a ON a.id = r.asset_id
		WHERE r.tenant_id = $1 AND a.name = 'csv.enrich.example.com'`, tenantA.String()).Scan(&n)
	if n != 1 {
		t.Fatalf("csv import requests = %d", n)
	}
}
