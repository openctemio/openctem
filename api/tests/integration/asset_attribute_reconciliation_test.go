package integration

// Attribute reconciliation (RFC-069) through the real ingest on a migrated
// database: the asset shows the value of the most trusted, most recent
// source; a report delivered late never undoes a newer one; a sensor cannot
// set what it is not trusted for; a person's lock wins until released; and
// nothing crosses tenants.

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/ctis"

	assetapp "github.com/openctemio/openctem/api/internal/app/asset"
	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type reconcileRig struct {
	t      *testing.T
	r      *v2Rig
	tn     v2Tenant
	assets *assetapp.AssetService
	repo   *postgres.AssetAttributeSourceRepository
}

func newReconcileRig(t *testing.T) *reconcileRig {
	t.Helper()
	var assets *assetapp.AssetService
	var repo *postgres.AssetAttributeSourceRepository
	r := newV2RigWith(t, ingest.DefaultBlindingGuard(), func(svc *ingest.Service, db *postgres.DB) {
		repo = postgres.NewAssetAttributeSourceRepository(db)
		assets = assetapp.NewAssetService(postgres.NewAssetRepository(db), logger.NewNop())
		assets.SetAttributeSources(repo, postgres.NewTenantRepository(db))
		assets.SetStateHistoryRepository(postgres.NewAssetStateHistoryRepository(db))
		svc.SetAttributeReconciler(assets)
	})
	return &reconcileRig{t: t, r: r, tn: r.newTenant("nmap", "httpx"), assets: assets, repo: repo}
}

// report sends one asset. kind "" is a sensor report bound to a command on
// the asset; import / integration are server-side ingests.
func (g *reconcileRig) report(kind asset.SourceKind, observed time.Time, a ctis.Asset) {
	g.t.Helper()
	tid := g.tn.tenant
	rep := &ctis.Report{Version: "1.0", Tool: &ctis.Tool{Name: "nmap"}, Assets: []ctis.Asset{a},
		Metadata: ctis.ReportMetadata{Timestamp: observed}}
	var agt *sensor.Sensor
	var opts ingest.Options
	if kind == "" {
		agt = &sensor.Sensor{ID: g.tn.sensor, TenantID: &tid, Type: sensor.SensorTypeWorker, Status: sensor.SensorStatusActive}
		opts = ingest.Options{Binding: ingest.Binding{Kind: ingest.BindingCommand, Targets: []string{a.Value}}}
	} else {
		agt = &sensor.Sensor{TenantID: &tid, Status: sensor.SensorStatusActive}
		opts = ingest.Options{SourceKind: kind, SourceName: string(kind) + "-feed"}
	}
	out, err := g.r.svc.Ingest(context.Background(), agt, ingest.Input{Report: rep, Options: opts})
	if err != nil || len(out.Errors) > 0 {
		g.t.Fatalf("Ingest: %v %v", err, out.Errors)
	}
}

func (g *reconcileRig) attrs(name string) (crit, owner, exposure, dc string) {
	g.t.Helper()
	if err := g.r.db.QueryRowContext(context.Background(), `
		SELECT criticality, COALESCE(owner_ref, ''), exposure, COALESCE(data_classification, '')
		  FROM assets WHERE tenant_id = $1 AND name = $2`, g.tn.tenant.String(), name).
		Scan(&crit, &owner, &exposure, &dc); err != nil {
		g.t.Fatalf("read %s: %v", name, err)
	}
	return
}

func (g *reconcileRig) assetID(name string) string {
	g.t.Helper()
	var id string
	if err := g.r.db.QueryRowContext(context.Background(),
		`SELECT id FROM assets WHERE tenant_id = $1 AND name = $2`, g.tn.tenant.String(), name).Scan(&id); err != nil {
		g.t.Fatalf("read %s: %v", name, err)
	}
	return id
}

func reconHost(name string) ctis.Asset {
	return ctis.Asset{ID: "h", Type: ctis.AssetTypeHost, Value: name}
}

func withClaims(a ctis.Asset, crit, owner, dc string) ctis.Asset {
	a.Criticality = ctis.Criticality(crit)
	a.Properties = ctis.Properties{}
	if owner != "" {
		a.Properties["owner"] = owner
	}
	if dc != "" {
		a.Compliance = &ctis.AssetCompliance{DataClassification: dc}
	}
	return a
}

func TestAttributeReconciliation_PrecedenceRecencyAndOrder(t *testing.T) {
	g := newReconcileRig(t)
	const name = "app-1.example.com"
	now := time.Now().UTC()

	// A scan creates the asset and claims an owner and a classification:
	// scanners are not trusted for them, so the asset takes neither.
	g.report("", now.Add(-3*time.Hour), withClaims(reconHost(name), "low", "evil@attacker.test", "public"))
	_, owner, _, dc := g.attrs(name)
	if owner != "" || dc != "" {
		t.Fatalf("a scan set owner %q / classification %q", owner, dc)
	}

	// An import states owner and criticality: trusted, it decides.
	g.report(asset.SourceKindImport, now.Add(-2*time.Hour), withClaims(reconHost(name), "high", "alice@example.com", "internal"))
	crit, owner, _, dc := g.attrs(name)
	if crit != "high" || owner != "alice@example.com" || dc != "internal" {
		t.Fatalf("after import: %s %s %s", crit, owner, dc)
	}

	// An integration outranks the import even with an older observation.
	g.report(asset.SourceKindIntegration, now.Add(-24*time.Hour), withClaims(reconHost(name), "critical", "bob@example.com", ""))
	crit, owner, _, dc = g.attrs(name)
	if crit != "critical" || owner != "bob@example.com" || dc != "internal" {
		t.Fatalf("after integration: %s %s %s (dc stays from the import: the integration did not state it)", crit, owner, dc)
	}

	// The same integration's report observed earlier, delivered late, does
	// not undo its newer one.
	g.report(asset.SourceKindIntegration, now.Add(-72*time.Hour), withClaims(reconHost(name), "low", "carol@example.com", ""))
	crit, owner, _, _ = g.attrs(name)
	if crit != "critical" || owner != "bob@example.com" {
		t.Fatalf("a late, older report changed the asset: %s %s", crit, owner)
	}

	// Its newer report does.
	g.report(asset.SourceKindIntegration, now.Add(-time.Minute), withClaims(reconHost(name), "medium", "dave@example.com", ""))
	crit, owner, _, _ = g.attrs(name)
	if crit != "medium" || owner != "dave@example.com" {
		t.Fatalf("a newer report did not decide: %s %s", crit, owner)
	}

	// Every change is in the asset history with its source.
	var n int
	if err := g.r.db.QueryRowContext(context.Background(), `
		SELECT count(*) FROM asset_state_history
		 WHERE tenant_id = $1 AND asset_id = $2 AND change_type = 'criticality_changed' AND source = 'integration'`,
		g.tn.tenant.String(), g.assetID(name)).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("integration criticality changes in history = %d, want 2", n)
	}
}

func TestAttributeReconciliation_ScanDecidesExposureButNotOwner(t *testing.T) {
	g := newReconcileRig(t)
	const name = "edge.example.com"
	now := time.Now().UTC()

	inv := reconHost(name)
	inv.Properties = ctis.Properties{"exposure": "private", "owner": "ops@example.com"}
	g.report(asset.SourceKindIntegration, now.Add(-time.Hour), inv)
	if _, owner, exp, _ := g.attrs(name); exp != "private" || owner != "ops@example.com" {
		t.Fatalf("inventory: exposure %q owner %q", exp, owner)
	}

	// A scan that reached the host from the internet outranks the inventory
	// for exposure; its owner claim changes nothing.
	scan := reconHost(name)
	scan.IsInternetAccessible = true
	scan.Properties = ctis.Properties{"owner": "evil@attacker.test"}
	g.report("", now, scan)
	if _, owner, exp, _ := g.attrs(name); exp != "public" || owner != "ops@example.com" {
		t.Fatalf("after scan: exposure %q owner %q", exp, owner)
	}

	views, err := g.assets.GetAttributeSources(context.Background(), g.tn.tenant.String(), g.assetID(name))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range views {
		switch v.Attribute {
		case asset.AttrExposure:
			// scan outranks the inventory for exposure: precedence, not a conflict
			if v.Conflict || v.Winner == nil || v.Winner.Kind != asset.SourceKindScan {
				t.Errorf("exposure: conflict %v winner %+v", v.Conflict, v.Winner)
			}
		case asset.AttrOwnerRef:
			var untrusted bool
			for _, c := range v.Candidates {
				if c.Kind == asset.SourceKindScan && c.Status == asset.CandidateUntrusted {
					untrusted = true
				}
			}
			if !untrusted || v.Conflict {
				t.Errorf("owner: the scan's claim must show as untrusted and not as a conflict: %+v", v.Candidates)
			}
		}
	}
}

func TestAttributeReconciliation_LockWinsUntilReleased(t *testing.T) {
	g := newReconcileRig(t)
	const name = "db.example.com"
	ctx := context.Background()
	now := time.Now().UTC()

	g.report(asset.SourceKindIntegration, now.Add(-time.Hour), withClaims(reconHost(name), "critical", "", ""))
	id := g.assetID(name)
	actor := shared.NewID().String()

	if _, err := g.assets.LockAttribute(ctx, g.tn.tenant.String(), id, "criticality", "low", actor); err != nil {
		t.Fatal(err)
	}
	g.report(asset.SourceKindIntegration, now, withClaims(reconHost(name), "high", "", ""))
	if crit, _, _, _ := g.attrs(name); crit != "low" {
		t.Fatalf("a source changed a locked value: %s", crit)
	}

	v, err := g.assets.ReleaseAttributeLock(ctx, g.tn.tenant.String(), id, "criticality", actor)
	if err != nil {
		t.Fatal(err)
	}
	if crit, _, _, _ := g.attrs(name); crit != "high" || v.Locked {
		t.Fatalf("after release: %s locked=%v, want high from the integration", crit, v.Locked)
	}

	// A value the attribute refuses is refused, and an unknown attribute too.
	if _, err := g.assets.LockAttribute(ctx, g.tn.tenant.String(), id, "criticality", "urgent", actor); err == nil {
		t.Error("an invalid criticality was locked")
	}
	if _, err := g.assets.LockAttribute(ctx, g.tn.tenant.String(), id, "name", "x", actor); err == nil {
		t.Error("an untracked attribute was locked")
	}
}

func TestAttributeReconciliation_PersonEditBecomesLock(t *testing.T) {
	g := newReconcileRig(t)
	const name = "crm.example.com"
	ctx := context.Background()
	g.report(asset.SourceKindImport, time.Now().UTC().Add(-time.Hour), withClaims(reconHost(name), "low", "", ""))
	id := g.assetID(name)

	crit := "critical"
	if _, err := g.assets.UpdateAsset(ctx, id, g.tn.tenant.String(), assetapp.UpdateAssetInput{
		Criticality: &crit, ActorID: shared.NewID().String(),
	}); err != nil {
		t.Fatal(err)
	}
	g.report(asset.SourceKindImport, time.Now().UTC(), withClaims(reconHost(name), "medium", "", ""))
	if c, _, _, _ := g.attrs(name); c != "critical" {
		t.Fatalf("an import overwrote a person's edit: %s", c)
	}
}

func TestAttributeReconciliation_TenantIsolation(t *testing.T) {
	g := newReconcileRig(t)
	other := g.r.newTenant("nmap")
	ctx := context.Background()
	const name = "shared-name.example.com"
	g.report(asset.SourceKindImport, time.Now().UTC().Add(-time.Hour), withClaims(reconHost(name), "low", "", ""))
	foreignID := shared.NewID()
	if _, err := g.r.db.ExecContext(ctx, `INSERT INTO assets (id, tenant_id, name, asset_type, criticality) VALUES ($1, $2, $3, 'host', 'low')`,
		foreignID.String(), other.tenant.String(), name); err != nil {
		t.Fatal(err)
	}

	// Observations naming another tenant's asset write nothing to it.
	changes, err := g.repo.Apply(ctx, g.tn.tenant, asset.AttributeApply{
		Observations: []asset.AttributeObservation{{AssetID: foreignID, Attribute: asset.AttrCriticality,
			Kind: asset.SourceKindIntegration, Name: "x", Value: "critical", ObservedAt: time.Now(), Confidence: 100}},
		Policy: asset.DefaultReconciliationPolicy(), Now: time.Now(),
	})
	if err != nil || len(changes.Changes) != 0 || changes.Events != 0 {
		t.Fatalf("cross-tenant apply: %v %v", changes, err)
	}
	var crit string
	var rows int
	_ = g.r.db.QueryRowContext(ctx, `SELECT criticality FROM assets WHERE id = $1`, foreignID.String()).Scan(&crit)
	_ = g.r.db.QueryRowContext(ctx, `SELECT count(*) FROM asset_attribute_sources WHERE asset_id = $1`, foreignID.String()).Scan(&rows)
	if crit != "low" || rows != 0 {
		t.Fatalf("another tenant's asset changed: criticality %s, %d source rows", crit, rows)
	}

	// The other tenant's sources view of tenant A's asset is not found, and
	// a lock through it does nothing.
	if _, err := g.assets.GetAttributeSources(ctx, other.tenant.String(), g.assetID(name)); err == nil {
		t.Error("another tenant read the sources")
	}
	if _, err := g.assets.LockAttribute(ctx, other.tenant.String(), g.assetID(name), "criticality", "critical", shared.NewID().String()); err == nil {
		t.Error("another tenant locked the asset")
	}
	if c, _, _, _ := g.attrs(name); c != "low" {
		t.Fatalf("tenant A's asset changed: %s", c)
	}
}
