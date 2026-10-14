package integration

// Asset freshness (docs/architecture/asset-freshness.md) on a migrated
// database through the real ingest: a report's tool moves the clock of the
// classes it observes on the assets it wrote; an older report never moves
// it back; the asset's freshness and the inventory filter agree; records,
// reads and filters are tenant- and data-scope-isolated.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/ctis"

	assetapp "github.com/openctemio/openctem/api/internal/app/asset"
	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/assetfreshness"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type freshRig struct {
	t      *testing.T
	r      *v2Rig
	tn     v2Tenant
	assets *assetapp.AssetService
	repo   *postgres.AssetFreshnessRepository
}

func newFreshRig(t *testing.T) *freshRig {
	t.Helper()
	var assets *assetapp.AssetService
	var repo *postgres.AssetFreshnessRepository
	r := newV2RigWith(t, ingest.DefaultBlindingGuard(), func(svc *ingest.Service, db *postgres.DB) {
		repo = postgres.NewAssetFreshnessRepository(db)
		assets = assetapp.NewAssetService(postgres.NewAssetRepository(db), logger.NewNop())
		assets.SetFreshness(repo)
		svc.SetAssetsObservedCallback(integrationRecorder(repo).AssetsObserved)
	})
	return &freshRig{t: t, r: r, tn: r.newTenant("dnsx"), assets: assets, repo: repo}
}

// importAs sends a server-side import of one asset reported by tool.
func (g *freshRig) importAs(tn v2Tenant, tool string, observed time.Time, a ctis.Asset) {
	g.t.Helper()
	tid := tn.tenant
	rep := &ctis.Report{Version: "1.0", Tool: &ctis.Tool{Name: tool}, Assets: []ctis.Asset{a},
		Metadata: ctis.ReportMetadata{Timestamp: observed}}
	agt := &sensor.Sensor{TenantID: &tid, Status: sensor.SensorStatusActive}
	opts := ingest.Options{SourceKind: asset.SourceKindImport, SourceName: "test-import"}
	if out, err := g.r.svc.Ingest(context.Background(), agt, ingest.Input{Report: rep, Options: opts}); err != nil || len(out.Errors) > 0 {
		g.t.Fatalf("Ingest: %v %v", err, out.Errors)
	}
}

func (g *freshRig) idOf(tn v2Tenant, name string) shared.ID {
	g.t.Helper()
	var id string
	if err := g.r.db.QueryRowContext(context.Background(),
		`SELECT id FROM assets WHERE tenant_id = $1 AND name = $2`, tn.tenant.String(), name).Scan(&id); err != nil {
		g.t.Fatalf("read %s: %v", name, err)
	}
	out, _ := shared.IDFromString(id)
	return out
}

func classOf(v *assetfreshness.AssetView, c assetfreshness.Class) *assetfreshness.ClassView {
	for i := range v.Classes {
		if v.Classes[i].Class == c {
			return &v.Classes[i]
		}
	}
	return nil
}

func subdomainAsset(name string) ctis.Asset {
	return ctis.Asset{ID: "s", Type: ctis.AssetTypeSubdomain, Value: name}
}

func TestAssetFreshness_IngestRecordsAndNeverRegresses(t *testing.T) {
	g := newFreshRig(t)
	ctx := context.Background()
	const name = "fresh-a.example.com"
	t0 := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Second)

	// A tool that observes no class (vulnerability templates) records nothing.
	g.importAs(g.tn, "nuclei", t0, subdomainAsset(name))
	id := g.idOf(g.tn, name)
	if obs, _ := g.repo.ListForAsset(ctx, g.tn.tenant, id); len(obs) != 0 {
		t.Fatalf("nuclei recorded %v", obs)
	}
	v, err := g.assets.GetFreshness(ctx, g.tn.tenant.String(), id.String())
	if err != nil || v.State != assetfreshness.StateNever {
		t.Fatalf("unobserved: %+v %v", v, err)
	}

	// The resolver observes DNS.
	g.importAs(g.tn, "dnsx", t0, subdomainAsset(name))
	v, err = g.assets.GetFreshness(ctx, g.tn.tenant.String(), id.String())
	if err != nil {
		t.Fatal(err)
	}
	dns := classOf(v, assetfreshness.ClassDNS)
	if dns == nil || dns.State != assetfreshness.StateLive || dns.Source != "dnsx" || !dns.ObservedAt.Equal(t0) {
		t.Fatalf("dns after dnsx: %+v", dns)
	}

	// A late report (older observation) does not move the clock back.
	g.importAs(g.tn, "dnsx", t0.Add(-48*time.Hour), subdomainAsset(name))
	v, _ = g.assets.GetFreshness(ctx, g.tn.tenant.String(), id.String())
	if dns = classOf(v, assetfreshness.ClassDNS); !dns.ObservedAt.Equal(t0) {
		t.Fatalf("late report moved dns back to %v", dns.ObservedAt)
	}
}

func TestAssetFreshness_FilterStaleAndNever(t *testing.T) {
	g := newFreshRig(t)
	ctx := context.Background()
	now := time.Now().UTC()
	g.importAs(g.tn, "dnsx", now.Add(-time.Hour), subdomainAsset("fresh-live.example.com"))
	g.importAs(g.tn, "dnsx", now.Add(-72*time.Hour), subdomainAsset("fresh-stale.example.com"))
	g.importAs(g.tn, "nuclei", now, subdomainAsset("fresh-never.example.com"))

	list := func(f string) map[string]bool {
		t.Helper()
		res, err := g.assets.ListAssets(ctx, assetapp.ListAssetsInput{TenantID: g.tn.tenant.String(), Freshness: f, PerPage: 100})
		if err != nil {
			t.Fatalf("list %s: %v", f, err)
		}
		out := map[string]bool{}
		for _, a := range res.Data {
			out[a.Name()] = true
		}
		return out
	}
	stale := list(assetfreshness.FilterStale)
	if !stale["fresh-stale.example.com"] || stale["fresh-live.example.com"] || stale["fresh-never.example.com"] {
		t.Fatalf("stale filter = %v", stale)
	}
	never := list(assetfreshness.FilterNever)
	if !never["fresh-never.example.com"] || never["fresh-live.example.com"] || never["fresh-stale.example.com"] {
		t.Fatalf("never filter = %v", never)
	}

	// Another tenant's stale asset never shows in this tenant's filter.
	other := g.r.newTenant("dnsx")
	g.importAs(other, "dnsx", now.Add(-72*time.Hour), subdomainAsset("fresh-other.example.com"))
	if stale = list(assetfreshness.FilterStale); stale["fresh-other.example.com"] {
		t.Fatal("another tenant's asset in the stale filter")
	}
}

func TestAssetFreshness_TenantAndScopeIsolation(t *testing.T) {
	g := newFreshRig(t)
	ctx := context.Background()
	const name = "fresh-iso.example.com"
	g.importAs(g.tn, "dnsx", time.Now().UTC().Add(-time.Hour), subdomainAsset(name))
	id := g.idOf(g.tn, name)
	other := g.r.newTenant("dnsx")

	// Another tenant cannot read it by id.
	if _, err := g.assets.GetFreshness(ctx, other.tenant.String(), id.String()); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("other tenant read freshness: %v", err)
	}
	// Another tenant cannot write rows for it: the asset id is not its own.
	old := time.Now().UTC().Add(-time.Hour)
	if err := g.repo.Record(ctx, other.tenant, []assetfreshness.Observation{
		{AssetID: id, Class: assetfreshness.ClassRegistration, ObservedAt: old, Source: "rdap"},
	}); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = g.r.db.QueryRowContext(ctx, `SELECT count(*) FROM asset_attribute_freshness WHERE asset_id = $1 AND class = 'registration'`, id.String()).Scan(&n)
	if n != 0 {
		t.Fatalf("a record for another tenant's asset was written (%d)", n)
	}
	if obs, _ := g.repo.ListForAsset(ctx, other.tenant, id); len(obs) != 0 {
		t.Fatalf("other tenant lists %v", obs)
	}

	// A member with no data-scope row does not see the asset's freshness.
	pg := &postgres.DB{DB: g.r.db}
	g.assets.SetDataScope(datascope.New(postgres.NewDataScopeRepository(pg), func(ctx context.Context) datascope.Caller {
		c, _ := ctx.Value(actCallerKey{}).(datascope.Caller)
		return c
	}, logger.NewNop()))
	member := seedActUser(t, g.r.db)
	if _, err := g.assets.GetFreshness(asCaller(ctx, datascope.Caller{UserID: member.String()}), g.tn.tenant.String(), id.String()); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("out-of-scope member read freshness: %v", err)
	}

	// Erasure: the records go with the asset's tenant.
	if _, err := g.r.db.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, g.tn.tenant.String()); err != nil {
		t.Fatal(err)
	}
	_ = g.r.db.QueryRowContext(ctx, `SELECT count(*) FROM asset_attribute_freshness WHERE tenant_id = $1`, g.tn.tenant.String()).Scan(&n)
	if n != 0 {
		t.Fatalf("%d freshness rows outlived their tenant", n)
	}
}

// Resolve before active (RFC-088): the freshest evidence of a name across
// the resolving classes, of the asking tenant's assets only.
func TestAssetFreshness_FreshestByName(t *testing.T) {
	g := newFreshRig(t)
	ctx := context.Background()
	other := g.r.newTenant("dnsx")
	const name = "evidence-a.example.com"
	old := time.Now().UTC().Add(-10 * 24 * time.Hour).Truncate(time.Second)
	recent := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)

	g.importAs(g.tn, "dnsx", old, subdomainAsset(name))
	g.importAs(g.tn, "httpx", recent, subdomainAsset(name))
	g.importAs(g.tn, "nuclei", recent, subdomainAsset("noevidence.example.com"))
	// Another tenant holds the same name with newer evidence.
	g.importAs(other, "dnsx", time.Now().UTC().Truncate(time.Second), subdomainAsset(name))

	ev, err := g.repo.FreshestByName(ctx, g.tn.tenant, []string{name, "noevidence.example.com", "unknown.example.com"},
		assetfreshness.ResolveEvidenceClasses)
	if err != nil {
		t.Fatal(err)
	}
	if len(ev) != 1 || ev[0].Name != name || ev[0].AssetID != g.idOf(g.tn, name) || !ev[0].ObservedAt.Equal(recent) {
		t.Fatalf("evidence = %+v, want the tenant's own asset at %v", ev, recent)
	}
	// Only the dns class: the older observation.
	ev, err = g.repo.FreshestByName(ctx, g.tn.tenant, []string{name}, []assetfreshness.Class{assetfreshness.ClassDNS})
	if err != nil || len(ev) != 1 || !ev[0].ObservedAt.Equal(old) {
		t.Fatalf("dns evidence = %+v %v", ev, err)
	}
}
