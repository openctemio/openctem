package integration

// Asset technologies (RFC-112) through the real ingest on a migrated
// database: every detection is a categorized technology; only a product
// with a version becomes a software component; a technology the same probe
// no longer sees leaves with the reconciled set; nothing crosses tenants.

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/ctis"

	assetapp "github.com/openctemio/openctem/api/internal/app/asset"
	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/assettech"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func newTechRig(t *testing.T) *setRig {
	t.Helper()
	var assets *assetapp.AssetService
	r := newV2RigWith(t, ingest.DefaultBlindingGuard(), func(svc *ingest.Service, db *postgres.DB) {
		assets = wireSetReconciliation(svc, db)
		svc.SetTechnologyRepository(postgres.NewAssetTechnologyRepository(db))
		svc.SetSoftwareRepository(postgres.NewSoftwareRepository(db))
	})
	return &setRig{t: t, r: r, tn: r.newTenant("httpx"), assets: assets}
}

func (g *setRig) technologies(tn v2Tenant, name string) map[string]assettech.Technology {
	g.t.Helper()
	id := g.assetID(tn, name)
	list, err := postgres.NewAssetTechnologyRepository(&postgres.DB{DB: g.r.db}).ListByAsset(context.Background(), tn.tenant, id)
	if err != nil {
		g.t.Fatal(err)
	}
	out := map[string]assettech.Technology{}
	for _, t := range list {
		out[t.Key] = t
	}
	return out
}

func (g *setRig) assetID(tn v2Tenant, name string) shared.ID {
	g.t.Helper()
	var s string
	if err := g.r.db.QueryRowContext(context.Background(), `SELECT id FROM assets WHERE tenant_id = $1 AND name = $2`,
		tn.tenant.String(), name).Scan(&s); err != nil {
		g.t.Fatalf("asset %s: %v", name, err)
	}
	id, _ := shared.IDFromString(s)
	return id
}

func TestAssetTechnologies_Ingest(t *testing.T) {
	g := newTechRig(t)
	const name = "www.tech.example.com"
	now := time.Now().UTC()
	probe := func(at time.Time, techs ...any) {
		t.Helper()
		g.send(g.tn, "httpx", at, "", ctis.Asset{ID: "d", Type: ctis.AssetTypeDomain, Value: name,
			Properties: ctis.Properties{"technologies": techs}})
	}

	probe(now.Add(-30*time.Minute), "HSTS", "Vercel", "Next.js:13.4.1", "nginx")
	got := g.technologies(g.tn, name)
	want := map[string]assettech.Category{
		"hsts": assettech.CategorySecurityHeader, "vercel": assettech.CategoryHosting,
		"next.js": assettech.CategoryFramework, "nginx": assettech.CategoryWebServer,
	}
	if len(got) != len(want) {
		t.Fatalf("technologies: %+v", got)
	}
	for k, c := range want {
		if got[k].Category != c || got[k].Source != "httpx" {
			t.Errorf("%s = %+v, want category %s from httpx", k, got[k], c)
		}
	}
	if got["next.js"].Version != "13.4.1" {
		t.Errorf("version lost: %+v", got["next.js"])
	}

	// Only Next.js (a product with a version) is a component; HSTS, Vercel
	// and a versionless nginx are not.
	var components []string
	rows, err := g.r.db.QueryContext(context.Background(), `
		SELECT p.name FROM asset_software s JOIN software_products p ON p.id = s.product_id
		 WHERE s.tenant_id = $1 AND s.asset_id = $2 ORDER BY 1`, g.tn.tenant.String(), g.assetID(g.tn, name).String())
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var n string
		_ = rows.Scan(&n)
		components = append(components, n)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(components) != 1 {
		t.Fatalf("components = %v, want only the versioned framework", components)
	}

	// The same probe no longer sees Vercel: the technology leaves with the
	// reconciled set; the others keep their first sighting.
	first := got["hsts"].FirstSeen
	probe(now.Add(-10*time.Minute), "HSTS", "Next.js:13.4.2", "nginx")
	got = g.technologies(g.tn, name)
	if _, ok := got["vercel"]; ok || len(got) != 3 {
		t.Fatalf("after the re-probe: %+v", got)
	}
	if !got["hsts"].FirstSeen.Equal(first) || !got["hsts"].LastSeen.After(first) {
		t.Errorf("first/last seen: %+v (first %v)", got["hsts"], first)
	}
	if got["next.js"].Version != "13.4.2" {
		t.Errorf("version not updated: %+v", got["next.js"])
	}

	// The technologies live only in asset_technologies: the asset keeps no
	// properties.technologies.
	var has bool
	if err := g.r.db.QueryRowContext(context.Background(), `SELECT properties ? 'technologies' FROM assets WHERE id = $1`,
		g.assetID(g.tn, name).String()).Scan(&has); err != nil {
		t.Fatal(err)
	}
	if has {
		t.Fatal("the asset still stores properties.technologies")
	}

	// Another fingerprinting tool reports an older nginx: one technology,
	// the better version.
	g.send(g.tn, "httpx", now.Add(-5*time.Minute), "", ctis.Asset{ID: "d", Type: ctis.AssetTypeDomain, Value: name,
		Technologies: []ctis.Technology{{Name: "nginx", Version: "1.25.3", Confidence: 80}, {Name: "HSTS"}, {Name: "Next.js", Version: "13.4.2"}}})
	got = g.technologies(g.tn, name)
	if len(got) != 3 || got["nginx"].Version != "1.25.3" || got["nginx"].Confidence != 80 {
		t.Fatalf("after the typed report: %+v", got)
	}
}

func TestAssetTechnologies_TenantIsolation(t *testing.T) {
	g := newTechRig(t)
	other := g.r.newTenant("httpx")
	const name = "iso.tech.example.com"
	g.send(g.tn, "httpx", time.Now().UTC().Add(-time.Minute), "", ctis.Asset{ID: "d", Type: ctis.AssetTypeDomain, Value: name,
		Properties: ctis.Properties{"technologies": []any{"nginx:1.25.3"}}})
	id := g.assetID(g.tn, name)
	repo := postgres.NewAssetTechnologyRepository(&postgres.DB{DB: g.r.db})
	ctx := context.Background()

	// Tenant B naming tenant A's asset changes nothing and reads nothing.
	tech, _ := assettech.Observation(id, "nginx", "", []string{"CDN"}, 99, "evil", time.Now())
	if err := repo.Enrich(ctx, other.tenant, []assettech.Technology{tech}); err != nil {
		t.Fatal(err)
	}
	if list, err := repo.ListByAsset(ctx, other.tenant, id); err != nil || len(list) != 0 {
		t.Fatalf("tenant B reads tenant A's technologies: %v %v", list, err)
	}
	if m, err := repo.ListByAssets(ctx, other.tenant, []shared.ID{id}, 10); err != nil || len(m) != 0 {
		t.Fatalf("tenant B lists tenant A's technologies: %v %v", m, err)
	}
	got := g.technologies(g.tn, name)
	if len(got) != 1 || got["nginx"].Version != "1.25.3" || got["nginx"].Source != "httpx" || got["nginx"].Confidence != 0 {
		t.Fatalf("tenant A's technologies changed: %+v", got)
	}
}

// Versioned products a probe names (technologies and the Server header)
// become software components resolved to the curated catalog, so CVE
// matching works for internet-facing assets.
func TestAssetTechnologies_VersionedProductsAreCPEComponents(t *testing.T) {
	g := newTechRig(t)
	const name = "cpe.tech.example.com"
	g.send(g.tn, "httpx", time.Now().UTC().Add(-time.Minute), "", ctis.Asset{ID: "d", Type: ctis.AssetTypeDomain, Value: name,
		Properties: ctis.Properties{"technologies": []any{"nginx:1.18.0", "HSTS", "Vercel"}, "server": "Apache/2.4.41 (Ubuntu)"}})
	rows, err := g.r.db.QueryContext(context.Background(), `
		SELECT lower(p.name), p.cpe_vendor IS NOT NULL AND p.tenant_id IS NULL
		  FROM asset_software s JOIN software_products p ON p.id = s.product_id
		 WHERE s.tenant_id = $1 AND s.asset_id = $2`, g.tn.tenant.String(), g.assetID(g.tn, name).String())
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	got := map[string]bool{}
	for rows.Next() {
		var n string
		var cpe bool
		_ = rows.Scan(&n, &cpe)
		got[n] = cpe
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("components = %v, want nginx and Apache only", got)
	}
	for n, cpe := range got {
		if !cpe {
			t.Errorf("%s is not resolved to a curated CPE product", n)
		}
	}
}
