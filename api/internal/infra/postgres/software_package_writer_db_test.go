package postgres

// Package writer and inventory reads against a migrated database (RFC-070):
// observations stay tenant-private, snapshots replace their locations, the
// graph keeps every parent, licenses are per tenant, and the reads respect
// the data scope.

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/component"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/software"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

func pkgNode(t *testing.T, purl, ref, rel string, deps ...string) software.PackageNode {
	t.Helper()
	p, err := software.ParsePURL(purl)
	if err != nil {
		t.Fatal(err)
	}
	return software.PackageNode{Ref: ref, PURL: p, DisplayName: p.Name, Relationship: rel,
		Location: "package-lock.json", DependsOn: deps}
}

func TestPackageWriter_ObservationsStayTenantPrivate(t *testing.T) {
	db := catalogTestDB(t)
	ctx := context.Background()
	w := NewSoftwarePackageWriter(&DB{DB: db})
	tA, tB := seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db)
	aA, aB := seedTestAsset(ctx, t, db, tA), seedTestAsset(ctx, t, db, tB)
	name := "priv-" + shared.NewID().String()[:8]
	purl := "pkg:npm/" + name + "@1.0.0"

	for _, x := range []struct{ tenant, asset shared.ID }{{tA, aA}, {tB, aB}} {
		if _, err := w.WritePackages(ctx, x.tenant, software.PackageSnapshot{
			AssetID: x.asset, Packages: []software.PackageNode{pkgNode(t, purl, "a", "direct")}, Replace: true,
		}); err != nil {
			t.Fatal(err)
		}
	}
	var global, private int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FILTER (WHERE tenant_id IS NULL), count(*) FILTER (WHERE tenant_id IS NOT NULL)
		FROM software_products WHERE purl_type = 'npm' AND purl_name = $1`, name).Scan(&global, &private); err != nil {
		t.Fatal(err)
	}
	if global != 0 || private != 2 {
		t.Fatalf("products global=%d private=%d, want 0 and one per tenant", global, private)
	}

	// Once the feed publishes the identity, new observations use the global row.
	fname := "feed-" + shared.NewID().String()[:8]
	productID, _ := testdb.SeedPackageVersion(t, db, "", "pkg:npm/"+fname)
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM software_products WHERE id = $1`, productID)
	})
	vid, err := w.EnsurePackageVersion(ctx, tA, mustPURL(t, "pkg:npm/"+fname+"@2.0.0"))
	if err != nil {
		t.Fatal(err)
	}
	var vProduct string
	var vTenant *string
	if err := db.QueryRowContext(ctx, `SELECT product_id, tenant_id FROM software_versions WHERE id = $1`, vid.String()).Scan(&vProduct, &vTenant); err != nil {
		t.Fatal(err)
	}
	if vProduct != productID || vTenant != nil {
		t.Fatalf("version of a feed package: product %s tenant %v, want the global product and no tenant", vProduct, vTenant)
	}
}

func mustPURL(t *testing.T, s string) software.PURL {
	t.Helper()
	p, err := software.ParsePURL(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPackageWriter_SnapshotGraphAndReplace(t *testing.T) {
	db := catalogTestDB(t)
	ctx := context.Background()
	w := NewSoftwarePackageWriter(&DB{DB: db})
	repo := NewComponentRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	asset := seedTestAsset(ctx, t, db, tenant)
	sfx := shared.NewID().String()[:8]
	app, lib, util := "pkg:npm/app-"+sfx+"@1.0.0", "pkg:npm/lib-"+sfx+"@2.0.0", "pkg:npm/util-"+sfx+"@3.0.0"

	// app -> lib -> util, app -> util, and a cycle util -> lib.
	res, err := w.WritePackages(ctx, tenant, software.PackageSnapshot{AssetID: asset, Channel: software.ChannelSensor, Replace: true,
		Packages: []software.PackageNode{
			pkgNode(t, app, "app", "direct", "lib", "util"),
			pkgNode(t, lib, "lib", "unknown", "util"),
			pkgNode(t, util, "util", "unknown", "lib"),
			pkgNode(t, util, "util-dup", "unknown"),
		}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Links != 3 || res.Edges != 4 {
		t.Fatalf("write = %+v, want 3 links (duplicate folded) and 4 edges", res)
	}
	usages, err := repo.ListAssetPackages(ctx, tenant, asset, pagination.New(1, 50))
	if err != nil {
		t.Fatal(err)
	}
	depth := map[string]int{}
	for _, u := range usages.Data {
		if u.Depth == nil {
			t.Fatalf("%s has no depth", u.PURL)
		}
		depth[u.PURL] = *u.Depth
		if u.Channel != software.ChannelSensor {
			t.Errorf("%s channel %q", u.PURL, u.Channel)
		}
	}
	if depth[app] != 0 || depth[lib] != 1 || depth[util] != 1 {
		t.Errorf("depths = %v", depth)
	}

	var utilVersion string
	if err := db.QueryRowContext(ctx, `SELECT id FROM software_versions WHERE purl = $1`, util).Scan(&utilVersion); err != nil {
		t.Fatal(err)
	}
	paths, err := repo.DependencyPaths(ctx, tenant, asset, shared.MustIDFromString(utilVersion), 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) < 2 || len(paths[0]) != 2 || paths[0][0].PURL != app {
		t.Fatalf("paths = %+v, want app->util first and app->lib->util", paths)
	}
	g, err := repo.DependencyGraph(ctx, tenant, asset, nil, 0, 0)
	if err != nil || len(g.Nodes) != 3 || len(g.Edges) != 4 || g.Truncated {
		t.Fatalf("graph = %+v %v", g, err)
	}
	if g, err := repo.DependencyGraph(ctx, tenant, asset, nil, 0, 1); err != nil || len(g.Nodes) != 1 || !g.Truncated {
		t.Fatalf("bounded graph = %+v %v, want 1 node and truncated", g, err)
	}

	// A new snapshot of the same location without util drops it and its edges.
	if _, err := w.WritePackages(ctx, tenant, software.PackageSnapshot{AssetID: asset, Replace: true,
		Packages: []software.PackageNode{pkgNode(t, app, "app", "direct", "lib"), pkgNode(t, lib, "lib", "unknown")}}); err != nil {
		t.Fatal(err)
	}
	var links, edges int
	_ = db.QueryRowContext(ctx, `SELECT count(*) FROM asset_software WHERE asset_id = $1 AND source = 'package'`, asset.String()).Scan(&links)
	_ = db.QueryRowContext(ctx, `SELECT count(*) FROM asset_software_edges WHERE asset_id = $1`, asset.String()).Scan(&edges)
	if links != 2 || edges != 1 {
		t.Fatalf("after replace: links=%d edges=%d, want 2 and 1", links, edges)
	}
}

func TestPackageWriter_LicensesAreTenantLocal(t *testing.T) {
	db := catalogTestDB(t)
	ctx := context.Background()
	w := NewSoftwarePackageWriter(&DB{DB: db})
	repo := NewComponentRepository(&DB{DB: db})
	tA, tB := seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db)
	aA, aB := seedTestAsset(ctx, t, db, tA), seedTestAsset(ctx, t, db, tB)
	purl := "pkg:npm/lic-" + shared.NewID().String()[:8] + "@1.0.0"
	write := func(tenant, asset shared.ID, lic ...string) {
		n := pkgNode(t, purl, "x", "direct")
		n.Licenses = lic
		if _, err := w.WritePackages(ctx, tenant, software.PackageSnapshot{AssetID: asset, Packages: []software.PackageNode{n}}); err != nil {
			t.Fatal(err)
		}
	}
	write(tA, aA, "AGPL-3.0-only")
	write(tB, aB, "MIT")
	licenses := func(tenant shared.ID) map[string]bool {
		f, err := repo.PackageFacets(ctx, component.Filter{TenantID: tenant})
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]bool{}
		for _, v := range f["license"] {
			out[v.Value] = true
		}
		return out
	}
	if b := licenses(tB); b["AGPL-3.0-only"] || !b["MIT"] {
		t.Errorf("tenant B licenses = %v, want only MIT", b)
	}
	if a := licenses(tA); !a["AGPL-3.0-only"] || a["MIT"] {
		t.Errorf("tenant A licenses = %v, want only AGPL-3.0-only", a)
	}
	write(tB, aB) // a re-scan without a license keeps the recorded one
	if b := licenses(tB); !b["MIT"] {
		t.Errorf("license lost on re-scan: %v", b)
	}
}

func TestPackageWriter_RefusesAnotherTenantsAsset(t *testing.T) {
	db := catalogTestDB(t)
	ctx := context.Background()
	w := NewSoftwarePackageWriter(&DB{DB: db})
	tA, tB := seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db)
	aA := seedTestAsset(ctx, t, db, tA)
	if _, err := w.WritePackages(ctx, tB, software.PackageSnapshot{AssetID: aA,
		Packages: []software.PackageNode{pkgNode(t, "pkg:npm/x-"+shared.NewID().String()[:8]+"@1", "x", "direct")}}); err == nil {
		t.Fatal("tenant B wrote a package link on tenant A's asset")
	}
	var n int
	_ = db.QueryRowContext(ctx, `SELECT count(*) FROM asset_software WHERE asset_id = $1`, aA.String()).Scan(&n)
	if n != 0 {
		t.Fatalf("links on A's asset: %d", n)
	}
}

func TestComponentRepository_PackageReads(t *testing.T) {
	db := catalogTestDB(t)
	ctx := context.Background()
	w := NewSoftwarePackageWriter(&DB{DB: db})
	repo := NewComponentRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	asset := seedTestAsset(ctx, t, db, tenant)
	purl := "pkg:npm/reads-" + shared.NewID().String()[:8] + "@1.0.0"
	if _, err := w.WritePackages(ctx, tenant, software.PackageSnapshot{AssetID: asset,
		Packages: []software.PackageNode{pkgNode(t, purl, "r", "direct")}}); err != nil {
		t.Fatal(err)
	}
	list, err := repo.ListPackages(ctx, component.Filter{TenantID: tenant, Sort: "-risk"}, pagination.New(1, 10))
	if err != nil || list.Total != 1 {
		t.Fatalf("list = %+v %v", list, err)
	}
	id := shared.MustIDFromString(list.Data[0].ID)
	d, err := repo.GetPackage(ctx, tenant, id, nil)
	if err != nil || d.PURL != mustPURL(t, purl).Base() || d.Global {
		t.Fatalf("detail = %+v %v", d, err)
	}
	if _, err := repo.GetPackage(ctx, seedTestTenant(ctx, t, db), id, nil); err == nil {
		t.Fatal("another tenant read the package")
	}
	vs, err := repo.ListVersions(ctx, tenant, id, nil)
	if err != nil || len(vs) != 1 || vs[0].Version != "1.0.0" {
		t.Fatalf("versions = %+v %v", vs, err)
	}
	us, err := repo.ListUsages(ctx, tenant, id, component.UsageFilter{}, nil, pagination.New(1, 10))
	if err != nil || us.Total != 1 {
		t.Fatalf("usages = %+v %v", us, err)
	}
	if _, err := repo.ListVulnerabilities(ctx, tenant, id, true, nil, pagination.New(1, 10)); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Summary(ctx, component.Filter{TenantID: tenant}); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.GetFindingComponent(ctx, tenant, shared.MustIDFromString(vs[0].ID), &asset); err != nil {
		t.Fatal(err)
	}
}
