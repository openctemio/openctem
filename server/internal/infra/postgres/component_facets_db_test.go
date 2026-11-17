package postgres

// The facets read is one statement over the package set: it runs, returns
// every facet key, counts only the tenant's own packages, and a severity
// filter value outside the allowlist changes nothing (it never reaches the
// statement text).

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/component"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/software"
)

func TestComponentRepository_PackageFacets(t *testing.T) {
	db := catalogTestDB(t)
	ctx := context.Background()
	w := NewSoftwarePackageWriter(&DB{DB: db})
	repo := NewComponentRepository(&DB{DB: db})
	tenant, other := seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db)
	asset, otherAsset := seedTestAsset(ctx, t, db, tenant), seedTestAsset(ctx, t, db, other)
	name := "lib-" + shared.NewID().String()[:8]
	if _, err := w.WritePackages(ctx, tenant, software.PackageSnapshot{AssetID: asset, Replace: true,
		Packages: []software.PackageNode{pkgNode(t, "pkg:npm/"+name+"@1.0.0", "a", "direct")}}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.WritePackages(ctx, other, software.PackageSnapshot{AssetID: otherAsset, Replace: true,
		Packages: []software.PackageNode{pkgNode(t, "pkg:maven/org.example/"+name+"@1.0.0", "a", "transitive")}}); err != nil {
		t.Fatal(err)
	}

	got, err := repo.PackageFacets(ctx, component.Filter{TenantID: tenant})
	if err != nil {
		t.Fatalf("facets: %v", err)
	}
	for _, k := range []string{"ecosystem", "license", "severity", "kev", "has_fix", "relationship", "scope"} {
		if _, ok := got[k]; !ok {
			t.Fatalf("facet %q missing from %v", k, got)
		}
	}
	if len(got["relationship"]) != 1 || got["relationship"][0].Value != "direct" || got["relationship"][0].Count != 1 {
		t.Fatalf("relationship facet = %+v, want the tenant's one direct link only", got["relationship"])
	}

	// A hostile severity value is ignored: same result, no error.
	hostile, err := repo.PackageFacets(ctx, component.Filter{TenantID: tenant, Severities: []string{"critical) OR 1=1 --", "bogus"}})
	if err != nil {
		t.Fatalf("hostile severity: %v", err)
	}
	if len(hostile["relationship"]) != 1 || hostile["relationship"][0].Count != 1 {
		t.Fatalf("hostile severity changed the result: %+v", hostile["relationship"])
	}
}
