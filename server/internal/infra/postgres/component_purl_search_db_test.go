package postgres

// Searching the package list with a pasted package URL: an exact package,
// narrowed to links of its version when it has one, within the tenant and
// the caller's data scope.

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/component"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/software"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

func TestComponentRepository_SearchByPackageURL(t *testing.T) {
	db := catalogTestDB(t)
	ctx := context.Background()
	w := NewSoftwarePackageWriter(&DB{DB: db})
	repo := NewComponentRepository(&DB{DB: db})
	tenant, other := seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db)
	inScope, outOfScope := seedTestAsset(ctx, t, db, tenant), seedTestAsset(ctx, t, db, tenant)
	otherAsset := seedTestAsset(ctx, t, db, other)
	name := "lib-" + shared.NewID().String()[:8]
	base := "pkg:maven/org.example/" + name
	npm := "pkg:npm/@acme/" + name

	write := func(tn, asset shared.ID, purls ...string) {
		t.Helper()
		nodes := make([]software.PackageNode, 0, len(purls))
		for i, p := range purls {
			nodes = append(nodes, pkgNode(t, p, string(rune('a'+i)), "direct"))
		}
		if _, err := w.WritePackages(ctx, tn, software.PackageSnapshot{AssetID: asset, Packages: nodes, Replace: true}); err != nil {
			t.Fatal(err)
		}
	}
	// A look-alike package whose name contains the searched one: a name
	// search would match it, a package URL must not.
	write(tenant, inScope, base+"@1.0.0", base+"-extra@1.0.0", npm+"@3.1.0")
	write(tenant, outOfScope, base+"@2.0.0")
	write(other, otherAsset, base+"@2.0.0")

	search := func(tn shared.ID, scope *shared.DataScope, q string) []component.Package {
		t.Helper()
		res, err := repo.ListPackages(ctx, component.Filter{TenantID: tn, Scope: scope, Query: q, Sort: "name"}, pagination.New(1, 20))
		if err != nil {
			t.Fatal(err)
		}
		return res.Data
	}

	if got := search(tenant, nil, base); len(got) != 1 || got[0].Name != name || got[0].VersionsInUse != 2 || got[0].Assets != 2 {
		t.Fatalf("package URL without version: %+v, want the one package with both versions", got)
	}
	if got := search(tenant, nil, base+"@2.0.0"); len(got) != 1 || got[0].VersionsInUse != 1 || got[0].Assets != 1 {
		t.Fatalf("package URL with version: %+v, want the package narrowed to 2.0.0", got)
	}
	if got := search(tenant, nil, base+"@9.9.9"); len(got) != 0 {
		t.Fatalf("version not in use: %+v", got)
	}
	// Canonicalised like the catalog: npm namespace and name fold case.
	if got := search(tenant, nil, "PKG:npm/%40ACME/"+name+"@3.1.0?foo=bar#sub"); len(got) != 1 {
		t.Fatalf("npm package URL in another spelling: %+v", got)
	}
	// Text that is not a package URL still matches names (both look-alikes).
	if got := search(tenant, nil, name); len(got) != 3 {
		t.Fatalf("name search: %d packages, want 3", len(got))
	}

	// Data scope: a member who sees only the first asset finds no 2.0.0.
	user := shared.NewID()
	mustExec(t, db, `INSERT INTO users (id, email, name) VALUES ($1, $2, 'scoped')`, user.String(), user.String()+"@example.com")
	t.Cleanup(func() { _, _ = db.ExecContext(ctx, `DELETE FROM users WHERE id=$1`, user.String()) })
	mustExec(t, db, `INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id) VALUES ($1,$2,$3)`,
		user.String(), tenant.String(), inScope.String())
	t.Cleanup(func() {
		_, _ = db.ExecContext(ctx, `DELETE FROM user_accessible_assets WHERE user_id=$1`, user.String())
	})
	scope := &shared.DataScope{TenantID: tenant, UserID: user}
	if got := search(tenant, scope, base+"@2.0.0"); len(got) != 0 {
		t.Fatalf("out-of-scope version leaked: %+v", got)
	}
	if got := search(tenant, scope, base); len(got) != 1 || got[0].Assets != 1 || got[0].VersionsInUse != 1 {
		t.Fatalf("scoped package: %+v, want only the in-scope asset counted", got)
	}

	// Another tenant: only its own asset, never this tenant's.
	if got := search(other, nil, base); len(got) != 1 || got[0].Assets != 1 {
		t.Fatalf("other tenant: %+v", got)
	}
	if got := search(other, nil, base+"@1.0.0"); len(got) != 0 {
		t.Fatalf("other tenant sees this tenant's version: %+v", got)
	}
}
