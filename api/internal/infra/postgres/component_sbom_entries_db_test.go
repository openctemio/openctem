package postgres

import (
	"context"
	"database/sql"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// TestComponentRepository_ListSBOMEntries pins what an SBOM export reads:
// only the tenant's own component links and license observations (the
// components table is shared by every tenant), one asset when asked, and
// only in-scope assets for a restricted user.
//
// DB-gated: needs DATABASE_URL pointing at app_test (never the live DB).
func TestComponentRepository_ListSBOMEntries(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed test")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()
	if err := db.Ping(); err != nil {
		t.Skipf("cannot reach test DB: %v", err)
	}
	ctx := context.Background()

	newTenant := func(name string) shared.ID {
		id := shared.NewID()
		mustExec(t, db, `INSERT INTO tenants (id, name, slug) VALUES ($1,$2,$3)`, id.String(), name, name+"-"+id.String()[28:])
		t.Cleanup(func() { _, _ = db.ExecContext(ctx, `DELETE FROM tenants WHERE id=$1`, id.String()) })
		return id
	}
	newAsset := func(tenant shared.ID, name string) shared.ID {
		id := shared.NewID()
		mustExec(t, db, `INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1,$2,$3,'repository')`, id.String(), tenant.String(), name)
		return id
	}
	newComponent := func(name, version string) shared.ID {
		id := shared.NewID()
		mustExec(t, db, `INSERT INTO components (id, purl, name, version, ecosystem, vulnerability_count) VALUES ($1,$2,$3,$4,'npm',1)`,
			id.String(), "pkg:npm/"+name+"@"+version+"-"+id.String()[28:], name, version)
		t.Cleanup(func() { _, _ = db.ExecContext(ctx, `DELETE FROM components WHERE id=$1`, id.String()) })
		return id
	}
	link := func(tenant, assetID, comp shared.ID, license string) {
		mustExec(t, db, `INSERT INTO asset_components (tenant_id, asset_id, component_id, name, ecosystem, license) VALUES ($1,$2,$3,'x','npm',NULLIF($4,''))`,
			tenant.String(), assetID.String(), comp.String(), license)
	}

	tenant := newTenant("sbom-a")
	other := newTenant("sbom-b")
	repoA := newAsset(tenant, "repo-a.example.com")
	repoB := newAsset(tenant, "repo-b.example.com")
	otherAsset := newAsset(other, "other.example.com")

	shared1 := newComponent("aaa-shared", "1.0.0") // used by both tenants
	onlyB := newComponent("bbb-only-b", "2.0.0")
	foreign := newComponent("ccc-foreign", "3.0.0")

	link(tenant, repoA, shared1, "MIT")
	link(tenant, repoB, shared1, "Apache-2.0")
	link(tenant, repoB, onlyB, "")
	// The other tenant reports a different license for the shared component
	// and uses a component this tenant does not.
	link(other, otherAsset, shared1, "GPL-3.0-only")
	link(other, otherAsset, foreign, "MIT")

	r := NewComponentRepository(&DB{DB: db})

	t.Run("whole inventory of the tenant only", func(t *testing.T) {
		got, err := r.ListSBOMEntries(ctx, tenant, nil, nil, 100)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 || got[0].ID != shared1 || got[1].ID != onlyB {
			t.Fatalf("entries %+v", got)
		}
		lic := map[string]bool{}
		for _, l := range got[0].Licenses {
			lic[l] = true
		}
		if !lic["MIT"] || !lic["Apache-2.0"] || lic["GPL-3.0-only"] || len(got[0].Licenses) != 2 {
			t.Fatalf("licenses must be this tenant's observations only: %v", got[0].Licenses)
		}
		if got[1].Licenses != nil {
			t.Fatalf("no license observed must give none: %v", got[1].Licenses)
		}
	})

	t.Run("one asset", func(t *testing.T) {
		got, err := r.ListSBOMEntries(ctx, tenant, &repoA, nil, 100)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].ID != shared1 || len(got[0].Licenses) != 1 || got[0].Licenses[0] != "MIT" {
			t.Fatalf("asset entries %+v", got)
		}
	})

	t.Run("another tenant's asset id gives nothing", func(t *testing.T) {
		got, err := r.ListSBOMEntries(ctx, tenant, &otherAsset, nil, 100)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 0 {
			t.Fatalf("cross-tenant asset leaked %+v", got)
		}
	})

	t.Run("data scope keeps only in-scope assets", func(t *testing.T) {
		user := shared.NewID()
		mustExec(t, db, `INSERT INTO users (id, email, name) VALUES ($1, $2, 'scoped')`, user.String(), user.String()+"@example.com")
		t.Cleanup(func() { _, _ = db.ExecContext(ctx, `DELETE FROM users WHERE id=$1`, user.String()) })
		mustExec(t, db, `INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id) VALUES ($1,$2,$3)`, user.String(), tenant.String(), repoA.String())
		t.Cleanup(func() {
			_, _ = db.ExecContext(ctx, `DELETE FROM user_accessible_assets WHERE user_id=$1`, user.String())
		})

		got, err := r.ListSBOMEntries(ctx, tenant, nil, &shared.DataScope{TenantID: tenant, UserID: user}, 100)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].ID != shared1 || len(got[0].Licenses) != 1 || got[0].Licenses[0] != "MIT" {
			t.Fatalf("scoped entries must come from repo-a only: %+v", got)
		}
	})

	t.Run("limit", func(t *testing.T) {
		got, err := r.ListSBOMEntries(ctx, tenant, nil, nil, 1)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 {
			t.Fatalf("limit not applied: %d", len(got))
		}
	})
}
