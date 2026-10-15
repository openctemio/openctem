package postgres

import (
	"context"
	"database/sql"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func seedPackageVersion(ctx context.Context, t *testing.T, db *sql.DB, name, version string) shared.ID {
	t.Helper()
	product, ver := shared.NewID(), shared.NewID()
	if _, err := db.ExecContext(ctx, `INSERT INTO software_products (id, part, name, source) VALUES ($1, 'a', $2, 'osv')`,
		product.String(), name+"-"+product.String()[:8]); err != nil {
		t.Fatalf("seed product: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO software_versions (id, product_id, raw) VALUES ($1, $2, $3)`,
		ver.String(), product.String(), version); err != nil {
		t.Fatalf("seed version: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM software_products WHERE id = $1`, product.String())
	})
	return ver
}

func seedPackageFinding(ctx context.Context, t *testing.T, db *sql.DB, tenant, asset, component shared.ID, severity, status, fixed string) shared.ID {
	t.Helper()
	id := shared.NewID()
	if _, err := db.ExecContext(ctx, `INSERT INTO findings (id, tenant_id, asset_id, component_id, source, tool_name, message, title, severity, fingerprint, status, metadata)
		VALUES ($1, $2, $3, $4, 'sca', 'trivy', 'm', $8, $5, $9, $6, jsonb_build_object('fixed_versions', $7::jsonb))`,
		id.String(), tenant.String(), asset.String(), component.String(), severity, status, fixed, "t-"+id.String(), "fp-"+id.String()); err != nil {
		t.Fatalf("seed finding: %v", err)
	}
	return id
}

// The package fix plan reads only the open findings of the same package
// version on the same asset of the same tenant.
func TestListPackageFixSiblings_ScopedToTenantAssetComponentAndOpen(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewFindingRepository(&DB{DB: db})

	tenant, other := seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db)
	asset, asset2 := seedTestAsset(ctx, t, db, tenant), seedTestAsset(ctx, t, db, tenant)
	otherAsset := seedTestAsset(ctx, t, db, other)
	django, flask := seedPackageVersion(ctx, t, db, "django", "4.2.20"), seedPackageVersion(ctx, t, db, "flask", "0.12.2")

	high := seedPackageFinding(ctx, t, db, tenant, asset, django, "high", "new", `["4.2.30","5.0.1"]`)
	crit := seedPackageFinding(ctx, t, db, tenant, asset, django, "critical", "in_progress", `["5.2.8","4.2.26"]`)
	seedPackageFinding(ctx, t, db, tenant, asset, django, "critical", "resolved", `["4.2.40"]`)       // closed
	seedPackageFinding(ctx, t, db, tenant, asset, django, "critical", "false_positive", `["4.2.41"]`) // closed
	seedPackageFinding(ctx, t, db, tenant, asset2, django, "critical", "new", `["4.2.42"]`)           // other asset
	seedPackageFinding(ctx, t, db, tenant, asset, flask, "critical", "new", `["1.0"]`)                // other package
	seedPackageFinding(ctx, t, db, other, otherAsset, django, "critical", "new", `["4.2.43"]`)        // other tenant

	got, err := repo.ListPackageFixSiblings(ctx, tenant, asset, django, 50)
	if err != nil {
		t.Fatalf("ListPackageFixSiblings: %v", err)
	}
	if len(got) != 2 || got[0].ID != crit.String() || got[1].ID != high.String() {
		t.Fatalf("want [critical, high] open siblings only, got %+v", got)
	}
	if want := []string{"5.2.8", "4.2.26"}; len(got[0].Fixed) != 2 || got[0].Fixed[0] != want[0] || got[0].Fixed[1] != want[1] {
		t.Fatalf("fixed versions read from metadata, got %v", got[0].Fixed)
	}

	// Cross-tenant: the other tenant's id with this tenant's asset reads nothing.
	if got, err := repo.ListPackageFixSiblings(ctx, other, asset, django, 50); err != nil || len(got) != 0 {
		t.Fatalf("cross-tenant read must be empty, got %v (%v)", got, err)
	}
}
