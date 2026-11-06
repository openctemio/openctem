package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The inventory overview counts per (lens, type, sub-type) only what the
// caller may list: its own tenant, its data scope, and in the total only the
// assets the default inventory shows (names in review counted apart,
// rejected names nowhere).
func TestGetInventoryOverview_ScopedAndHonest(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewAssetRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)
	owner := seedGroupsUser(ctx, t, db, "overview.test")
	addTenantMember(ctx, t, db, tenant, owner)
	scoped := seedGroupsUser(ctx, t, db, "overview-scoped.test")
	addTenantMember(ctx, t, db, tenant, scoped)

	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	newAsset := func(tn shared.ID, typ string, risk int) shared.ID {
		t.Helper()
		id := shared.NewID()
		exec(`INSERT INTO assets (id, tenant_id, name, asset_type, risk_score) VALUES ($1, $2, $3, $4, $5)`,
			id.String(), tn.String(), "ov-"+id.String(), typ, risk)
		return id
	}
	ownedHost := newAsset(tenant, "host", 10)
	exec(`INSERT INTO asset_owners (asset_id, user_id, ownership_type) VALUES ($1, $2, 'primary')`,
		ownedHost.String(), owner.String())
	riskyHost := newAsset(tenant, "host", 90)
	oldHost := newAsset(tenant, "host", 10)
	exec(`UPDATE assets SET first_seen = now() - interval '30 days' WHERE id = $1`, oldHost.String())
	review := newAsset(tenant, "domain", 0)
	exec(`INSERT INTO asset_attributions (asset_id, tenant_id, state, confidence) VALUES ($1, $2, 'needs_review', 50)`,
		review.String(), tenant.String())
	rejected := newAsset(tenant, "domain", 0)
	exec(`INSERT INTO asset_attributions (asset_id, tenant_id, state, confidence) VALUES ($1, $2, 'rejected', 0)`,
		rejected.String(), tenant.String())
	confirmed := newAsset(tenant, "domain", 0)
	exec(`INSERT INTO asset_attributions (asset_id, tenant_id, state, confidence) VALUES ($1, $2, 'confirmed', 100)`,
		confirmed.String(), tenant.String())
	newAsset(other, "host", 99) // another tenant's: never counted

	byType := func(rows []asset.InventoryOverviewRow) map[string]asset.InventoryOverviewRow {
		out := map[string]asset.InventoryOverviewRow{}
		for _, r := range rows {
			out[r.Type] = r
		}
		return out
	}

	rows, err := repo.GetInventoryOverview(ctx, tenant, asset.AccessScope{})
	if err != nil {
		t.Fatal(err)
	}
	got := byType(rows)
	host := got["host"]
	if host.Total != 3 || host.Unowned != 2 || host.HighRisk != 1 || host.New7d != 2 || host.NeedsReview != 0 {
		t.Errorf("host = %+v, want total 3, unowned 2, high risk 1, new 2, review 0", host)
	}
	if host.Lens != "cloud_infra" {
		t.Errorf("host lens = %q, want cloud_infra", host.Lens)
	}
	domain := got["domain"]
	if domain.Total != 1 || domain.NeedsReview != 1 {
		t.Errorf("domain = %+v, want total 1 (confirmed) and 1 in review; rejected nowhere", domain)
	}
	if len(got) != 2 {
		t.Errorf("rows = %+v, want only this tenant's host and domain", rows)
	}

	// A scoped member counts only the assets of its data scope.
	exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`,
		scoped.String(), tenant.String(), riskyHost.String())
	rows, err = repo.GetInventoryOverview(ctx, tenant, asset.AccessScope{DataScopeUserID: &scoped})
	if err != nil {
		t.Fatal(err)
	}
	got = byType(rows)
	if len(got) != 1 || got["host"].Total != 1 || got["host"].HighRisk != 1 {
		t.Errorf("scoped rows = %+v, want only the one host in scope", rows)
	}

	// A member with no scope row sees nothing.
	none := seedGroupsUser(ctx, t, db, "overview-none.test")
	addTenantMember(ctx, t, db, tenant, none)
	rows, err = repo.GetInventoryOverview(ctx, tenant, asset.AccessScope{DataScopeUserID: &none})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Errorf("unscoped member rows = %+v, want none", rows)
	}
}
