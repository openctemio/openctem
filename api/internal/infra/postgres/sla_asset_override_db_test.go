package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// HasAssetOverride decides whether the bootstrap's tenant windows stand for
// every asset: only an active asset policy of the same tenant counts.
func TestSLAPolicy_HasAssetOverride_DB(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewSLAPolicyRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)

	has := func(id shared.ID) bool {
		t.Helper()
		v, err := repo.HasAssetOverride(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	if has(tenant) {
		t.Fatal("a tenant without policies reports an override")
	}

	var assetID string
	if err := db.QueryRowContext(ctx, `INSERT INTO assets (tenant_id, name, asset_type) VALUES ($1,'sla-ov','domain') RETURNING id`, tenant.String()).Scan(&assetID); err != nil {
		t.Fatal(err)
	}
	polID := shared.NewID().String()
	if _, err := db.ExecContext(ctx, `INSERT INTO sla_policies (id, tenant_id, asset_id, name, is_default, critical_days, high_days, medium_days, low_days, info_days)
		VALUES ($1,$2,$3,'ov',FALSE,1,7,30,90,0)`, polID, tenant.String(), assetID); err != nil {
		t.Fatal(err)
	}
	if !has(tenant) {
		t.Fatal("an active asset policy is not reported")
	}
	if has(other) {
		t.Fatal("another tenant's override leaked into this tenant's answer")
	}
	if _, err := db.ExecContext(ctx, `UPDATE sla_policies SET is_active = FALSE WHERE id = $1`, polID); err != nil {
		t.Fatal(err)
	}
	if has(tenant) {
		t.Fatal("an inactive asset policy still counts as an override")
	}
}
