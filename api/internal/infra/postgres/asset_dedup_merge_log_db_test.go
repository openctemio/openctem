package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The asset drawer asks for the merge history of one asset. The log must be
// narrowed to that asset, stay inside the caller's tenant, and report a total
// that matches the narrowed set.
func TestGetMergeLog_AssetFilter(t *testing.T) {
	db, pdb := openBatchDedupDB(t)
	ctx := context.Background()
	tenantA := seedBatchTenant(t, db)
	tenantB := seedBatchTenant(t, db)
	repo := NewAssetDedupRepository(pdb)

	assetA, assetB, assetOther := shared.NewID(), shared.NewID(), shared.NewID()
	ins := func(tenant, kept, merged shared.ID, action string) {
		t.Helper()
		if _, err := db.Exec(`INSERT INTO asset_merge_log
			(tenant_id, kept_asset_id, kept_asset_name, merged_asset_id, merged_asset_name, correlation_type, action)
			VALUES ($1,$2,'kept',$3,'merged','name',$4)`,
			tenant.String(), kept.String(), merged.String(), action); err != nil {
			t.Fatalf("seed merge log: %v", err)
		}
	}
	ins(tenantA, assetA, shared.NewID(), "merge")
	ins(tenantA, assetA, shared.NewID(), "merge")
	ins(tenantA, assetB, shared.NewID(), "merge")
	// An asset absorbed into another also sees the event.
	ins(tenantA, assetB, assetOther, "merge")
	// The same asset id logged under another tenant must never leak.
	ins(tenantB, assetA, shared.NewID(), "merge")

	rows, total, err := repo.GetMergeLog(ctx, tenantA.String(), assetA.String(), 10, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || total != 2 {
		t.Fatalf("asset A: got %d rows, total %d; want 2, 2", len(rows), total)
	}
	rows, total, err = repo.GetMergeLog(ctx, tenantA.String(), assetB.String(), 10, nil)
	if err != nil || len(rows) != 2 || total != 2 {
		t.Fatalf("asset B: got %d rows, total %d, err %v; want 2, 2", len(rows), total, err)
	}
	rows, total, err = repo.GetMergeLog(ctx, tenantA.String(), assetOther.String(), 10, nil)
	if err != nil || len(rows) != 1 || total != 1 {
		t.Fatalf("absorbed asset: got %d rows, total %d, err %v; want 1, 1", len(rows), total, err)
	}
	// Total counts past the limit.
	rows, total, err = repo.GetMergeLog(ctx, tenantA.String(), assetA.String(), 1, nil)
	if err != nil || len(rows) != 1 || total != 2 {
		t.Fatalf("limit 1: got %d rows, total %d, err %v; want 1, 2", len(rows), total, err)
	}
	// Tenant B has one event for asset A; tenant A's other assets never show.
	rows, total, err = repo.GetMergeLog(ctx, tenantB.String(), assetB.String(), 10, nil)
	if err != nil || len(rows) != 0 || total != 0 {
		t.Fatalf("cross-tenant: got %d rows, total %d, err %v; want 0, 0", len(rows), total, err)
	}
	// No asset filter keeps the tenant-wide log.
	_, total, err = repo.GetMergeLog(ctx, tenantA.String(), "", 10, nil)
	if err != nil || total != 4 {
		t.Fatalf("unfiltered: total %d, err %v; want 4", total, err)
	}
}
