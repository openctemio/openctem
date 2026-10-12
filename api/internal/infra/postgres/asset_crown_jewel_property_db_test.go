package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// The crown-jewel flag is the assets.is_crown_jewel column (migration
// 000778). Every reader takes it from there; a properties->'is_crown_jewel'
// left behind by an older writer, whatever its type, is ignored.
func TestCrownJewelReads_UseTheColumn(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	tenantID := seedTestTenant(ctx, t, db)
	tenant := tenantID.String()

	seed := func(name string, column bool, props string) string {
		id := shared.NewID().String()
		mustExec(t, db, `INSERT INTO assets (id, tenant_id, name, asset_type, criticality, is_crown_jewel, properties)
			VALUES ($1, $2, $3, 'domain', 'high', $4, $5::jsonb)`, id, tenant, name, column, props)
		mustExec(t, db, `INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
			VALUES ($1::uuid, $2, $3, 'sast', 'cj-tool', 'cj finding', 'high', $1::text, 'new')`,
			shared.NewID().String(), tenant, id)
		return id
	}
	jewel := seed("cj-col.example.com", true, `{}`)
	// Stale or hostile property values never count and never break a read.
	propOnly := seed("cj-prop.example.com", false, `{"is_crown_jewel": true}`)
	bad := seed("cj-bad.example.com", false, `{"is_crown_jewel": "x", "business_impact_score": "lots"}`)

	repo := NewAssetRepository(&DB{DB: db})
	yes := true
	res, err := repo.List(ctx, asset.Filter{IsCrownJewel: &yes}.WithTenantID(tenant), asset.NewListOptions(), pagination.New(1, 50))
	if err != nil {
		t.Fatalf("crown-jewel filter: %v", err)
	}
	if res.Total != 1 || res.Data[0].ID().String() != jewel || !res.Data[0].IsCrownJewel() {
		t.Errorf("crown-jewel filter = %d rows; want only %s, flagged", res.Total, jewel)
	}
	no := false
	res, err = repo.List(ctx, asset.Filter{IsCrownJewel: &no}.WithTenantID(tenant), asset.NewListOptions(), pagination.New(1, 50))
	if err != nil || res.Total != 2 {
		t.Errorf("not-crown-jewel filter = %d (err %v), want 2", res.Total, err)
	}

	nodes, err := repo.ListAllNodes(ctx, tenantID)
	if err != nil {
		t.Fatalf("ListAllNodes: %v", err)
	}
	for _, n := range nodes {
		if n.IsCrownJewel != (n.ID == jewel) {
			t.Errorf("attack-path node %s crown jewel = %v", n.ID, n.IsCrownJewel)
		}
	}

	s, err := NewDashboardRepository(db).GetExecutiveSummary(ctx, tenantID, 30)
	if err != nil {
		t.Fatalf("executive summary: %v", err)
	}
	if s.CrownJewelsAtRisk != 1 {
		t.Errorf("crown jewels at risk = %d, want 1", s.CrownJewelsAtRisk)
	}

	// The writer sets the column and the business impact in one statement.
	pid, _ := shared.IDFromString(propOnly)
	if err := repo.SetCrownJewel(ctx, tenantID, pid, true, 70, "payments"); err != nil {
		t.Fatalf("SetCrownJewel: %v", err)
	}
	a, err := repo.GetByID(ctx, tenantID, pid)
	if err != nil {
		t.Fatal(err)
	}
	if !a.IsCrownJewel() || a.Properties()["business_impact_score"] != float64(70) || a.Properties()["business_impact_notes"] != "payments" {
		t.Errorf("after SetCrownJewel: crown=%v props=%v", a.IsCrownJewel(), a.Properties())
	}
	// Another tenant's id is not found and changes nothing.
	other := seedTestTenant(ctx, t, db)
	bid, _ := shared.IDFromString(bad)
	if err := repo.SetCrownJewel(ctx, other, bid, true, 1, ""); err == nil {
		t.Error("SetCrownJewel across tenants succeeded")
	}
	// A soft-deleted asset is not found and keeps its flag.
	mustExec(t, db, `UPDATE assets SET deleted_at = NOW() WHERE id = $1`, bad)
	if err := repo.SetCrownJewel(ctx, tenantID, bid, true, 1, ""); err == nil {
		t.Error("SetCrownJewel on a deleted asset succeeded")
	}
	// A generic Update never touches the flag.
	j, _ := shared.IDFromString(jewel)
	ja, err := repo.GetByID(ctx, tenantID, j)
	if err != nil {
		t.Fatal(err)
	}
	ja.UpdateDescription("touched")
	if err := repo.Update(ctx, ja); err != nil {
		t.Fatal(err)
	}
	var still bool
	_ = db.QueryRow(`SELECT is_crown_jewel FROM assets WHERE id = $1`, jewel).Scan(&still)
	if !still {
		t.Error("a generic Update cleared is_crown_jewel")
	}
}
