package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// TestCrownJewelReads_IgnoreBadPropertyValues: one asset whose properties
// hold a non-boolean is_crown_jewel (and an out-of-range, non-numeric
// business_impact_score) must not break the tenant's crown-jewel filter,
// attack-path graph or executive dashboard. A bad value reads as "not a
// crown jewel"; real crown jewels are still found.
func TestCrownJewelReads_IgnoreBadPropertyValues(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	tenantID := seedTestTenant(ctx, t, db)
	tenant := tenantID.String()

	seed := func(name, props string) string {
		id := shared.NewID().String()
		mustExec(t, db, `INSERT INTO assets (id, tenant_id, name, asset_type, criticality, properties)
			VALUES ($1, $2, $3, 'domain', 'high', $4::jsonb)`, id, tenant, name, props)
		mustExec(t, db, `INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
			VALUES ($1::uuid, $2, $3, 'sast', 'cj-tool', 'cj finding', 'high', $1::text, 'new')`,
			shared.NewID().String(), tenant, id)
		return id
	}
	jewel := seed("cj-real.example.com", `{"is_crown_jewel": true, "business_impact_score": 80}`)
	jewelStr := seed("cj-string.example.com", `{"is_crown_jewel": "true"}`)
	bad := seed("cj-bad.example.com", `{"is_crown_jewel": "x", "business_impact_score": "lots"}`)
	badObj := seed("cj-obj.example.com", `{"is_crown_jewel": {"nested": 1}, "business_impact_score": 1e9}`)
	plain := seed("cj-plain.example.com", `{}`)

	repo := NewAssetRepository(&DB{DB: db})
	yes := true
	res, err := repo.List(ctx, asset.Filter{IsCrownJewel: &yes}.WithTenantID(tenant), asset.NewListOptions(), pagination.New(1, 50))
	if err != nil {
		t.Fatalf("crown-jewel filter errored on a bad property value: %v", err)
	}
	got := map[string]bool{}
	for _, a := range res.Data {
		got[a.ID().String()] = true
	}
	if !got[jewel] || !got[jewelStr] || got[bad] || got[badObj] || got[plain] {
		t.Errorf("crown-jewel filter = %v; want only %s and %s", got, jewel, jewelStr)
	}

	nodes, err := repo.ListAllNodes(ctx, tenantID)
	if err != nil {
		t.Fatalf("attack-path ListAllNodes errored on a bad property value: %v", err)
	}
	cj := map[string]bool{}
	for _, n := range nodes {
		if n.IsCrownJewel {
			cj[n.ID] = true
		}
	}
	if len(cj) != 2 || !cj[jewel] || !cj[jewelStr] {
		t.Errorf("attack-path crown jewels = %v; want %s and %s", cj, jewel, jewelStr)
	}

	s, err := NewDashboardRepository(db).GetExecutiveSummary(ctx, tenantID, 30)
	if err != nil {
		t.Fatalf("executive summary errored on a bad property value: %v", err)
	}
	if s.CrownJewelsAtRisk != 2 {
		t.Errorf("crown jewels at risk = %d, want 2", s.CrownJewelsAtRisk)
	}
}
