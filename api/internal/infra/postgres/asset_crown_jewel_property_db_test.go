package postgres

import (
	"context"
	"os"
	"testing"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// The crown-jewel flag is the assets.is_crown_jewel column (migration
// 000776). Every reader takes it from there; a properties->'is_crown_jewel'
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

// Migration 000776 backfills the column from properties and removes the
// key. Run inside a rolled-back transaction, starting from the pre-000776
// shape that its down migration restores.
func TestCrownJewelMigration_Backfill(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	up, err := os.ReadFile("../../../migrations/000776_assets_crown_jewel_column.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("../../../migrations/000776_assets_crown_jewel_column.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	tenantID := seedTestTenant(ctx, t, db)
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := tx.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%.80s: %v", q, err)
		}
	}
	testdb.LockForDDL(t, ctx, tx, "tenants", "assets")
	exec(string(down))

	cases := map[string]struct {
		column *bool
		props  string
		want   bool
	}{
		"json-true":   {nil, `{"is_crown_jewel": true, "registrar": "x"}`, true},
		"string-true": {nil, `{"is_crown_jewel": "true"}`, true},
		"string-TRUE": {nil, `{"is_crown_jewel": "TRUE"}`, true},
		"json-false":  {nil, `{"is_crown_jewel": false}`, false},
		"string-x":    {nil, `{"is_crown_jewel": "x"}`, false},
		"number":      {nil, `{"is_crown_jewel": 1}`, false},
		"object":      {nil, `{"is_crown_jewel": {"a": 1}}`, false},
		"missing":     {nil, `{}`, false},
		"column-true": {boolPtr(true), `{}`, true},
	}
	ids := map[string]string{}
	for name, c := range cases {
		id := shared.NewID().String()
		ids[name] = id
		var props any
		if c.props != "" {
			props = c.props
		}
		exec(`INSERT INTO assets (id, tenant_id, name, asset_type, criticality, is_crown_jewel, properties)
			VALUES ($1, $2, $3, 'domain', 'high', $4, $5::jsonb)`, id, tenantID.String(), "mig-"+name+".example.com", c.column, props)
	}

	exec(string(up))

	for name, c := range cases {
		var got, hasKey bool
		var registrar *string
		if err := tx.QueryRowContext(ctx, `SELECT is_crown_jewel, COALESCE(properties ? 'is_crown_jewel', FALSE), properties->>'registrar'
			FROM assets WHERE id = $1`, ids[name]).Scan(&got, &hasKey, &registrar); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got != c.want {
			t.Errorf("%s: is_crown_jewel = %v, want %v", name, got, c.want)
		}
		if hasKey {
			t.Errorf("%s: properties still hold is_crown_jewel", name)
		}
		if name == "json-true" && (registrar == nil || *registrar != "x") {
			t.Errorf("json-true: other properties were lost")
		}
	}
	var nullable string
	if err := tx.QueryRowContext(ctx, `SELECT is_nullable FROM information_schema.columns
		WHERE table_name = 'assets' AND column_name = 'is_crown_jewel'`).Scan(&nullable); err != nil {
		t.Fatal(err)
	}
	if nullable != "NO" {
		t.Errorf("is_crown_jewel is_nullable = %s, want NO", nullable)
	}
	// Down restores the property for the previous release.
	exec(string(down))
	var restored bool
	_ = tx.QueryRowContext(ctx, `SELECT properties->>'is_crown_jewel' = 'true' FROM assets WHERE id = $1`, ids["string-true"]).Scan(&restored)
	if !restored {
		t.Error("down migration did not restore the property")
	}
}

func boolPtr(b bool) *bool { return &b }
