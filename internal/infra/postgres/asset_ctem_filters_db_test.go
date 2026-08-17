package postgres

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// TestAsset_CTEMInventoryFilters exercises the CTEM inventory filter dimensions
// and the extended facet counts end-to-end against Postgres. Skipped unless
// DATABASE_URL is set (CI runs it against a migrated database).
//
// Fixture (one tenant):
//
//	assetA: secret / internet-facing / production / aws / recent, owned, and the
//	        target of a control-plane edge, and a member of business unit BU1.
//	assetB: internal / not internet-facing / staging / github / stale (60d), unowned.
//	assetC: bare defaults (not internet-facing, no classification), unowned.
func TestAsset_CTEMInventoryFilters(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB execution check")
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()

	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}

	repo := NewAssetRepository(&DB{DB: db})
	tenantID := seedTestTenant(ctx, t, db)
	tenant := tenantID.String()

	now := time.Now().UTC()
	assetA := insertCTEMAsset(t, db, tenant, "ctem-a", "secret", true, "production", "aws", now)
	assetB := insertCTEMAsset(t, db, tenant, "ctem-b", "internal", false, "staging", "github", now.Add(-60*24*time.Hour))
	assetC := insertCTEMAsset(t, db, tenant, "ctem-c", "", false, "", "", now)

	// Business unit BU1 with assetA as a member.
	bu1 := shared.NewID().String()
	mustExec(t, db, `INSERT INTO business_units (id, tenant_id, name) VALUES ($1,$2,$3)`, bu1, tenant, "BU One")
	mustExec(t, db, `INSERT INTO business_unit_assets (id, tenant_id, business_unit_id, asset_id) VALUES ($1,$2,$3,$4)`,
		shared.NewID().String(), tenant, bu1, assetA)

	// A tenant group owning assetA -> has_owner true for assetA only.
	grp := shared.NewID().String()
	mustExec(t, db, `INSERT INTO groups (id, tenant_id, name, slug) VALUES ($1,$2,$3,$4)`, grp, tenant, "Owners", "owners")
	mustExec(t, db, `INSERT INTO asset_owners (id, asset_id, group_id, ownership_type) VALUES ($1,$2,$3,'primary')`,
		shared.NewID().String(), assetA, grp)

	// Control-plane edge: assetB depends_on assetA, marking assetA a control plane.
	mustExec(t, db,
		`INSERT INTO asset_relationships (id, tenant_id, source_asset_id, target_asset_id, relationship_type, is_control_plane)
		 VALUES ($1,$2,$3,$4,'depends_on',true)`,
		shared.NewID().String(), tenant, assetB, assetA)

	list := func(f asset.Filter) map[string]bool {
		t.Helper()
		res, err := repo.List(ctx, f.WithTenantID(tenant), asset.NewListOptions(), pagination.New(1, 50))
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		got := make(map[string]bool)
		for _, a := range res.Data {
			got[a.ID().String()] = true
		}
		return got
	}

	assertOnly := func(name string, got map[string]bool, want ...string) {
		t.Helper()
		wantSet := make(map[string]bool)
		for _, id := range want {
			wantSet[id] = true
			if !got[id] {
				t.Errorf("%s: expected asset %s in results, missing", name, id)
			}
		}
		for id := range got {
			if !wantSet[id] {
				t.Errorf("%s: unexpected asset %s in results", name, id)
			}
		}
	}

	assertOnly("internet_accessible", list(asset.NewFilter().WithIsInternetAccessible(true)), assetA)
	assertOnly("data_classification=secret", list(asset.NewFilter().WithDataClassifications("secret")), assetA)
	assertOnly("environment=production", list(asset.NewFilter().WithEnvironments("production")), assetA)
	assertOnly("provider=aws", list(asset.NewFilter().WithProviders(asset.Provider("aws"))), assetA)
	assertOnly("business_unit", list(asset.NewFilter().WithBusinessUnitIDs(bu1)), assetA)
	assertOnly("has_owner=true", list(asset.NewFilter().WithHasOwner(true)), assetA)
	assertOnly("has_owner=false", list(asset.NewFilter().WithHasOwner(false)), assetB, assetC)
	assertOnly("is_control_plane=true", list(asset.NewFilter().WithIsControlPlane(true)), assetA)
	// Stale assetB is excluded when filtering to assets seen within the last day.
	assertOnly("last_seen_after", list(asset.NewFilter().WithLastSeenAfter(now.Add(-24*time.Hour))), assetA, assetC)

	// Facet counts.
	stats, err := repo.GetAggregateStats(ctx, tenantID, nil, nil, "")
	if err != nil {
		t.Fatalf("aggregate stats: %v", err)
	}
	checkCount(t, "by_internet_accessible[true]", stats.ByInternetAccessible["true"], 1)
	checkCount(t, "by_internet_accessible[false]", stats.ByInternetAccessible["false"], 2)
	checkCount(t, "by_data_classification[secret]", stats.ByDataClassification["secret"], 1)
	checkCount(t, "by_data_classification[unset]", stats.ByDataClassification["unset"], 1)
	checkCount(t, "by_environment[production]", stats.ByEnvironment["production"], 1)
	checkCount(t, "by_provider[aws]", stats.ByProvider["aws"], 1)
	checkCount(t, "by_has_owner[true]", stats.ByHasOwner["true"], 1)
	checkCount(t, "by_has_owner[false]", stats.ByHasOwner["false"], 2)
	checkCount(t, "by_control_plane[true]", stats.ByControlPlane["true"], 1)
	checkCount(t, "by_control_plane[false]", stats.ByControlPlane["false"], 2)
	checkCount(t, "by_business_unit[bu1]", stats.ByBusinessUnit[bu1], 1)
}

func insertCTEMAsset(t *testing.T, db *sql.DB, tenant, name, classification string, internet bool, environment, provider string, lastSeen time.Time) string {
	t.Helper()
	id := shared.NewID().String()
	mustExec(t, db,
		`INSERT INTO assets (id, tenant_id, name, asset_type, data_classification, is_internet_accessible, environment, provider, last_seen)
		 VALUES ($1,$2,$3,'host',$4,$5,$6,$7,$8)`,
		id, tenant, name+"-"+id,
		nullIfEmpty(classification), internet, nullIfEmpty(environment), nullIfEmpty(provider), lastSeen)
	return id
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func checkCount(t *testing.T, label string, got, want int) {
	t.Helper()
	if got != want {
		t.Errorf("%s = %d, want %d", label, got, want)
	}
}
