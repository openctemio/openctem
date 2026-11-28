package postgres

// A business unit's counts are computed when they are read, for every reader:
// the stored counters change only when an asset joins or leaves the unit, so
// a finding opened after that never showed (every unit read "0 findings,
// no open risk"). They count the dashboard's population, and never another
// tenant's rows.

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

func TestBusinessUnitStats_LiveForEveryReader(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewBusinessUnitRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)

	unit := func(tid shared.ID) shared.ID {
		t.Helper()
		id := shared.NewID()
		if _, err := db.ExecContext(ctx, `INSERT INTO business_units (id, tenant_id, name) VALUES ($1, $2, $3)`,
			id.String(), tid.String(), "unit-"+id.String()); err != nil {
			t.Fatalf("seed unit: %v", err)
		}
		return id
	}
	member := func(tid, bu, asset shared.ID) {
		t.Helper()
		if _, err := db.ExecContext(ctx, `INSERT INTO business_unit_assets (id, tenant_id, business_unit_id, asset_id) VALUES ($1, $2, $3, $4)`,
			shared.NewID().String(), tid.String(), bu.String(), asset.String()); err != nil {
			t.Fatalf("seed member: %v", err)
		}
	}

	bu := unit(tenant)
	a1 := seedOwnedAsset(ctx, t, db, tenant, nil)
	a2 := seedOwnedAsset(ctx, t, db, tenant, nil)
	member(tenant, bu, a1)
	member(tenant, bu, a2)
	// The stored counters are filled now (as AddAsset does) and go stale below.
	if err := repo.RecalculateCounts(ctx, tenant, bu); err != nil {
		t.Fatal(err)
	}
	seedGroupFinding(ctx, t, db, tenant, a1, "CVE-2099-5001", "critical", nil)
	seedGroupFinding(ctx, t, db, tenant, a2, "CVE-2099-5002", "high", nil)
	fixed := seedGroupFinding(ctx, t, db, tenant, a2, "CVE-2099-5003", "critical", nil)
	compliance := seedGroupFinding(ctx, t, db, tenant, a1, "CVE-2099-5004", "critical", nil)
	if _, err := db.ExecContext(ctx, `UPDATE findings SET status = 'resolved' WHERE id = $1`, fixed.String()); err != nil {
		t.Fatal(err)
	}
	// A compliance check is not a vulnerability figure (as on the dashboard).
	if _, err := db.ExecContext(ctx, `UPDATE findings SET practice = 'compliance' WHERE id = $1`, compliance.String()); err != nil {
		t.Fatal(err)
	}

	// The other tenant: a unit with the same shape. Its rows never count,
	// and its unit id asked under this tenant returns nothing.
	obu := unit(other)
	oa := seedOwnedAsset(ctx, t, db, other, nil)
	member(other, obu, oa)
	seedGroupFinding(ctx, t, db, other, oa, "CVE-2099-5005", "critical", nil)

	stats, err := repo.ScopedStats(ctx, tenant, []shared.ID{bu, obu}, nil)
	if err != nil {
		t.Fatalf("stats (no scope): %v", err)
	}
	got := stats[bu]
	if got.AssetCount != 2 || got.FindingCount != 2 || got.CriticalFindingCount != 1 {
		t.Errorf("unit stats = %+v, want 2 assets, 2 open findings, 1 critical", got)
	}
	if o := stats[obu]; o.AssetCount != 0 || o.FindingCount != 0 {
		t.Errorf("another tenant's unit counted under this tenant: %+v", o)
	}

	// The stored counters still say 0 findings: that is what readers saw.
	var stored int
	if err := db.QueryRowContext(ctx, `SELECT finding_count FROM business_units WHERE id = $1`, bu.String()).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != 0 {
		t.Fatalf("stored finding_count = %d, the test expects it stale at 0", stored)
	}
}
