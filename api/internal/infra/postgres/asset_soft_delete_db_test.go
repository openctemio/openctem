package postgres

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// Safe asset delete (owner decision O3): a delete never destroys findings,
// and a soft-deleted asset is invisible everywhere and frees its name.

func countRows(ctx context.Context, t *testing.T, db *sql.DB, q string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRowContext(ctx, q, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return n
}

func TestAssetDelete_RefusedWhileFindingsExist(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewAssetRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	a := seedOwnedAsset(ctx, t, db, tenant, nil)
	f := seedGroupFinding(ctx, t, db, tenant, a, "CVE-2099-3001", "low", nil)
	// A resolved finding is history too.
	if _, err := db.ExecContext(ctx, `UPDATE findings SET status = 'resolved' WHERE id = $1`, f.String()); err != nil {
		t.Fatal(err)
	}

	err := repo.Delete(ctx, tenant, a, nil)
	var hf *asset.HasFindingsError
	if !errors.As(err, &hf) || hf.FindingCount != 1 || !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("Delete = %v, want HasFindingsError{1} (a conflict)", err)
	}
	if n := countRows(ctx, t, db, `SELECT COUNT(*) FROM assets WHERE id = $1 AND deleted_at IS NULL`, a.String()); n != 1 {
		t.Fatal("refused delete changed the asset")
	}
	if n := countRows(ctx, t, db, `SELECT COUNT(*) FROM findings WHERE id = $1`, f.String()); n != 1 {
		t.Fatal("finding gone")
	}

	// No path can cascade findings away any more: a hard delete fails.
	if _, err := db.ExecContext(ctx, `DELETE FROM assets WHERE id = $1`, a.String()); err == nil {
		t.Fatal("hard delete of an asset with findings succeeded (findings FK must be NO ACTION)")
	}
}

func TestAssetDelete_SoftDeleteHidesDetachesAndFreesName(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewAssetRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)
	user := seedGroupsUser(ctx, t, db, "soft-delete.test")
	addTenantMember(ctx, t, db, tenant, user)

	victim := seedOwnedAsset(ctx, t, db, tenant, &user)
	keep := seedOwnedAsset(ctx, t, db, tenant, nil)
	child := seedOwnedAsset(ctx, t, db, tenant, nil)
	var name string
	if err := db.QueryRowContext(ctx, `SELECT name FROM assets WHERE id = $1`, victim.String()).Scan(&name); err != nil {
		t.Fatal(err)
	}
	group := shared.NewID()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	exec(`UPDATE assets SET parent_id = $1 WHERE id = $2`, victim.String(), child.String())
	exec(`INSERT INTO asset_groups (id, tenant_id, name) VALUES ($1, $2, 'sd-group')`, group.String(), tenant.String())
	exec(`INSERT INTO asset_group_members (asset_group_id, asset_id) VALUES ($1, $2), ($1, $3)`, group.String(), victim.String(), keep.String())
	exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`, user.String(), tenant.String(), victim.String())
	exec(`INSERT INTO asset_access_grants (tenant_id, asset_id, user_id) VALUES ($1, $2, $3)`, tenant.String(), victim.String(), user.String())
	exec(`INSERT INTO asset_relationships (tenant_id, source_asset_id, target_asset_id, relationship_type) VALUES ($1, $2, $3, 'runs_on')`, tenant.String(), keep.String(), victim.String())
	exec(`INSERT INTO asset_identifiers (tenant_id, asset_id, kind, value, strong) VALUES ($1, $2, 'ip', '10.99.0.1', false)`, tenant.String(), victim.String())
	exec(`INSERT INTO asset_state_history (tenant_id, asset_id, change_type, source) VALUES ($1, $2, 'appeared', 'manual')`, tenant.String(), victim.String())

	// Another tenant cannot delete it.
	if err := repo.Delete(ctx, other, victim, nil); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant delete = %v, want not found", err)
	}

	if err := repo.Delete(ctx, tenant, victim, &user); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := repo.Delete(ctx, tenant, victim, &user); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("second delete = %v, want not found", err)
	}

	// Invisible to every repository read.
	if _, err := repo.GetByID(ctx, tenant, victim); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("GetByID of a deleted asset = %v, want not found", err)
	}
	if _, err := repo.GetByName(ctx, tenant, name); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("GetByName of a deleted asset's name = %v, want not found", err)
	}
	if got, _ := repo.GetByIDs(ctx, tenant, []shared.ID{victim, keep}); len(got) != 1 {
		t.Errorf("GetByIDs returned %d, want only the live asset", len(got))
	}
	if exists, _ := repo.ExistsByName(ctx, tenant, name); exists {
		t.Error("ExistsByName true for a deleted asset")
	}
	tid := tenant.String()
	filter := asset.Filter{TenantID: &tid}
	list, err := repo.List(ctx, filter, asset.ListOptions{}, pagination.New(1, 100))
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range list.Data {
		if a.ID() == victim {
			t.Error("List returned the deleted asset")
		}
	}
	if list.Total != 2 {
		t.Errorf("List total = %d, want 2 live assets", list.Total)
	}
	if n, _ := repo.Count(ctx, filter); n != 2 {
		t.Errorf("Count = %d, want 2", n)
	}
	stats, err := repo.GetAggregateStats(ctx, tenant, asset.AccessScope{}, nil, nil, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if stats.Total != 2 {
		t.Errorf("aggregate stats total = %d, want 2", stats.Total)
	}
	breakdown, err := repo.GetAssetTypeBreakdown(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	if breakdown["host"].Total != 2 {
		t.Errorf("type breakdown host = %d, want 2", breakdown["host"].Total)
	}

	// Detached from everything that would surface it or route work to it.
	for q, want := range map[string]int{
		`SELECT COUNT(*) FROM asset_group_members WHERE asset_id = $1`:                                0,
		`SELECT COUNT(*) FROM user_accessible_assets WHERE asset_id = $1`:                             0,
		`SELECT COUNT(*) FROM asset_access_grants WHERE asset_id = $1`:                                0,
		`SELECT COUNT(*) FROM asset_owners WHERE asset_id = $1`:                                       0,
		`SELECT COUNT(*) FROM asset_relationships WHERE source_asset_id = $1 OR target_asset_id = $1`: 0,
		`SELECT COUNT(*) FROM asset_identifiers WHERE asset_id = $1`:                                  0,
		`SELECT COUNT(*) FROM assets WHERE parent_id = $1`:                                            0,
		// History stays for the retention period.
		`SELECT COUNT(*) FROM asset_state_history WHERE asset_id = $1`:         1,
		`SELECT COUNT(*) FROM assets WHERE id = $1 AND deleted_by IS NOT NULL`: 1,
	} {
		if n := countRows(ctx, t, db, q, victim.String()); n != want {
			t.Errorf("%s = %d, want %d", q, n, want)
		}
	}
	if n := countRows(ctx, t, db, `SELECT COUNT(*) FROM asset_group_members WHERE asset_id = $1`, keep.String()); n != 1 {
		t.Error("deleting one asset detached another")
	}

	// The name is free again: a create and an ingest upsert both make a new asset.
	again, err := asset.NewAssetWithTenant(tenant, name, asset.AssetTypeHost, asset.CriticalityLow)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Create(ctx, again); err != nil {
		t.Fatalf("re-create with the deleted name: %v", err)
	}
	if got, err := repo.GetByName(ctx, tenant, name); err != nil || got.ID() != again.ID() {
		t.Fatalf("GetByName after re-create = %v, %v", got, err)
	}
	ingested, err := asset.NewAssetWithTenant(tenant, name, asset.AssetTypeHost, asset.CriticalityLow)
	if err != nil {
		t.Fatal(err)
	}
	_, _, ids, err := repo.UpsertBatch(ctx, []*asset.Asset{ingested})
	if err != nil {
		t.Fatalf("UpsertBatch: %v", err)
	}
	if ids[name] != again.ID() {
		t.Errorf("ingest of the name resolved to %s, want the live asset %s (never the deleted one)", ids[name], again.ID())
	}
}

func TestAssetPurgeDeleted(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewAssetRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	old := seedOwnedAsset(ctx, t, db, tenant, nil)
	recent := seedOwnedAsset(ctx, t, db, tenant, nil)
	live := seedOwnedAsset(ctx, t, db, tenant, nil)
	gained := seedOwnedAsset(ctx, t, db, tenant, nil)
	for _, a := range []shared.ID{old, recent, gained} {
		if err := repo.Delete(ctx, tenant, a, nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.ExecContext(ctx, `UPDATE assets SET deleted_at = NOW() - INTERVAL '40 days' WHERE id IN ($1, $2)`, old.String(), gained.String()); err != nil {
		t.Fatal(err)
	}
	// A finding that raced in after the delete: the purge must keep the row.
	seedGroupFinding(ctx, t, db, tenant, gained, "CVE-2099-3002", "low", nil)

	n, err := repo.PurgeDeleted(ctx, time.Now().AddDate(0, 0, -30), 100)
	if err != nil {
		t.Fatal(err)
	}
	if n < 1 {
		t.Fatalf("purged %d, want at least the old one", n)
	}
	for id, want := range map[shared.ID]int{old: 0, recent: 1, live: 1, gained: 1} {
		if got := countRows(ctx, t, db, `SELECT COUNT(*) FROM assets WHERE id = $1`, id.String()); got != want {
			t.Errorf("asset %s rows = %d, want %d", id, got, want)
		}
	}
}

// Tenant deletion cascades to assets and findings in one statement: the NO
// ACTION findings FK is checked at the end of the statement, so it still works.
func TestTenantDeleteStillCascadesFindings(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	tenant := shared.NewID()
	if _, err := db.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, 'cascade', $2)`, tenant.String(), "cascade-"+tenant.String()); err != nil {
		t.Fatal(err)
	}
	a := seedOwnedAsset(ctx, t, db, tenant, nil)
	f := seedGroupFinding(ctx, t, db, tenant, a, "CVE-2099-3003", "low", nil)
	if _, err := db.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, tenant.String()); err != nil {
		t.Fatalf("tenant delete: %v", err)
	}
	if n := countRows(ctx, t, db, `SELECT COUNT(*) FROM findings WHERE id = $1`, f.String()) +
		countRows(ctx, t, db, `SELECT COUNT(*) FROM assets WHERE id = $1`, a.String()); n != 0 {
		t.Fatalf("%d rows left after tenant delete", n)
	}
}
