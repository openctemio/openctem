package postgres

import (
	"context"
	"database/sql"
	"os"
	"testing"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/accesscontrol"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// One owner model: asset_owners is the only owner store. These tests cover the
// migration that folded assets.owner_id into it, the owner_ref sync, and the
// tenant-scoped owner lookups every reader uses.

func addTenantMember(ctx context.Context, t *testing.T, db *sql.DB, tenantID, userID shared.ID) {
	t.Helper()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, 'member')`,
		userID.String(), tenantID.String()); err != nil {
		t.Fatalf("seed tenant member: %v", err)
	}
}

type ownerRow struct {
	ownershipType string
	source        string
}

func assetOwnerRows(ctx context.Context, t *testing.T, q interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}, assetID shared.ID) map[string]ownerRow {
	t.Helper()
	rows, err := q.QueryContext(ctx,
		`SELECT user_id::text, ownership_type, COALESCE(assignment_source, 'manual')
		 FROM asset_owners WHERE asset_id = $1 AND user_id IS NOT NULL`, assetID.String())
	if err != nil {
		t.Fatalf("list owners: %v", err)
	}
	defer rows.Close()
	out := map[string]ownerRow{}
	for rows.Next() {
		var uid string
		var r ownerRow
		if err := rows.Scan(&uid, &r.ownershipType, &r.source); err != nil {
			t.Fatal(err)
		}
		out[uid] = r
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func countAccessRows(ctx context.Context, t *testing.T, db *sql.DB, userID shared.ID) int {
	t.Helper()
	var n int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM user_accessible_assets WHERE user_id = $1`, userID.String()).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// Migration 000340 copies assets.owner_id into asset_owners as a primary
// 'owner_ref' row, keeps an explicit RACI row as it is, skips an owner who
// left the tenant, and grants no data access. It is replayed inside a
// rolled-back transaction with the dropped column recreated.
func TestOwnerModelMigration_CopiesOwnerID(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	up, err := os.ReadFile("../../../migrations/000340_asset_owner_single_model.up.sql")
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}

	tenant := seedTestTenant(ctx, t, db)
	alice := seedGroupsUser(ctx, t, db, "owner-model.test")
	bob := seedGroupsUser(ctx, t, db, "owner-model.test")
	gone := seedGroupsUser(ctx, t, db, "owner-model.test")
	addTenantMember(ctx, t, db, tenant, alice)
	addTenantMember(ctx, t, db, tenant, bob)

	tx, err := testdb.OpenMigrator(t).BeginTx(ctx, nil) // the migration is DDL: schema owner
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	testdb.LockForDDL(t, ctx, tx, "tenants", "assets", "asset_owners")
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := tx.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	exec(`ALTER TABLE assets ADD COLUMN IF NOT EXISTS owner_id UUID`)

	aliceAsset, bobAsset, goneAsset := shared.NewID(), shared.NewID(), shared.NewID()
	for id, owner := range map[shared.ID]shared.ID{aliceAsset: alice, bobAsset: bob, goneAsset: gone} {
		exec(`INSERT INTO assets (id, tenant_id, name, asset_type, owner_id) VALUES ($1, $2, $3, 'host', $4)`,
			id.String(), tenant.String(), "asset-"+id.String(), owner.String())
	}
	// Bob is already an explicit secondary owner of his asset.
	exec(`INSERT INTO asset_owners (asset_id, user_id, ownership_type, assignment_source) VALUES ($1, $2, 'secondary', 'manual')`,
		bobAsset.String(), bob.String())

	if _, err := tx.ExecContext(ctx, string(up)); err != nil {
		t.Fatalf("apply migration: %v", err)
	}
	// Re-runnable.
	if _, err := tx.ExecContext(ctx, string(up)); err != nil {
		t.Fatalf("re-apply migration: %v", err)
	}

	if got := assetOwnerRows(ctx, t, tx, aliceAsset); len(got) != 1 || got[alice.String()] != (ownerRow{"primary", accesscontrol.AssignmentSourceOwnerRef}) {
		t.Errorf("alice's asset owners = %+v, want one primary owner_ref row for alice", got)
	}
	if got := assetOwnerRows(ctx, t, tx, bobAsset); len(got) != 1 || got[bob.String()] != (ownerRow{"secondary", "manual"}) {
		t.Errorf("bob's asset owners = %+v, want his explicit secondary row kept as it is", got)
	}
	if got := assetOwnerRows(ctx, t, tx, goneAsset); len(got) != 0 {
		t.Errorf("owner who left the tenant was copied: %+v", got)
	}

	// The copied row grants no data access, even on a full refresh.
	exec(`SELECT refresh_user_accessible_assets()`)
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_accessible_assets WHERE user_id = $1`, alice.String()).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("owner_ref owner got %d data-scope rows, want 0", n)
	}
}

// SyncOwnerRefOwner keeps one owner_ref-derived primary owner per asset,
// follows owner_ref changes, never touches an owner set by a person, never
// adds a non-member, ignores another tenant's asset, and grants no access.
func TestSyncOwnerRefOwner(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewAccessControlRepository(&DB{DB: db})

	tenant := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)
	alice := seedGroupsUser(ctx, t, db, "owner-sync.test")
	bob := seedGroupsUser(ctx, t, db, "owner-sync.test")
	carol := seedGroupsUser(ctx, t, db, "owner-sync.test")
	outsider := seedGroupsUser(ctx, t, db, "owner-sync.test")
	for _, u := range []shared.ID{alice, bob, carol} {
		addTenantMember(ctx, t, db, tenant, u)
	}
	asset := seedOwnedAsset(ctx, t, db, tenant, nil)
	foreign := seedOwnedAsset(ctx, t, db, other, nil)

	// Carol is a manual secondary owner; the sync must never touch her.
	if _, err := db.ExecContext(ctx,
		`INSERT INTO asset_owners (asset_id, user_id, ownership_type, assignment_source) VALUES ($1, $2, 'secondary', 'manual')`,
		asset.String(), carol.String()); err != nil {
		t.Fatal(err)
	}

	sync := func(u *shared.ID) {
		t.Helper()
		if err := repo.SyncOwnerRefOwner(ctx, tenant, asset, u); err != nil {
			t.Fatalf("sync: %v", err)
		}
	}
	derived := ownerRow{"primary", accesscontrol.AssignmentSourceOwnerRef}
	carolRow := ownerRow{"secondary", "manual"}

	sync(&alice)
	sync(&alice) // idempotent
	if got := assetOwnerRows(ctx, t, db, asset); len(got) != 2 || got[alice.String()] != derived || got[carol.String()] != carolRow {
		t.Fatalf("after alice: %+v", got)
	}

	sync(&bob)
	if got := assetOwnerRows(ctx, t, db, asset); len(got) != 2 || got[bob.String()] != derived || got[carol.String()] != carolRow {
		t.Fatalf("after owner_ref changed to bob: %+v", got)
	}

	sync(&carol) // already a manual owner: nothing changes
	if got := assetOwnerRows(ctx, t, db, asset); len(got) != 1 || got[carol.String()] != carolRow {
		t.Fatalf("after owner_ref matched the manual owner: %+v", got)
	}

	sync(&outsider) // not a member: not added
	if got := assetOwnerRows(ctx, t, db, asset); len(got) != 1 || got[carol.String()] != carolRow {
		t.Fatalf("after owner_ref matched a non-member: %+v", got)
	}

	sync(&alice)
	sync(nil) // owner_ref cleared or unmatched
	if got := assetOwnerRows(ctx, t, db, asset); len(got) != 1 || got[carol.String()] != carolRow {
		t.Fatalf("after owner_ref cleared: %+v", got)
	}

	// Another tenant's asset is never written.
	if err := repo.SyncOwnerRefOwner(ctx, tenant, foreign, &alice); err != nil {
		t.Fatalf("sync foreign: %v", err)
	}
	if got := assetOwnerRows(ctx, t, db, foreign); len(got) != 0 {
		t.Fatalf("foreign asset got owners: %+v", got)
	}

	if n := countAccessRows(ctx, t, db, alice) + countAccessRows(ctx, t, db, bob); n != 0 {
		t.Errorf("owner_ref sync created %d data-scope rows, want 0", n)
	}
}

// The owner lookups are tenant-scoped and use the documented definitions:
// the primary user owner is the earliest primary user row of a member; a
// responsible owner is a primary or secondary user row.
func TestOwnerLookups_TenantScoped(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewAccessControlRepository(&DB{DB: db})

	tenant := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)
	first := seedGroupsUser(ctx, t, db, "owner-lookup.test")
	second := seedGroupsUser(ctx, t, db, "owner-lookup.test")
	stakeholder := seedGroupsUser(ctx, t, db, "owner-lookup.test")
	addTenantMember(ctx, t, db, tenant, first)
	addTenantMember(ctx, t, db, tenant, second)
	addTenantMember(ctx, t, db, tenant, stakeholder)

	a1 := seedOwnedAsset(ctx, t, db, tenant, nil)
	a2 := seedOwnedAsset(ctx, t, db, tenant, nil)
	unowned := seedOwnedAsset(ctx, t, db, tenant, nil)
	foreign := seedOwnedAsset(ctx, t, db, other, nil)

	insert := func(asset, user shared.ID, typ, at string) {
		t.Helper()
		if _, err := db.ExecContext(ctx,
			`INSERT INTO asset_owners (asset_id, user_id, ownership_type, assigned_at) VALUES ($1, $2, $3, $4)`,
			asset.String(), user.String(), typ, at); err != nil {
			t.Fatal(err)
		}
	}
	insert(a1, second, "primary", "2026-01-02T00:00:00Z")
	insert(a1, first, "primary", "2026-01-01T00:00:00Z")
	insert(a2, second, "secondary", "2026-01-01T00:00:00Z")
	insert(a2, stakeholder, "stakeholder", "2026-01-01T00:00:00Z")
	insert(foreign, first, "primary", "2026-01-01T00:00:00Z")

	primaries, err := repo.GetPrimaryUserOwnersByAssetIDs(ctx, tenant, []shared.ID{a1, a2, unowned, foreign})
	if err != nil {
		t.Fatal(err)
	}
	if len(primaries) != 1 || primaries[a1] != first {
		t.Errorf("primary user owners = %v, want only a1 → earliest primary (first)", primaries)
	}

	owned, err := repo.FilterAssetsOwnedByUser(ctx, tenant, second, []shared.ID{a1, a2, unowned, foreign})
	if err != nil {
		t.Fatal(err)
	}
	if len(owned) != 2 || !owned[a1] || !owned[a2] {
		t.Errorf("assets owned by second = %v, want a1 (primary) and a2 (secondary)", owned)
	}
	owned, err = repo.FilterAssetsOwnedByUser(ctx, tenant, stakeholder, []shared.ID{a2})
	if err != nil {
		t.Fatal(err)
	}
	if len(owned) != 0 {
		t.Errorf("a stakeholder is not a responsible owner, got %v", owned)
	}
	owned, err = repo.FilterAssetsOwnedByUser(ctx, tenant, first, []shared.ID{foreign})
	if err != nil {
		t.Fatal(err)
	}
	if len(owned) != 0 {
		t.Errorf("another tenant's asset leaked into the owned set: %v", owned)
	}
}

// "Assigned to me" on the flat findings list reads asset_owners: a primary or
// secondary owner of the finding's asset sees it, a stakeholder does not.
func TestFindingList_AssignedToMe_ReadsAssetOwners(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewFindingRepository(&DB{DB: db})

	tenant := seedTestTenant(ctx, t, db)
	me := seedGroupsUser(ctx, t, db, "flat-mine.test")

	primaryAsset := seedOwnedAsset(ctx, t, db, tenant, &me)
	secondaryAsset := seedOwnedAsset(ctx, t, db, tenant, nil)
	stakeholderAsset := seedOwnedAsset(ctx, t, db, tenant, nil)
	for asset, typ := range map[shared.ID]string{secondaryAsset: "secondary", stakeholderAsset: "stakeholder"} {
		if _, err := db.ExecContext(ctx,
			`INSERT INTO asset_owners (asset_id, user_id, ownership_type) VALUES ($1, $2, $3)`,
			asset.String(), me.String(), typ); err != nil {
			t.Fatal(err)
		}
	}
	fPrimary := seedGroupFinding(ctx, t, db, tenant, primaryAsset, "CVE-2099-1001", "high", nil)
	fSecondary := seedGroupFinding(ctx, t, db, tenant, secondaryAsset, "CVE-2099-1002", "high", nil)
	seedGroupFinding(ctx, t, db, tenant, stakeholderAsset, "CVE-2099-1003", "high", nil)

	filter := vulnerability.NewFindingFilter()
	filter.TenantID = &tenant
	filter.RelatedToUserID = &me
	res, err := repo.List(ctx, filter, vulnerability.NewFindingListOptions(), pagination.New(1, 50))
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	got := map[shared.ID]bool{}
	for _, f := range res.Data {
		got[f.ID()] = true
	}
	if len(got) != 2 || !got[fPrimary] || !got[fSecondary] {
		t.Errorf("assigned-to-me findings = %v, want the primary and secondary owner's findings only", got)
	}
}
