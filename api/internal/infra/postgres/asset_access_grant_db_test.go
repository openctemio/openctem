package postgres

import (
	"context"
	"os"
	"testing"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Migration 000372 (owner decision O1) turns today's owner-derived access
// into explicit grants, so nobody loses an asset they can see at upgrade, and
// nobody gains one: an owner_ref owner or an owner whose access row is
// missing gets no grant. After a full refresh, direct ownership alone gives
// no access. Replayed inside a rolled-back transaction.
func TestAccessGrantMigration_PreservesOwnerAccess(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	up, err := os.ReadFile("../../../migrations/000372_asset_access_grants.up.sql")
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}

	tenant := seedTestTenant(ctx, t, db)
	ownerOnly := seedGroupsUser(ctx, t, db, "grant-mig.test")    // sees the asset only as its owner
	ownerInGroup := seedGroupsUser(ctx, t, db, "grant-mig.test") // owner and group member
	refOwner := seedGroupsUser(ctx, t, db, "grant-mig.test")     // owner_ref owner, no access
	noAccess := seedGroupsUser(ctx, t, db, "grant-mig.test")     // manual owner with no access row
	for _, u := range []shared.ID{ownerOnly, ownerInGroup, refOwner, noAccess} {
		addTenantMember(ctx, t, db, tenant, u)
	}
	asset := seedOwnedAsset(ctx, t, db, tenant, nil)
	group := shared.NewID()

	tx, err := testdb.OpenMigrator(t).BeginTx(ctx, nil) // the migration is DDL: schema owner
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	testdb.LockForDDL(t, ctx, tx, "asset_access_grants", "user_accessible_assets")
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := tx.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	exec(`INSERT INTO groups (id, tenant_id, name, slug, is_active) VALUES ($1, $2, $3, $3, true)`,
		group.String(), tenant.String(), "g-"+group.String())
	exec(`INSERT INTO group_members (group_id, user_id) VALUES ($1, $2)`, group.String(), ownerInGroup.String())
	exec(`INSERT INTO asset_owners (asset_id, group_id, ownership_type) VALUES ($1, $2, 'secondary')`, asset.String(), group.String())
	for u, src := range map[shared.ID]string{ownerOnly: "manual", ownerInGroup: "manual", refOwner: "owner_ref", noAccess: "manual"} {
		exec(`INSERT INTO asset_owners (asset_id, user_id, ownership_type, assignment_source) VALUES ($1, $2, 'primary', $3)`,
			asset.String(), u.String(), src)
	}
	for _, u := range []shared.ID{ownerOnly, ownerInGroup} {
		// ON CONFLICT: the group asset insert above already materialized the
		// group member's row (trigger asset_owners_scope_sync, migration 001034).
		exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'primary')
		      ON CONFLICT (user_id, tenant_id, asset_id) DO NOTHING`,
			u.String(), tenant.String(), asset.String())
	}

	if _, err := tx.ExecContext(ctx, string(up)); err != nil {
		t.Fatalf("apply migration: %v", err)
	}
	if _, err := tx.ExecContext(ctx, string(up)); err != nil {
		t.Fatalf("re-apply migration: %v", err)
	}

	granted := func(u shared.ID) bool {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM asset_access_grants WHERE asset_id = $1 AND user_id = $2 AND source = 'migration'`,
			asset.String(), u.String()).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n == 1
	}
	sees := func(u shared.ID) bool {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_accessible_assets WHERE asset_id = $1 AND user_id = $2`,
			asset.String(), u.String()).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n == 1
	}
	if !granted(ownerOnly) || !granted(ownerInGroup) {
		t.Fatal("an owner who could see the asset got no grant")
	}
	if granted(refOwner) || granted(noAccess) {
		t.Fatal("an owner who could not see the asset got a grant")
	}

	// A full refresh recomputes scope without the ownership path.
	exec(`SELECT refresh_user_accessible_assets()`)
	if !sees(ownerOnly) || !sees(ownerInGroup) {
		t.Fatal("pre-existing access was lost after the migration")
	}
	if sees(refOwner) || sees(noAccess) {
		t.Fatal("ownership alone gave access after the migration")
	}

	// Ownership no longer feeds the incremental path either.
	exec(`SELECT refresh_access_for_direct_owner_add($1, $2, 'primary')`, asset.String(), noAccess.String())
	if sees(noAccess) {
		t.Fatal("refresh_access_for_direct_owner_add still grants access")
	}
	// Revoking the migrated grant of the owner-only user removes the access.
	exec(`DELETE FROM asset_access_grants WHERE asset_id = $1 AND user_id = $2`, asset.String(), ownerOnly.String())
	exec(`SELECT refresh_access_for_grant_remove($1, $2)`, asset.String(), ownerOnly.String())
	if sees(ownerOnly) {
		t.Fatal("access stayed after the grant was revoked (ownership must not keep it)")
	}
}
