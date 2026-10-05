package integration

// The scope materialization (user_accessible_assets) follows every source
// write in the same transaction (migration 000971, RFC-050 W6). Research 21b
// H6: deactivating an access group never removed the access it granted.

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestScopeMaterialization_FollowsSourceWrites(t *testing.T) {
	db := setupTestDB(t)
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()

	tenantID := createTestTenant(t, db, "scope-sync")
	stamp := time.Now().UnixNano()
	userID := createTestUser(t, db, fmt.Sprintf("scope-sync-%d@example.com", stamp), "Scope Sync")
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = db.ExecContext(bg, `DELETE FROM groups WHERE tenant_id = $1`, tenantID.String())
		_, _ = db.ExecContext(bg, `DELETE FROM asset_access_grants WHERE tenant_id = $1`, tenantID.String())
		_, _ = db.ExecContext(bg, `DELETE FROM user_accessible_assets WHERE tenant_id = $1`, tenantID.String())
		_, _ = db.ExecContext(bg, `DELETE FROM tenant_members WHERE tenant_id = $1`, tenantID.String())
		cleanupTestData(db, tenantID)
		_, _ = db.ExecContext(bg, `DELETE FROM users WHERE id = $1`, userID.String())
	})
	createTestMembership(t, db, tenantID, userID, "member")

	assetA := createTestAsset(t, db, tenantID, fmt.Sprintf("sync-a-%d", stamp))
	assetB := createTestAsset(t, db, tenantID, fmt.Sprintf("sync-b-%d", stamp))
	groupID := shared.NewID()
	tid, uid := tenantID.String(), userID.String()

	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	sees := func(asset shared.ID) bool {
		t.Helper()
		var n int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_accessible_assets
			WHERE tenant_id = $1 AND user_id = $2 AND asset_id = $3`, tid, uid, asset.String()).Scan(&n); err != nil {
			t.Fatalf("read scope: %v", err)
		}
		return n > 0
	}

	exec(`INSERT INTO groups (id, tenant_id, name, slug, is_active) VALUES ($1, $2, 'Sync', $3, TRUE)`,
		groupID.String(), tid, fmt.Sprintf("sync-%d", stamp))
	exec(`INSERT INTO group_members (group_id, user_id, role) VALUES ($1, $2, 'member')`, groupID.String(), uid)

	// Assignment: no explicit refresh call, the insert itself grants.
	exec(`INSERT INTO asset_owners (asset_id, group_id, ownership_type) VALUES ($1, $2, 'primary')`, assetA.String(), groupID.String())
	exec(`INSERT INTO asset_owners (asset_id, group_id, ownership_type) VALUES ($1, $2, 'primary')`, assetB.String(), groupID.String())
	if !sees(assetA) || !sees(assetB) {
		t.Fatal("assigning assets to the group did not grant its member access")
	}
	// B is also granted directly: it must survive every group change below.
	exec(`INSERT INTO asset_access_grants (tenant_id, asset_id, user_id) VALUES ($1, $2, $3)`, tid, assetB.String(), uid)

	// H6: deactivating the group removes what it granted, at once.
	exec(`UPDATE groups SET is_active = FALSE WHERE id = $1 AND tenant_id = $2`, groupID.String(), tid)
	if sees(assetA) {
		t.Error("a deactivated group still grants its asset (H6)")
	}
	if !sees(assetB) {
		t.Error("the direct grant was lost when the group was deactivated")
	}
	exec(`UPDATE groups SET is_active = TRUE WHERE id = $1 AND tenant_id = $2`, groupID.String(), tid)
	if !sees(assetA) {
		t.Error("re-activating the group did not restore its asset")
	}

	// Unassigning through any path removes the access.
	exec(`DELETE FROM asset_owners WHERE asset_id = $1 AND group_id = $2`, assetA.String(), groupID.String())
	if sees(assetA) {
		t.Error("an unassigned asset is still visible")
	}

	// Leaving the group removes its assets (grant excepted).
	exec(`INSERT INTO asset_owners (asset_id, group_id, ownership_type) VALUES ($1, $2, 'primary')`, assetA.String(), groupID.String())
	exec(`DELETE FROM group_members WHERE group_id = $1 AND user_id = $2`, groupID.String(), uid)
	if sees(assetA) || !sees(assetB) {
		t.Errorf("after leaving the group: sees A=%v (want false) B=%v (want true)", sees(assetA), sees(assetB))
	}
	exec(`INSERT INTO group_members (group_id, user_id, role) VALUES ($1, $2, 'member')`, groupID.String(), uid)
	exec(`SELECT refresh_access_for_member_add($1, $2)`, groupID.String(), uid)
	if !sees(assetA) {
		t.Fatal("re-joining the group did not restore access")
	}

	// A scope rule's auto-assignments go when the rule is deactivated or deleted.
	for _, mode := range []string{"deactivate", "delete"} {
		ruleID := shared.NewID()
		assetR := createTestAsset(t, db, tenantID, fmt.Sprintf("sync-r-%s-%d", mode, stamp))
		exec(`INSERT INTO group_asset_scope_rules (id, tenant_id, group_id, name, rule_type, match_tags)
		      VALUES ($1, $2, $3, $4, 'tag_match', ARRAY['env:prod'])`, ruleID.String(), tid, groupID.String(), "rule-"+mode)
		exec(`INSERT INTO asset_owners (asset_id, group_id, ownership_type, assignment_source, scope_rule_id)
		      VALUES ($1, $2, 'secondary', 'scope_rule', $3)`, assetR.String(), groupID.String(), ruleID.String())
		if !sees(assetR) {
			t.Fatalf("%s: the rule's auto-assignment did not grant access", mode)
		}
		if mode == "deactivate" {
			exec(`UPDATE group_asset_scope_rules SET is_active = FALSE WHERE id = $1 AND tenant_id = $2`, ruleID.String(), tid)
		} else {
			exec(`DELETE FROM group_asset_scope_rules WHERE id = $1 AND tenant_id = $2`, ruleID.String(), tid)
		}
		if sees(assetR) {
			t.Errorf("%s: a scope rule's auto-assignment still grants access (M-2)", mode)
		}
		var left int
		_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM asset_owners WHERE asset_id = $1 AND group_id = $2`,
			assetR.String(), groupID.String()).Scan(&left)
		if left != 0 {
			t.Errorf("%s: the rule's asset row was left behind (orphaned scope_rule_id)", mode)
		}
	}

	// Deleting the group removes everything it granted (grant excepted).
	exec(`DELETE FROM groups WHERE id = $1 AND tenant_id = $2`, groupID.String(), tid)
	if sees(assetA) || !sees(assetB) {
		t.Errorf("after deleting the group: sees A=%v (want false) B=%v (want true)", sees(assetA), sees(assetB))
	}
}
