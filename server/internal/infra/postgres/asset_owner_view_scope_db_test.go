package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Owning an asset grants view of it (migration asset_owner_view_scope,
// docs/architecture/asset-ownership.md): a primary or secondary user owner
// set by a person has the asset, and so its findings, in their data scope;
// the row goes as soon as the ownership does. Owners matched from owner_ref
// and stakeholder owners get nothing, another tenant's member gets nothing,
// and owning asset A never shows asset B. Requires DATABASE_URL.
func TestAssetOwnerViewScope(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	scope := NewDataScopeRepository(&DB{DB: db})

	tenant := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)
	casey := seedGroupsUser(ctx, t, db, "owner-scope.test")    // primary owner of A
	sam := seedGroupsUser(ctx, t, db, "owner-scope.test")      // secondary owner of A
	riley := seedGroupsUser(ctx, t, db, "owner-scope.test")    // stakeholder of A
	derived := seedGroupsUser(ctx, t, db, "owner-scope.test")  // owner_ref match on A
	outsider := seedGroupsUser(ctx, t, db, "owner-scope.test") // member of the other tenant only
	for _, u := range []shared.ID{casey, sam, riley, derived} {
		addTenantMember(ctx, t, db, tenant, u)
	}
	addTenantMember(ctx, t, db, other, outsider)

	assetA := seedOwnedAsset(ctx, t, db, tenant, nil)
	assetB := seedOwnedAsset(ctx, t, db, tenant, nil)
	findingA := seedFinding(ctx, t, db, tenant, assetA, "sast", "high", "new")
	findingB := seedFinding(ctx, t, db, tenant, assetB, "sast", "high", "new")

	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	addOwner := func(asset, user shared.ID, typ, source string) {
		t.Helper()
		exec(`INSERT INTO asset_owners (asset_id, user_id, ownership_type, assignment_source) VALUES ($1, $2, $3, $4)`,
			asset.String(), user.String(), typ, source)
	}
	sees := func(user shared.ID) map[shared.ID]bool {
		t.Helper()
		ids, err := scope.AssetIDsInScope(ctx, tenant, user, []shared.ID{assetA, assetB})
		if err != nil {
			t.Fatal(err)
		}
		out := map[shared.ID]bool{}
		for _, id := range ids {
			out[id] = true
		}
		return out
	}

	addOwner(assetA, casey, "primary", "manual")
	addOwner(assetA, sam, "secondary", "manual")
	addOwner(assetA, riley, "stakeholder", "manual")
	addOwner(assetA, derived, "primary", "owner_ref")
	// A member of another tenant named as owner (asset_owners has no
	// tenant column): never in scope.
	addOwner(assetA, outsider, "primary", "manual")

	for _, u := range []shared.ID{casey, sam} {
		if got := sees(u); !got[assetA] || got[assetB] {
			t.Errorf("owner %s sees %v, want only asset A", u, got)
		}
		f, err := scope.FindingIDsInScope(ctx, tenant, u, []shared.ID{findingA, findingB})
		if err != nil {
			t.Fatal(err)
		}
		if len(f) != 1 || f[0] != findingA {
			t.Errorf("owner %s sees findings %v, want only the finding of asset A", u, f)
		}
	}
	for name, u := range map[string]shared.ID{"stakeholder": riley, "owner_ref owner": derived} {
		if got := sees(u); len(got) != 0 {
			t.Errorf("%s sees %v, want nothing", name, got)
		}
	}
	if n := countAccessRows(ctx, t, db, outsider); n != 0 {
		t.Errorf("a member of another tenant got %d scope rows from ownership", n)
	}
	if ids, err := scope.AssetIDsInScope(ctx, other, outsider, []shared.ID{assetA}); err != nil || len(ids) != 0 {
		t.Errorf("outsider in its own tenant sees %v (%v)", ids, err)
	}

	// Demoted to stakeholder: access goes at once.
	exec(`UPDATE asset_owners SET ownership_type = 'stakeholder' WHERE asset_id = $1 AND user_id = $2`, assetA.String(), sam.String())
	if got := sees(sam); len(got) != 0 {
		t.Errorf("demoted owner still sees %v", got)
	}
	// Promoted back: access returns.
	exec(`UPDATE asset_owners SET ownership_type = 'primary' WHERE asset_id = $1 AND user_id = $2`, assetA.String(), sam.String())
	if got := sees(sam); !got[assetA] {
		t.Errorf("promoted owner does not see asset A: %v", got)
	}

	// Ownership moved to another member (offboarding hand-over): the old
	// owner loses the asset, the new one gets it.
	exec(`DELETE FROM asset_owners WHERE asset_id = $1 AND user_id = $2`, assetA.String(), riley.String())
	exec(`UPDATE asset_owners SET user_id = $3 WHERE asset_id = $1 AND user_id = $2`, assetA.String(), sam.String(), riley.String())
	if got := sees(sam); len(got) != 0 {
		t.Errorf("previous owner still sees %v", got)
	}
	if got := sees(riley); !got[assetA] {
		t.Errorf("new owner does not see asset A: %v", got)
	}

	// Ex-owner loses access when the ownership is removed.
	exec(`DELETE FROM asset_owners WHERE asset_id = $1 AND user_id = $2`, assetA.String(), casey.String())
	if got := sees(casey); len(got) != 0 {
		t.Errorf("ex-owner still sees %v", got)
	}

	// Removing ownership keeps access that another source still gives.
	addOwner(assetA, casey, "primary", "manual")
	exec(`INSERT INTO asset_access_grants (tenant_id, asset_id, user_id, source) VALUES ($1, $2, $3, 'manual')`,
		tenant.String(), assetA.String(), casey.String())
	exec(`DELETE FROM asset_owners WHERE asset_id = $1 AND user_id = $2`, assetA.String(), casey.String())
	if got := sees(casey); !got[assetA] {
		t.Errorf("explicit grant lost with the ownership: %v", got)
	}
	// And revoking the grant keeps access the ownership gives.
	addOwner(assetA, casey, "primary", "manual")
	exec(`DELETE FROM asset_access_grants WHERE asset_id = $1 AND user_id = $2`, assetA.String(), casey.String())
	exec(`SELECT refresh_access_for_grant_remove($1, $2)`, assetA.String(), casey.String())
	if got := sees(casey); !got[assetA] {
		t.Errorf("ownership lost with the grant: %v", got)
	}

	// A disabled member keeps no scope from ownership; full rebuilds agree.
	exec(`UPDATE tenant_members SET status = 'suspended' WHERE tenant_id = $1 AND user_id = $2`, tenant.String(), casey.String())
	exec(`SELECT refresh_access_for_user($1, $2)`, tenant.String(), casey.String())
	if got := sees(casey); len(got) != 0 {
		t.Errorf("suspended owner sees %v", got)
	}
	exec(`UPDATE tenant_members SET status = 'active' WHERE tenant_id = $1 AND user_id = $2`, tenant.String(), casey.String())
	exec(`SELECT refresh_user_accessible_assets_for_tenant($1)`, tenant.String())
	if got := sees(casey); !got[assetA] || got[assetB] {
		t.Errorf("after tenant rebuild the owner sees %v, want only asset A", got)
	}
	if n := countAccessRows(ctx, t, db, derived); n != 0 {
		t.Errorf("after tenant rebuild the owner_ref owner has %d rows", n)
	}
}

// A creator grant (source 'creator') is a valid explicit grant.
func TestAssetAccessGrant_CreatorSource(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	tenant := seedTestTenant(ctx, t, db)
	u := seedGroupsUser(ctx, t, db, "creator-grant.test")
	addTenantMember(ctx, t, db, tenant, u)
	asset := seedOwnedAsset(ctx, t, db, tenant, nil)
	var id string
	if err := db.QueryRowContext(ctx,
		`INSERT INTO asset_access_grants (tenant_id, asset_id, user_id, source) VALUES ($1, $2, $3, 'creator') RETURNING id::text`,
		tenant.String(), asset.String(), u.String()).Scan(&id); err != nil {
		t.Fatalf("creator grant refused: %v", err)
	}
}
