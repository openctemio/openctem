package postgres

import (
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// The asset list filters the New Scan target picker uses: members of asset
// groups and assets owned by users or groups. Another tenant's group or
// owner never matches, and the filters compose with the data scope.
func TestAssetList_GroupAndOwnerFilters_DB(t *testing.T) {
	db, ctx := openRegistryDB(t)
	repo := NewAssetRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db).String()
	other := seedTestTenant(ctx, t, db).String()
	user := seedGroupsUser(ctx, t, db, "picker-filter.test")
	addTenantMember(ctx, t, db, shared.MustIDFromString(tenant), user)

	now := time.Now().UTC()
	a := insertCTEMAsset(t, db, tenant, "pick-a", "", false, "", "", now)
	b := insertCTEMAsset(t, db, tenant, "pick-b", "", false, "", "", now)
	c := insertCTEMAsset(t, db, tenant, "pick-c", "", false, "", "", now)
	foreignAsset := insertCTEMAsset(t, db, other, "pick-foreign", "", false, "", "", now)

	g1, g2, foreignGroup := shared.NewID().String(), shared.NewID().String(), shared.NewID().String()
	mustExec(t, db, `INSERT INTO asset_groups (id, tenant_id, name) VALUES ($1,$2,'g1'), ($3,$2,'g2')`, g1, tenant, g2)
	mustExec(t, db, `INSERT INTO asset_groups (id, tenant_id, name) VALUES ($1,$2,'fg')`, foreignGroup, other)
	mustExec(t, db, `INSERT INTO asset_group_members (asset_group_id, asset_id) VALUES ($1,$2), ($3,$4)`, g1, a, g2, b)
	mustExec(t, db, `INSERT INTO asset_group_members (asset_group_id, asset_id) VALUES ($1,$2)`, foreignGroup, foreignAsset)

	team := shared.NewID().String()
	mustExec(t, db, `INSERT INTO groups (id, tenant_id, name, slug) VALUES ($1,$2,'Team','team-picker')`, team, tenant)
	mustExec(t, db, `INSERT INTO asset_owners (asset_id, group_id, ownership_type) VALUES ($1,$2,'primary')`, b, team)
	mustExec(t, db, `INSERT INTO asset_owners (asset_id, user_id, ownership_type) VALUES ($1,$2,'primary')`, c, user.String())

	ids := func(f asset.Filter) map[string]bool {
		t.Helper()
		res, err := repo.List(ctx, f.WithTenantID(tenant), asset.NewListOptions(), pagination.New(1, 50))
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]bool{}
		for _, x := range res.Data {
			out[x.ID().String()] = true
		}
		return out
	}
	is := func(name string, got map[string]bool, want ...string) {
		t.Helper()
		if len(got) != len(want) {
			t.Fatalf("%s: got %v, want %v", name, got, want)
		}
		for _, w := range want {
			if !got[w] {
				t.Fatalf("%s: missing %s (got %v)", name, w, got)
			}
		}
	}

	is("group g1", ids(asset.NewFilter().WithAssetGroupIDs(g1)), a)
	is("groups g1+g2", ids(asset.NewFilter().WithAssetGroupIDs(g1, g2)), a, b)
	is("another tenant's group", ids(asset.NewFilter().WithAssetGroupIDs(foreignGroup)))
	is("owner team", ids(asset.NewFilter().WithOwnerIDs(team)), b)
	is("owner user", ids(asset.NewFilter().WithOwnerIDs(user.String())), c)
	is("owner team or user", ids(asset.NewFilter().WithOwnerIDs(team, user.String())), b, c)
	is("unknown owner", ids(asset.NewFilter().WithOwnerIDs(shared.NewID().String())))
	is("group and owner", ids(asset.NewFilter().WithAssetGroupIDs(g1, g2).WithOwnerIDs(team)), b)

	// A restricted reader sees only their scope inside the filter.
	mustExec(t, db, `INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1,$2,$3,'secondary')`,
		user.String(), tenant, a)
	scoped := asset.NewFilter().WithAssetGroupIDs(g1, g2)
	scoped.DataScopeUserID = &user
	is("groups, restricted reader", ids(scoped), a)
}
