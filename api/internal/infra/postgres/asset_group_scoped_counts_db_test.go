package postgres

import (
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/assetgroup"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// L-18: a group's counts, risk score and finding count used to be the stored
// tenant-wide values, so a member restricted to some assets learned how many
// assets (and findings) of the group lie outside their data scope, and could
// probe them with the risk / has_findings filters and the sorts. With a
// scope, every one of those values covers only the members in that scope.
func TestAssetGroupList_CountsFollowDataScope_DB(t *testing.T) {
	db, ctx := openRegistryDB(t)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	tenant := seedTestTenant(ctx, t, db)
	user := seedGroupsUser(ctx, t, db, "group-counts-scope.test")
	addTenantMember(ctx, t, db, tenant, user)

	group := shared.NewID()
	exec(`INSERT INTO asset_groups (id, tenant_id, name) VALUES ($1, $2, 'scoped-counts')`, group.String(), tenant.String())
	addAsset := func(name, typ string, risk int, findings int, visible bool) {
		t.Helper()
		id := shared.NewID()
		exec(`INSERT INTO assets (id, tenant_id, name, asset_type, risk_score) VALUES ($1, $2, $3, $4, $5)`,
			id.String(), tenant.String(), name, typ, risk)
		exec(`INSERT INTO asset_group_members (asset_group_id, asset_id) VALUES ($1, $2)`, group.String(), id.String())
		for i := 0; i < findings; i++ {
			exec(`INSERT INTO findings (tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
				VALUES ($1, $2, 'sast', 'test', 'm', 'high', $3, 'new')`, tenant.String(), id.String(), shared.NewID().String())
		}
		if visible {
			exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`,
				user.String(), tenant.String(), id.String())
		}
	}
	addAsset("seen.example.com", "domain", 20, 1, true)
	addAsset("hidden-1.example.com", "domain", 90, 3, false)
	addAsset("hidden-2.example.com", "domain", 90, 2, false)

	repo := NewAssetGroupRepository(&DB{DB: db})
	if err := repo.RecalculateCounts(ctx, group); err != nil {
		t.Fatal(err)
	}
	scope := &shared.DataScope{TenantID: tenant, UserID: user}
	list := func(f assetgroup.Filter) []*assetgroup.AssetGroup {
		t.Helper()
		f = f.WithTenantID(tenant.String())
		res, err := repo.List(ctx, f, assetgroup.NewListOptions(), pagination.New(1, 20))
		if err != nil {
			t.Fatal(err)
		}
		return res.Data
	}

	full := list(assetgroup.NewFilter())
	if len(full) != 1 || full[0].AssetCount() != 3 || full[0].FindingCount() != 6 || full[0].DomainCount() != 3 {
		t.Fatalf("unrestricted: got %d groups, counts %+v", len(full), groupCounts(full))
	}

	f := assetgroup.NewFilter()
	f.DataScope = scope
	got := list(f)
	if len(got) != 1 {
		t.Fatalf("restricted reader sees %d groups, want 1 (the group itself is tenant configuration)", len(got))
	}
	g := got[0]
	if g.AssetCount() != 1 || g.DomainCount() != 1 || g.RiskScore() != 20 || g.FindingCount() != 1 {
		t.Fatalf("restricted counts = asset %d domain %d risk %d findings %d, want 1 1 20 1",
			g.AssetCount(), g.DomainCount(), g.RiskScore(), g.FindingCount())
	}

	// The filters see the scoped values: the stored risk (avg 66) would match.
	min := 50
	f.MinRiskScore = &min
	if n := len(list(f)); n != 0 {
		t.Fatalf("min_risk_score 50 over the scoped risk 20 matched %d groups, want 0", n)
	}
	f.MinRiskScore = nil

	// A scope with no rows sees the group with zero counts and no findings.
	stranger := seedGroupsUser(ctx, t, db, "group-counts-stranger.test")
	addTenantMember(ctx, t, db, tenant, stranger)
	none := assetgroup.NewFilter().WithHasFindings(true)
	none.DataScope = &shared.DataScope{TenantID: tenant, UserID: stranger}
	if n := len(list(none)); n != 0 {
		t.Fatalf("has_findings for a reader with no assets matched %d groups, want 0", n)
	}

	// IDs narrows to the group (the single-group read path).
	byID := assetgroup.NewFilter()
	byID.IDs = []shared.ID{shared.NewID()}
	if n := len(list(byID)); n != 0 {
		t.Fatalf("unknown id matched %d groups", n)
	}

	// Stats follow the same rule.
	st, err := repo.GetStats(ctx, tenant, scope)
	if err != nil {
		t.Fatal(err)
	}
	if st.TotalAssets != 1 || st.TotalFindings != 1 {
		t.Fatalf("restricted stats assets %d findings %d, want 1 1", st.TotalAssets, st.TotalFindings)
	}
	st, err = repo.GetStats(ctx, tenant, nil)
	if err != nil {
		t.Fatal(err)
	}
	if st.TotalAssets != 3 || st.TotalFindings != 6 {
		t.Fatalf("unrestricted stats assets %d findings %d, want 3 6", st.TotalAssets, st.TotalFindings)
	}
}

func groupCounts(gs []*assetgroup.AssetGroup) []int {
	out := []int{}
	for _, g := range gs {
		out = append(out, g.AssetCount(), g.DomainCount(), g.RiskScore(), g.FindingCount())
	}
	return out
}
