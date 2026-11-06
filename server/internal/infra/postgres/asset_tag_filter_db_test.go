package postgres

// The inventory tag filter (any / all / exclude) and the tag list: tenant
// scoped, data scoped, and a private program's system tags neither match,
// exclude nor list for a non-member (RFC-065 §15.3). Requires DATABASE_URL.

import (
	"context"
	"slices"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

func TestAssetTagFilterModesAndTagList(t *testing.T) {
	fx := seedPrivateProgram(t)
	ctx := context.Background()
	tenant := fx.tenant
	enf := datascope.New(NewDataScopeRepository(fx.pdb), func(context.Context) datascope.Caller { return datascope.Caller{} }, nil)
	adminScope, err := enf.ResolveFor(ctx, tenant, datascope.Caller{UserID: fx.admin.String(), IsAdmin: true})
	if err != nil || adminScope == nil {
		t.Fatalf("admin scope = %+v %v", adminScope, err)
	}
	memberScope, err := enf.ResolveFor(ctx, tenant, datascope.Caller{UserID: fx.member.String()})
	if err != nil || memberScope == nil {
		t.Fatalf("member scope = %+v %v", memberScope, err)
	}
	programTag := "program:acme:priv"

	// own: own-tag + env-prod; shared (program-linked): env-prod; a fourth
	// asset with NULL tags; the other tenant's asset carries the same tags.
	mustExec(t, fx.db, `UPDATE assets SET tags = '{own-tag,env-prod}' WHERE id = $1`, fx.own.String())
	mustExec(t, fx.db, `UPDATE assets SET tags = '{env-prod}' WHERE id = $1`, fx.shared1.String())
	mustExec(t, fx.db, `UPDATE assets SET tags = '{env-prod,own-tag,foreign-only}' WHERE id = $1`, fx.foreign.String())
	nullTags := seedTagAsset(t, fx, "null.own"+fx.suffix+".example")
	mustExec(t, fx.db, `UPDATE assets SET tags = NULL WHERE id = $1`, nullTags.String())

	repo := NewAssetRepository(fx.pdb)
	shop, app, own, null := "shop.p"+fx.suffix+".example", "app.p"+fx.suffix+".example", "www.own"+fx.suffix+".example", "null.own"+fx.suffix+".example"
	names := func(f asset.Filter) []string {
		t.Helper()
		page, err := repo.List(ctx, f.WithTenantID(tenant.String()), asset.NewListOptions(), pagination.New(1, 200))
		if err != nil {
			t.Fatal(err)
		}
		out := []string{}
		for _, a := range page.Data {
			out = append(out, a.Name())
		}
		slices.Sort(out)
		return out
	}
	sorted := func(v ...string) []string { slices.Sort(v); return v }

	// Any (default): either tag; never the other tenant's asset.
	if got := names(asset.NewFilter().WithTags("own-tag", "env-prod")); !slices.Equal(got, sorted(own, shop)) {
		t.Fatalf("any = %v", got)
	}
	// All: both tags.
	f := asset.NewFilter().WithTags("own-tag", "env-prod")
	f.TagsMatchAll = true
	if got := names(f); !slices.Equal(got, []string{own}) {
		t.Fatalf("all = %v", got)
	}
	// All across a user tag and a system tag: the owner matches the shared
	// asset; the non-member admin does not (the link is hidden from them);
	// the program member does.
	f = asset.NewFilter().WithTags("env-prod", programTag)
	f.TagsMatchAll = true
	if got := names(f); !slices.Equal(got, []string{shop}) {
		t.Fatalf("owner all with system tag = %v", got)
	}
	f = asset.NewFilter().WithDataScope(adminScope).WithTags("env-prod", programTag)
	f.TagsMatchAll, f.ProgramTagViewer = true, &fx.admin
	if got := names(f); len(got) != 0 {
		t.Fatalf("admin all with hidden system tag = %v", got)
	}
	f = asset.NewFilter().WithDataScope(memberScope).WithTags("env-prod", programTag)
	f.TagsMatchAll, f.ProgramTagViewer = true, &fx.member
	if got := names(f); !slices.Equal(got, []string{shop}) {
		t.Fatalf("member all with system tag = %v", got)
	}

	// Exclude: an asset with NULL tags is kept; the owner excluding the
	// program tag drops both program assets.
	f = asset.NewFilter()
	f.ExcludeTags = []string{"own-tag"}
	if got := names(f); !slices.Equal(got, sorted(app, shop, null)) {
		t.Fatalf("exclude own-tag = %v", got)
	}
	f = asset.NewFilter()
	f.ExcludeTags = []string{programTag}
	if got := names(f); !slices.Equal(got, sorted(own, null)) {
		t.Fatalf("owner exclude program tag = %v", got)
	}
	// The non-member admin excluding the hidden program's tag keeps the
	// shared asset: excluding must not reveal which assets it covers.
	f = asset.NewFilter().WithDataScope(adminScope)
	f.ExcludeTags, f.ProgramTagViewer = []string{programTag}, &fx.admin
	if got := names(f); !slices.Equal(got, sorted(own, shop, null)) {
		t.Fatalf("admin exclude hidden program tag = %v", got)
	}
	// Include and exclude together.
	f = asset.NewFilter().WithTags("env-prod")
	f.ExcludeTags = []string{"own-tag"}
	if got := names(f); !slices.Equal(got, []string{shop}) {
		t.Fatalf("env-prod minus own-tag = %v", got)
	}

	// Tag list: most used first, this tenant only.
	list, err := repo.ListDistinctTags(ctx, tenant, asset.AccessScope{}, asset.TagListQuery{Limit: 50, IncludeSystem: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Tags) == 0 || list.Tags[0] != "env-prod" || slices.Contains(list.Tags, "foreign-only") {
		t.Fatalf("owner tags = %v", list.Tags)
	}
	if !slices.Contains(list.SystemTags, programTag) || !slices.Contains(list.SystemTags, "bug-bounty") {
		t.Fatalf("owner system tags = %v", list.SystemTags)
	}
	// Without include_system no system tags; q is a substring match.
	list, err = repo.ListDistinctTags(ctx, tenant, asset.AccessScope{}, asset.TagListQuery{Limit: 50, Search: "PROD"})
	if err != nil || !slices.Equal(list.Tags, []string{"env-prod"}) || list.SystemTags != nil {
		t.Fatalf("search = %+v %v", list, err)
	}
	// The non-member admin: no system tag of the hidden program.
	list, err = repo.ListDistinctTags(ctx, tenant, asset.AccessScope{DataScopeUserID: &fx.admin, DataScopeUnrestricted: true},
		asset.TagListQuery{Limit: 50, IncludeSystem: true, ProgramTagViewer: &fx.admin})
	if err != nil {
		t.Fatal(err)
	}
	if len(list.SystemTags) != 0 || slices.Contains(list.Tags, "secret-bb") {
		t.Fatalf("admin list = %+v", list)
	}
	// The restricted program member: the program's tags, but not the tags
	// of assets outside their data scope.
	list, err = repo.ListDistinctTags(ctx, tenant, asset.AccessScope{DataScopeUserID: &fx.member},
		asset.TagListQuery{Limit: 50, IncludeSystem: true, ProgramTagViewer: &fx.member})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(list.SystemTags, programTag) || slices.Contains(list.Tags, "own-tag") {
		t.Fatalf("member list = %+v", list)
	}
}

// seedTagAsset adds a domain asset to the fixture's tenant.
func seedTagAsset(t *testing.T, fx privateProgramFixture, name string) shared.ID {
	t.Helper()
	id := shared.NewID()
	mustExec(t, fx.db, `INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, $3, 'domain')`, id.String(), fx.tenant.String(), name)
	return id
}
