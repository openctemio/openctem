package postgres

// Private program assets (RFC-065 §15.3), the side channels: a non-member
// administrator must not learn of a private program, or count its hidden
// assets, through the inventory tag filter, the program-assets filter, the
// tag suggestions, the EASM overview or a notification push. Members and
// owners still see them; another tenant is never affected. Requires
// DATABASE_URL.

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/notification"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

func TestPrivateProgramSideChannels(t *testing.T) {
	fx := seedPrivateProgram(t)
	ctx := context.Background()
	tenant := fx.tenant
	enf := datascope.New(NewDataScopeRepository(fx.pdb), func(context.Context) datascope.Caller { return datascope.Caller{} }, nil)
	adminScope, err := enf.ResolveFor(ctx, tenant, datascope.Caller{UserID: fx.admin.String(), IsAdmin: true})
	if err != nil || adminScope == nil || !adminScope.Unrestricted {
		t.Fatalf("admin scope = %+v %v", adminScope, err)
	}
	memberScope, err := enf.ResolveFor(ctx, tenant, datascope.Caller{UserID: fx.member.String()})
	if err != nil || memberScope == nil {
		t.Fatalf("member scope = %+v %v", memberScope, err)
	}
	programTag := "program:acme:priv"

	assets := NewAssetRepository(fx.pdb)
	names := func(f asset.Filter) []string {
		t.Helper()
		page, err := assets.List(ctx, f.WithTenantID(tenant.String()), asset.NewListOptions(), pagination.New(1, 200))
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
	shop, app := "shop.p"+fx.suffix+".example", "app.p"+fx.suffix+".example"

	// Tag filter: the private program's system tags (program, platform,
	// bug-bounty) do not match the shared asset for the non-member admin.
	for _, tag := range []string{programTag, "platform:acme", "bug-bounty"} {
		f := asset.NewFilter().WithDataScope(adminScope).WithTags(tag)
		f.ProgramTagViewer = &fx.admin
		if got := names(f); len(got) != 0 {
			t.Fatalf("admin tag filter %q matched %v", tag, got)
		}
	}
	// The member matches both program assets, the owner (no viewer) too.
	f := asset.NewFilter().WithDataScope(memberScope).WithTags(programTag)
	f.ProgramTagViewer = &fx.member
	if got := names(f); !slices.Equal(got, []string{app, shop}) {
		t.Fatalf("member tag filter = %v", got)
	}
	if got := names(asset.NewFilter().WithTags(programTag)); !slices.Equal(got, []string{app, shop}) {
		t.Fatalf("owner tag filter = %v", got)
	}
	// A user tag still matches as before.
	f = asset.NewFilter().WithDataScope(adminScope).WithTags("own-tag")
	f.ProgramTagViewer = &fx.admin
	if got := names(f); len(got) != 1 {
		t.Fatalf("admin user-tag filter = %v", got)
	}

	// program_assets=only: nothing for the non-member admin, the shared
	// asset for the member.
	f = asset.NewFilter().WithDataScope(adminScope)
	f.ProgramAssets, f.ProgramTagViewer = "only", &fx.admin
	if got := names(f); len(got) != 0 {
		t.Fatalf("admin program assets = %v", got)
	}
	f = asset.NewFilter().WithDataScope(memberScope)
	f.ProgramAssets, f.ProgramTagViewer = "only", &fx.member
	if got := names(f); !slices.Equal(got, []string{app, shop}) {
		t.Fatalf("member program assets = %v", got)
	}

	// Tag suggestions: the hidden asset's tag is not suggested to the
	// admin; the owner gets both.
	tags, err := assets.ListDistinctTags(ctx, tenant, asset.AccessScope{DataScopeUserID: &fx.admin, DataScopeUnrestricted: true}, "", nil, 50)
	if err != nil || slices.Contains(tags, "secret-bb") || !slices.Contains(tags, "own-tag") {
		t.Fatalf("admin tag suggestions = %v %v", tags, err)
	}
	tags, err = assets.ListDistinctTags(ctx, tenant, asset.AccessScope{}, "", nil, 50)
	if err != nil || !slices.Contains(tags, "secret-bb") || !slices.Contains(tags, "own-tag") {
		t.Fatalf("owner tag suggestions = %v %v", tags, err)
	}

	// EASM overview counts: the admin counts one asset fewer than the
	// owner; a restricted member whose scope rows name the hidden asset
	// does not count it either.
	easm := NewEASMSummaryRepository(fx.pdb)
	now := time.Now().UTC()
	all, err := easm.Summary(ctx, tenant, nil, now, 10)
	if err != nil {
		t.Fatal(err)
	}
	asAdmin, err := easm.Summary(ctx, tenant, adminScope, now, 10)
	if err != nil {
		t.Fatal(err)
	}
	if all.AssetsByType["domain"] != 3 || asAdmin.AssetsByType["domain"] != 2 {
		t.Fatalf("easm domains: owner %d admin %d, want 3 and 2", all.AssetsByType["domain"], asAdmin.AssetsByType["domain"])
	}
	scoped := seedGroupsUser(ctx, t, fx.db, "ppc.example")
	for _, id := range []shared.ID{fx.hidden, fx.own} {
		if _, err := fx.db.Exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id) VALUES ($1, $2, $3)`,
			scoped.String(), tenant.String(), id.String()); err != nil {
			t.Fatal(err)
		}
	}
	asScoped, err := easm.Summary(ctx, tenant, &shared.DataScope{TenantID: tenant, UserID: scoped}, now, 10)
	if err != nil || asScoped.AssetsByType["domain"] != 1 {
		t.Fatalf("easm domains for a scoped non-member = %v %v, want 1", asScoped.AssetsByType, err)
	}

	// Notification push: a notice about the hidden finding reaches the
	// member and the owner, not the admin; one about an own finding still
	// reaches the admin.
	notifs := NewNotificationRepository(fx.pdb)
	recipients := func(findingID shared.ID) []shared.ID {
		t.Helper()
		n := notification.NewNotification(notification.NotificationParams{TenantID: tenant, Audience: notification.AudienceAll,
			NotificationType: notification.TypeSystemAlert, Title: "t", Body: "b", Severity: notification.SeverityHigh,
			ResourceType: "finding", ResourceID: &findingID})
		ids, err := notifs.ListRecipients(ctx, n)
		if err != nil {
			t.Fatal(err)
		}
		return ids
	}
	got := recipients(fx.hiddenFinding)
	if slices.Contains(got, fx.admin) || !slices.Contains(got, fx.member) || !slices.Contains(got, fx.owner) {
		t.Fatalf("hidden finding recipients = %v (admin %s member %s owner %s)", got, fx.admin, fx.member, fx.owner)
	}
	if got := recipients(fx.ownFinding); !slices.Contains(got, fx.admin) {
		t.Fatalf("own finding recipients = %v, want the admin", got)
	}

	// Another tenant: its asset of the same name carries no program tags
	// and is never matched through this tenant.
	page, err := assets.List(ctx, asset.NewFilter().WithTenantID(fx.other.String()).WithTags(programTag), asset.NewListOptions(), pagination.New(1, 10))
	if err != nil || len(page.Data) != 0 {
		t.Fatalf("other tenant tag match = %d %v", len(page.Data), err)
	}
}
