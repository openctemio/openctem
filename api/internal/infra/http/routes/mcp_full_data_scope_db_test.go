package routes

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/asset"
	"github.com/openctemio/openctem/api/internal/app/datascope"
	mcpoauthapp "github.com/openctemio/openctem/api/internal/app/mcpoauth"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// An MCP connection reads all organization data only when its principal is
// full-data (grant.full_data and a full-data role right now, decided by the
// authorization server on every request) AND the enforcer still finds the
// full-data role. The caller is built as production builds it
// (middleware.ReadsOnOwnScope). Private program assets stay hidden, as for
// the same person in the web console.
func TestMCPFullDataGrantReadsEveryAssetNarrowedOtherwise(t *testing.T) {
	h := newDSHarness(t)
	db := &postgres.DB{DB: h.db}

	// A private program asset the full-data member is not a member of.
	prog := shared.NewID()
	h.exec(`INSERT INTO bounty_programs (id, tenant_id, name, terms_sha256, visibility) VALUES ($1, $2, 'fd-p', repeat('a', 64), 'private')`,
		prog.String(), h.tenant.String())
	hiddenAsset := shared.NewID()
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, program_only) VALUES ($1, $2, 'fd-p.example.com', 'domain', TRUE)`,
		hiddenAsset.String(), h.tenant.String())
	h.exec(`INSERT INTO asset_program_links (tenant_id, asset_id, program_id, source) VALUES ($1, $2, $3, 'program_manual')`,
		h.tenant.String(), hiddenAsset.String(), prog.String())

	enforcer := datascope.New(postgres.NewDataScopeRepository(db), func(ctx context.Context) datascope.Caller {
		return datascope.Caller{
			UserID: middleware.GetUserID(ctx), IsAdmin: middleware.IsAdmin(ctx), IsOwner: middleware.IsOwner(ctx),
			APIKey: middleware.ReadsOnOwnScope(ctx),
		}
	}, logger.NewNop())
	svc := asset.NewAssetService(postgres.NewAssetRepository(db), logger.NewNop())
	svc.SetAccessControlRepository(postgres.NewAccessControlRepository(db))
	svc.SetDataScope(enforcer)

	mcpCtx := func(user shared.ID, p *mcpoauthapp.Principal) context.Context {
		ctx := context.WithValue(context.Background(), middleware.UserIDKey, user.String())
		ctx = context.WithValue(ctx, middleware.TenantIDKey, h.tenant.String())
		ctx = context.WithValue(ctx, middleware.IsAdminKey, false)
		ctx = context.WithValue(ctx, middleware.AuthProviderKey, middleware.AuthProviderMCPOAuth)
		if p != nil {
			ctx = context.WithValue(ctx, middleware.MCPPrincipalKey, p)
		}
		return ctx
	}
	names := func(ctx context.Context, user shared.ID) map[string]bool {
		t.Helper()
		res, err := svc.ListAssets(ctx, asset.ListAssetsInput{TenantID: h.tenant.String(), ActingUserID: user.String(), Page: 1, PerPage: 100})
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]bool{}
		for _, a := range res.Data {
			out[a.Name()] = true
		}
		return out
	}

	// A scoped connection of the full-data role holder reads nothing: no
	// scope row (the delegated rule, unchanged).
	if got := names(mcpCtx(h.memberFull, &mcpoauthapp.Principal{}), h.memberFull); len(got) != 0 {
		t.Fatalf("a scoped MCP connection read %v", got)
	}
	// With the grant's full data flag it reads every ordinary asset, not the
	// private program's.
	got := names(mcpCtx(h.memberFull, &mcpoauthapp.Principal{FullData: true}), h.memberFull)
	if !got[dsMarkerAssetA] || !got[dsMarkerAssetB] || got["fd-p.example.com"] {
		t.Fatalf("a full-data MCP connection read %v", got)
	}
	// The role is removed: the authorization server stops setting FullData
	// on the next request, and even a stale flag finds no role in the
	// enforcer.
	h.exec(`DELETE FROM user_roles WHERE user_id = $1 AND tenant_id = $2`, h.memberFull.String(), h.tenant.String())
	if got := names(mcpCtx(h.memberFull, &mcpoauthapp.Principal{FullData: true}), h.memberFull); len(got) != 0 {
		t.Fatalf("a full-data flag outlived the role: %v", got)
	}
	// A member who never held the role cannot gain it from the flag.
	if got := names(mcpCtx(h.memberFree, &mcpoauthapp.Principal{FullData: true}), h.memberFree); len(got) != 0 {
		t.Fatalf("a forged full-data flag read %v", got)
	}
	// Another organization's data is out of reach whatever the flag says.
	other := shared.NewID()
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'fd-other', $2)`, other.String(), "fdother-"+other.String()[:8])
	t.Cleanup(func() { _, _ = h.db.Exec(`DELETE FROM tenants WHERE id = $1`, other.String()) })
	res, err := svc.ListAssets(mcpCtx(h.memberFull, &mcpoauthapp.Principal{FullData: true}),
		asset.ListAssetsInput{TenantID: other.String(), ActingUserID: h.memberFull.String(), Page: 1, PerPage: 10})
	if err == nil && len(res.Data) != 0 {
		t.Fatalf("read another organization's assets: %v", res)
	}
}
