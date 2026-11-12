package routes

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// GetFindingWithScope is the by-id read behind the MCP finding tools, which
// have no route guard in front. It must make the same decision as the guard
// (datascope.Enforcer): a caller with a full-data role who is not a member of
// a private bug-bounty program does not read that program's findings, and an
// MCP token (not an API key) is no exception.
func TestGetFindingWithScope_FollowsTheEnforcerOnPrivateProgramAssets(t *testing.T) {
	h := newDSHarness(t)
	db := &postgres.DB{DB: h.db}
	prog := shared.NewID()
	h.exec(`INSERT INTO bounty_programs (id, tenant_id, name, terms_sha256, visibility) VALUES ($1, $2, 'scope-p', repeat('a', 64), 'private')`,
		prog.String(), h.tenant.String())
	hiddenAsset := shared.NewID()
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, program_only) VALUES ($1, $2, 'scope-p.example.com', 'domain', TRUE)`,
		hiddenAsset.String(), h.tenant.String())
	h.exec(`INSERT INTO asset_program_links (tenant_id, asset_id, program_id, source) VALUES ($1, $2, $3, 'program_manual')`,
		h.tenant.String(), hiddenAsset.String(), prog.String())
	hidden := shared.NewID()
	h.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
		VALUES ($1::uuid, $2, $3, 'sast', 't', 'private program finding', 'high', $1::text, 'new')`,
		hidden.String(), h.tenant.String(), hiddenAsset.String())
	open := shared.NewID()
	h.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
		VALUES ($1::uuid, $2, $3, 'sast', 't', 'ordinary finding', 'high', $1::text, 'new')`,
		open.String(), h.tenant.String(), h.assetA.String())

	svc := finding.NewVulnerabilityService(postgres.NewVulnerabilityRepository(db), postgres.NewFindingRepository(db), logger.NewNop())
	svc.SetAccessControlRepository(postgres.NewAccessControlRepository(db))
	svc.SetDataScope(h.enforcer)

	ctxFor := func(user shared.ID, provider string) context.Context {
		ctx := context.WithValue(context.Background(), middleware.UserIDKey, user.String())
		ctx = context.WithValue(ctx, middleware.TenantIDKey, h.tenant.String())
		ctx = context.WithValue(ctx, middleware.IsAdminKey, false)
		return context.WithValue(ctx, middleware.AuthProviderKey, provider)
	}
	read := func(ctx context.Context, user shared.ID, id shared.ID) error {
		_, err := svc.GetFindingWithScope(ctx, h.tenant.String(), id.String(), user.String(), false)
		return err
	}

	// The fixture: the route guard hides the program's finding from the
	// full-data member.
	if err := h.enforcer.AssertFinding(ctxFor(h.memberFull, middleware.AuthProviderMCPOAuth), h.tenant, hidden); err == nil {
		t.Fatal("fixture: the private program asset is not hidden from the full-data member")
	}

	for _, provider := range []string{middleware.AuthProviderMCPOAuth, "jwt"} {
		ctx := ctxFor(h.memberFull, provider)
		if err := read(ctx, h.memberFull, hidden); !errors.Is(err, shared.ErrNotFound) {
			t.Errorf("%s: full-data member read a private program finding: %v", provider, err)
		}
		if err := read(ctx, h.memberFull, open); err != nil {
			t.Errorf("%s: full-data member cannot read an ordinary finding: %v", provider, err)
		}
	}

	// A restricted member is held to the scope rows, even for a hidden asset
	// their scope row names.
	h.exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')
		ON CONFLICT DO NOTHING`, h.memberA.String(), h.tenant.String(), hiddenAsset.String())
	ctx := ctxFor(h.memberA, middleware.AuthProviderMCPOAuth)
	if err := read(ctx, h.memberA, hidden); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("restricted member read a private program finding through a scope row: %v", err)
	}
	if err := read(ctx, h.memberA, open); err != nil {
		t.Errorf("restricted member cannot read an in-scope finding: %v", err)
	}
	if err := read(ctxFor(h.memberFree, middleware.AuthProviderMCPOAuth), h.memberFree, open); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("a member without a scope row read a finding: %v", err)
	}
}
