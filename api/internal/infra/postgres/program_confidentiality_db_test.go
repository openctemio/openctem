package postgres

// Private program assets (RFC-065 §15.3) against a migrated database: a
// program-only asset of a private program, and its findings, are seen only
// by the program's members and the organization's owners. A non-member
// administrator gets 404 by id, and they are left out of the asset and
// finding lists and counts; a shared asset stays visible without the
// program's tag; another tenant is never affected. Requires DATABASE_URL.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	"github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

func TestPrivateProgramAssetsHiddenFromNonMembers(t *testing.T) {
	db, pdb := openBatchDedupDB(t)
	ctx := context.Background()
	tenant, other := seedBatchTenant(t, db), seedBatchTenant(t, db)
	member := seedGroupsUser(ctx, t, db, "ppc.example")
	admin := seedGroupsUser(ctx, t, db, "ppc.example")
	for _, u := range []shared.ID{member, admin} {
		if _, err := db.Exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, 'member')`, u.String(), tenant.String()); err != nil {
			t.Fatal(err)
		}
	}
	programs := NewBountyProgramRepository(pdb)
	suffix := strings.ReplaceAll(tenant.String(), "-", "")[:10]

	now := time.Now().UTC()
	p := &bountyprogram.Program{ID: shared.NewID(), TenantID: tenant, Name: "Priv " + suffix, Platform: "acme",
		Handle: "priv", Visibility: bountyprogram.VisibilityPrivate, Status: bountyprogram.StatusActive,
		ScopeSource: bountyprogram.ScopeSourceFileImport, TermsSHA256: strings.Repeat("ef", 32), CreatedBy: &member,
		CreatedAt: now.Add(-time.Hour), UpdatedAt: now}
	e, _ := scope.NewEntry(tenant, scope.TargetTypeDomain, "*.p"+suffix+".example", "", member.String(), scope.EntryOptions{MaxTier: scope.TierActive})
	_ = e.SetAuthorization(scope.AuthProgram, &p.ID)
	if err := programs.Import(ctx, bountyprogram.ImportWrite{Program: p, Entries: []*scope.Target{e}, Group: bountyprogram.NewGroup{
		ID: shared.NewID(), Name: "Program: priv", Slug: "program-" + strings.ReplaceAll(p.ID.String(), "-", "")[:16], Member: &member}}); err != nil {
		t.Fatal(err)
	}
	addAsset := func(tid shared.ID, name string, created time.Time) shared.ID {
		id := shared.NewID()
		if _, err := db.Exec(`INSERT INTO assets (id, tenant_id, name, asset_type, created_at) VALUES ($1, $2, $3, 'domain', $4)`,
			id.String(), tid.String(), name, created); err != nil {
			t.Fatal(err)
		}
		return id
	}
	hidden := addAsset(tenant, "app.p"+suffix+".example", now.Add(time.Minute))    // program-only
	shared1 := addAsset(tenant, "shop.p"+suffix+".example", now.Add(-2*time.Hour)) // the organization had it first
	own := addAsset(tenant, "www.own"+suffix+".example", now)                      // not a program asset
	foreign := addAsset(other, "app.p"+suffix+".example", now.Add(time.Minute))    // another tenant
	findingOn := func(tid, assetID shared.ID) shared.ID {
		id := shared.NewID()
		if _, err := db.Exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
			VALUES ($1::uuid, $2, $3, 'sast', 'ppc', 'ppc finding', 'high', $1::text, 'new')`, id.String(), tid.String(), assetID.String()); err != nil {
			t.Fatal(err)
		}
		return id
	}
	hiddenFinding, ownFinding := findingOn(tenant, hidden), findingOn(tenant, own)
	if _, _, err := programs.AssignProgramAssets(ctx, tenant, p.ID); err != nil {
		t.Fatal(err)
	}

	var caller datascope.Caller
	enf := datascope.New(NewDataScopeRepository(pdb), func(context.Context) datascope.Caller { return caller }, nil)

	// A non-member administrator: 404 by id on the hidden asset and its
	// finding; the shared and own assets stay.
	caller = datascope.Caller{UserID: admin.String(), IsAdmin: true}
	if err := enf.AssertAsset(ctx, tenant, hidden); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("admin reads the hidden asset: %v", err)
	}
	if err := enf.AssertFinding(ctx, tenant, hiddenFinding); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("admin reads the hidden finding: %v", err)
	}
	for _, id := range []shared.ID{shared1, own} {
		if err := enf.AssertAsset(ctx, tenant, id); err != nil {
			t.Fatalf("admin cannot read %s: %v", id, err)
		}
	}
	adminScope, err := enf.Resolve(ctx, tenant)
	if err != nil || adminScope == nil || !adminScope.Unrestricted {
		t.Fatalf("admin scope = %+v %v", adminScope, err)
	}

	// Lists and counts leave it out for the administrator.
	assets := NewAssetRepository(pdb)
	list, err := assets.List(ctx, asset.NewFilter().WithTenantID(tenant.String()).WithDataScope(adminScope), asset.NewListOptions(), pagination.New(1, 200))
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, a := range list.Data {
		names[a.Name()] = true
	}
	if names["app.p"+suffix+".example"] || !names["shop.p"+suffix+".example"] || !names["www.own"+suffix+".example"] {
		t.Fatalf("admin asset list = %v", names)
	}
	findings := NewFindingRepository(pdb)
	fl, err := findings.List(ctx, vulnerability.NewFindingFilter().WithTenantID(tenant).WithDataScope(adminScope),
		vulnerability.NewFindingListOptions(), pagination.New(1, 200))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[shared.ID]bool{}
	for _, f := range fl.Data {
		seen[f.ID()] = true
	}
	if seen[hiddenFinding] || !seen[ownFinding] {
		t.Fatalf("admin finding list: hidden %v own %v", seen[hiddenFinding], seen[ownFinding])
	}
	stats, err := findings.GetStats(ctx, tenant, nil, vulnerability.FindingStatsFilter{HiddenFor: &admin})
	if err != nil || stats.Total != 1 {
		t.Fatalf("admin finding count = %+v %v, want 1", stats, err)
	}

	// The program member sees it (through the program group), the owner
	// too; neither is narrowed for it.
	caller = datascope.Caller{UserID: member.String()}
	if err := enf.AssertAsset(ctx, tenant, hidden); err != nil {
		t.Fatalf("member: %v", err)
	}
	if err := enf.AssertFinding(ctx, tenant, hiddenFinding); err != nil {
		t.Fatalf("member finding: %v", err)
	}
	caller = datascope.Caller{UserID: admin.String(), IsAdmin: true, IsOwner: true}
	if err := enf.AssertAsset(ctx, tenant, hidden); err != nil {
		t.Fatalf("owner: %v", err)
	}

	// The shared asset keeps its program tag only for whoever may see the
	// program.
	flags := NewProgramAssetFlagRepository(pdb)
	asAdmin, err := flags.ProgramAssetFlagsFor(ctx, tenant.String(), []string{shared1.String(), hidden.String()}, shared.ProgramViewer{UserID: admin})
	if err != nil {
		t.Fatal(err)
	}
	if f, ok := asAdmin[shared1.String()]; ok && len(f.SystemTags) > 0 {
		t.Fatalf("a non-member sees the private program on a shared asset: %+v", f)
	}
	asMember, err := flags.ProgramAssetFlagsFor(ctx, tenant.String(), []string{shared1.String()}, shared.ProgramViewer{UserID: member})
	if err != nil || len(asMember[shared1.String()].SystemTags) == 0 {
		t.Fatalf("member flags = %+v %v", asMember, err)
	}

	// Dashboards that include program assets still leave out the hidden one
	// for a non-member.
	dctx := shared.WithProgramViewer(shared.WithProgramAssets(ctx), shared.ProgramViewer{UserID: admin})
	var n int
	if err := db.QueryRowContext(dctx, `SELECT count(*) FROM assets WHERE tenant_id = $1`+programAssetExcl(dctx, ""), tenant.String()).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("dashboard assets with program assets included = %d, want 2", n)
	}

	// Another tenant: the ids are not visible through this tenant, and the
	// foreign asset of the same name is untouched by the program.
	vis, err := NewDataScopeRepository(pdb).AssetIDsVisible(ctx, other, admin, []shared.ID{hidden, foreign})
	if err != nil || len(vis) != 1 || vis[0] != foreign {
		t.Fatalf("other tenant visible = %v %v", vis, err)
	}
}
