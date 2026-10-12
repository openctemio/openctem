package postgres

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	"github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// Program assets (migration 001792): links and system tags derived from a
// program's scope, program-only only for assets that came after the program
// and that no own entry covers, the inventory filter, the default exclusion
// from dashboard numbers, system tags out of reach of asset updates, and
// tenant isolation. Requires DATABASE_URL.
func TestProgramAssetLinks(t *testing.T) {
	db, pdb := openBatchDedupDB(t)
	ctx := context.Background()
	tenant, other := seedBatchTenant(t, db), seedBatchTenant(t, db)
	user := seedGroupsUser(ctx, t, db, "pa.example")
	programs := NewBountyProgramRepository(pdb)
	targets := NewScopeTargetRepository(pdb)
	assets := NewAssetRepository(pdb)

	addAsset := func(tid shared.ID, name string, created time.Time) shared.ID {
		id := shared.NewID()
		if _, err := db.Exec(`INSERT INTO assets (id, tenant_id, name, asset_type, created_at) VALUES ($1, $2, $3, 'domain', $4)`,
			id.String(), tid.String(), name, created); err != nil {
			t.Fatal(err)
		}
		return id
	}
	before := time.Now().Add(-time.Hour)
	ownOld := addAsset(tenant, "shop.pa-prog.example", before) // the organization had it before the program
	// An own entry covers api.pa-prog.example.
	own, err := scope.NewEntry(tenant, scope.TargetTypeDomain, "api.pa-prog.example", "", user.String(), scope.EntryOptions{MaxTier: scope.TierActive})
	if err != nil {
		t.Fatal(err)
	}
	if err := targets.Create(ctx, own); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	p := &bountyprogram.Program{ID: shared.NewID(), TenantID: tenant, Name: "PA " + tenant.String()[:8], Platform: "Acme Bounty",
		Handle: "pa", Visibility: bountyprogram.VisibilityPrivate, Status: bountyprogram.StatusPendingAttestation,
		ScopeSource: bountyprogram.ScopeSourcePublicFeed, TermsSHA256: strings.Repeat("ab", 32), CreatedBy: &user,
		CreatedAt: now, UpdatedAt: now}
	e, _ := scope.NewEntry(tenant, scope.TargetTypeDomain, "*.pa-prog.example", "", user.String(), scope.EntryOptions{MaxTier: scope.TierActive})
	_ = e.SetAuthorization(scope.AuthProgram, &p.ID)
	e.Deactivate() // a followed program not accepted yet
	if err := programs.Import(ctx, bountyprogram.ImportWrite{Program: p, Entries: []*scope.Target{e}, Group: bountyprogram.NewGroup{
		ID: shared.NewID(), Name: "Program: pa", Slug: "program-" + strings.ReplaceAll(p.ID.String(), "-", "")[:16], Member: &user}}); err != nil {
		t.Fatal(err)
	}
	newProg := addAsset(tenant, "new.pa-prog.example", now.Add(time.Minute))
	ownCovered := addAsset(tenant, "api.pa-prog.example", now.Add(time.Minute))
	otherTenant := addAsset(other, "x.pa-prog.example", now.Add(time.Minute))

	if _, _, err := programs.AssignProgramAssets(ctx, tenant, p.ID); err != nil {
		t.Fatalf("assign: %v", err)
	}
	flagReader := NewProgramAssetFlagRepository(pdb)
	flags, err := flagReader.ProgramAssetFlags(ctx, tenant.String(), []string{ownOld.String(), newProg.String(), ownCovered.String(), otherTenant.String()})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"bug-bounty", "platform:acme-bounty", "program-unattested", "program:acme-bounty:pa", "source:programfeed"}
	for _, id := range []shared.ID{ownOld, newProg, ownCovered} {
		if got := flags[id.String()].SystemTags; strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("system tags of %s = %v", id, got)
		}
	}
	if !flags[newProg.String()].ProgramOnly || flags[ownOld.String()].ProgramOnly || flags[ownCovered.String()].ProgramOnly {
		t.Fatalf("program_only: new %v, old %v, own-covered %v", flags[newProg.String()].ProgramOnly,
			flags[ownOld.String()].ProgramOnly, flags[ownCovered.String()].ProgramOnly)
	}
	if _, ok := flags[otherTenant.String()]; ok {
		t.Fatal("another tenant's asset read")
	}

	// The inventory filter.
	tid := tenant.String()
	list := func(mode string) int {
		res, err := assets.List(ctx, asset.Filter{TenantID: &tid, ProgramAssets: mode}, asset.ListOptions{}, pagination.New(1, 100))
		if err != nil {
			t.Fatal(err)
		}
		return int(res.Total)
	}
	if n := list("only"); n != 3 {
		t.Fatalf("only = %d", n)
	}
	if all, excl := list(""), list("exclude"); all-excl != 1 {
		t.Fatalf("exclude left out %d", all-excl)
	}

	// Dashboard numbers leave the program-only asset out unless asked.
	dash := NewDashboardRepository(db)
	def, err := dash.GetAllStats(ctx, tenant, nil)
	if err != nil {
		t.Fatal(err)
	}
	inc, err := dash.GetAllStats(shared.WithProgramAssets(ctx), tenant, nil)
	if err != nil {
		t.Fatal(err)
	}
	if inc.Assets.Total-def.Assets.Total != 1 {
		t.Fatalf("assets total default %d, with program assets %d", def.Assets.Total, inc.Assets.Total)
	}

	// People cannot change system tags: an asset update writes tags only.
	a, err := assets.GetByID(ctx, tenant, ownOld)
	if err != nil {
		t.Fatal(err)
	}
	a.AddTag("custom")
	if err := assets.Update(ctx, a); err != nil {
		t.Fatal(err)
	}
	var sys []string
	if err := db.QueryRow(`SELECT system_tags FROM assets WHERE id = $1`, ownOld.String()).Scan(pq.Array(&sys)); err != nil {
		t.Fatal(err)
	}
	if strings.Join(sys, ",") != strings.Join(want, ",") {
		t.Fatalf("system tags after an update = %v", sys)
	}

	// Ending the program removes its links and tags.
	p.Status = bountyprogram.StatusEnded
	if err := programs.SetStatus(ctx, p, scope.StatusInactive); err != nil {
		t.Fatal(err)
	}
	if _, _, err := programs.AssignProgramAssets(ctx, tenant, p.ID); err != nil {
		t.Fatal(err)
	}
	if flags, _ = flagReader.ProgramAssetFlags(ctx, tenant.String(), []string{newProg.String()}); len(flags) != 0 {
		t.Fatalf("flags after the program ended = %v", flags)
	}
}
