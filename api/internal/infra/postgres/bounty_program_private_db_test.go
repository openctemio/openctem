package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	"github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// Private programs (migration 001700): visibility and terms text round
// trip, a program without a link, per-person attestations scoped to the
// tenant, and the scope list leaving out hidden programs' entries.
// Requires DATABASE_URL.
func TestBountyProgramRepository_Private(t *testing.T) {
	db, pdb := openBatchDedupDB(t)
	ctx := context.Background()
	tenant := seedBatchTenant(t, db)
	other := seedBatchTenant(t, db)
	importer := seedGroupsUser(ctx, t, db, "pp.example")
	member := seedGroupsUser(ctx, t, db, "pp.example")
	repo := NewBountyProgramRepository(pdb)
	targets := NewScopeTargetRepository(pdb)

	items, err := bountyprogram.ParseScopeFile(bountyprogram.ScopeFile{Format: bountyprogram.FileFormatText, Content: "*.private.example\n"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	terms := bountyprogram.NewTerms("", bountyprogram.Rules{}, items).WithText("NDA").SHA256()
	p := &bountyprogram.Program{
		ID: shared.NewID(), TenantID: tenant, Name: "Private " + tenant.String()[:8], Visibility: bountyprogram.VisibilityPrivate,
		TermsText: "NDA", Status: bountyprogram.StatusActive, ScopeSource: bountyprogram.ScopeSourceFileImport,
		ScopeItems: items, TermsSHA256: terms, AcceptedBy: &importer, AcceptedAt: &now, CreatedBy: &importer,
		CreatedAt: now, UpdatedAt: now,
	}
	e, err := scope.NewEntry(tenant, scope.TargetTypeDomain, "*.private.example", "", importer.String(), scope.EntryOptions{MaxTier: scope.TierActive})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.SetAuthorization(scope.AuthProgram, &p.ID); err != nil {
		t.Fatal(err)
	}
	own, err := scope.NewEntry(tenant, scope.TargetTypeDomain, "own.private.example", "", importer.String(), scope.EntryOptions{MaxTier: scope.TierActive})
	if err != nil {
		t.Fatal(err)
	}
	if err := targets.Create(ctx, own); err != nil {
		t.Fatal(err)
	}
	group := bountyprogram.NewGroup{ID: shared.NewID(), Name: "Program: private", Slug: "program-" + p.ID.String()[:8], Member: &importer}
	if err := repo.Import(ctx, bountyprogram.ImportWrite{Program: p, Group: group, Entries: []*scope.Target{e}}); err != nil {
		t.Fatalf("import: %v", err)
	}
	got, err := repo.GetByID(ctx, tenant, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Visibility != bountyprogram.VisibilityPrivate || got.TermsText != "NDA" || got.ProgramURL != "" || got.ScopeSource != bountyprogram.ScopeSourceFileImport {
		t.Fatalf("round trip: %+v", got)
	}
	ids, err := repo.PrivateProgramIDs(ctx, tenant)
	if err != nil || len(ids) != 1 || !ids[0].Equals(p.ID) {
		t.Fatalf("private ids = %v, %v", ids, err)
	}
	if ids, _ := repo.PrivateProgramIDs(ctx, other); len(ids) != 0 {
		t.Fatalf("other tenant private ids = %v", ids)
	}

	// Attestations: per person, tenant-scoped; another tenant cannot write
	// one for this program.
	if err := repo.Attest(ctx, bountyprogram.Attestation{TenantID: tenant, ProgramID: p.ID, UserID: member, TermsSHA256: terms, AcceptedAt: now}); err != nil {
		t.Fatalf("attest: %v", err)
	}
	if err := repo.Attest(ctx, bountyprogram.Attestation{TenantID: other, ProgramID: p.ID, UserID: member, TermsSHA256: terms, AcceptedAt: now}); !errors.Is(err, bountyprogram.ErrNotFound) {
		t.Fatalf("cross-tenant attest: %v", err)
	}
	att, err := repo.Attestations(ctx, tenant, member)
	if err != nil || att[p.ID] != terms {
		t.Fatalf("attestations = %v, %v", att, err)
	}
	if att, _ := repo.Attestations(ctx, other, member); len(att) != 0 {
		t.Fatalf("other tenant attestations = %v", att)
	}
	if att, _ := repo.Attestations(ctx, tenant, importer); len(att) != 0 {
		t.Fatalf("importer has no row until the service records one: %v", att)
	}

	// The scope list leaves out the entries of hidden programs.
	tid := tenant.String()
	list := func(exclude []string) map[string]bool {
		res, err := targets.List(ctx, scope.TargetFilter{TenantID: &tid, ExcludeProgramIDs: exclude}, pagination.New(1, 100))
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]bool{}
		for _, x := range res.Data {
			out[x.Pattern()] = true
		}
		return out
	}
	if all := list(nil); !all["*.private.example"] || !all["own.private.example"] {
		t.Fatalf("unfiltered list = %v", all)
	}
	if filtered := list([]string{p.ID.String()}); filtered["*.private.example"] || !filtered["own.private.example"] {
		t.Fatalf("filtered list = %v", filtered)
	}
}
