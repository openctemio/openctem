package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	"github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Programs (migration 001454): import in one transaction, membership-filtered
// lists, re-import, status changes reaching the entries, the authorization
// source round trip, and tenant isolation. Requires DATABASE_URL.
func TestBountyProgramRepository(t *testing.T) {
	db, pdb := openBatchDedupDB(t)
	ctx := context.Background()
	tenant := seedBatchTenant(t, db)
	other := seedBatchTenant(t, db)
	importer := seedGroupsUser(ctx, t, db, "bb.example")
	outsider := seedGroupsUser(ctx, t, db, "bb.example")
	repo := NewBountyProgramRepository(pdb)
	targets := NewScopeTargetRepository(pdb)

	items, err := bountyprogram.ParseScope("*.acme.example\n-admin.acme.example\n")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	p := &bountyprogram.Program{
		ID: shared.NewID(), TenantID: tenant, Name: "Acme", Platform: "self", Handle: "jdoe",
		ProgramURL: "https://acme.example/security", Status: bountyprogram.StatusActive,
		ScopeSource: bountyprogram.ScopeSourcePaste, Rules: bountyprogram.Rules{RateLimitRPS: 5},
		ScopeItems: items, TermsSHA256: bountyprogram.NewTerms("https://acme.example/security", bountyprogram.Rules{RateLimitRPS: 5}, items).SHA256(),
		AcceptedBy: &importer, AcceptedAt: &now, CreatedBy: &importer, CreatedAt: now, UpdatedAt: now,
	}
	entry := func(pattern string) *scope.Target {
		e, err := scope.NewEntry(tenant, scope.TargetTypeDomain, pattern, "", importer.String(), scope.EntryOptions{MaxTier: scope.TierActive})
		if err != nil {
			t.Fatal(err)
		}
		if err := e.SetAuthorization(scope.AuthProgram, &p.ID); err != nil {
			t.Fatal(err)
		}
		return e
	}
	e1 := entry("*.acme.example")
	group := bountyprogram.NewGroup{ID: shared.NewID(), Name: "Program: Acme", Slug: "program-" + p.ID.String()[:8], Member: &importer}
	err = repo.Import(ctx, bountyprogram.ImportWrite{
		Program: p, Group: group, Entries: []*scope.Target{e1},
		Exclusions: []bountyprogram.Exclusion{{ID: shared.NewID(), TenantID: tenant, ProgramID: p.ID,
			TargetType: scope.TargetTypeDomain, Pattern: "admin.acme.example", Reason: bountyprogram.ReasonOutOfScope, CreatedAt: now}},
	})
	if err != nil {
		t.Fatalf("import: %v", err)
	}

	got, err := repo.GetByID(ctx, tenant, p.ID)
	if err != nil || got.GroupID == nil || !got.GroupID.Equals(group.ID) || got.Rules.RateLimitRPS != 5 || len(got.ScopeItems) != 2 {
		t.Fatalf("get: %+v %v", got, err)
	}
	if _, err := repo.GetByID(ctx, other, p.ID); !errors.Is(err, bountyprogram.ErrNotFound) {
		t.Fatalf("another tenant must not read the program: %v", err)
	}

	// The entry keeps its source and program.
	stored, err := targets.GetByID(ctx, tenant, e1.ID())
	if err != nil || !stored.IsProgramEntry() || !stored.ProgramID().Equals(p.ID) || stored.Origin() != scope.OriginProgram {
		t.Fatalf("stored entry: %+v %v", stored, err)
	}

	// Membership.
	if ok, _ := repo.IsMember(ctx, tenant, p.ID, importer); !ok {
		t.Fatal("the importer is a member")
	}
	if ok, _ := repo.IsMember(ctx, tenant, p.ID, outsider); ok {
		t.Fatal("an outsider is not a member")
	}
	if ok, _ := repo.IsMember(ctx, other, p.ID, importer); ok {
		t.Fatal("membership is tenant-scoped")
	}
	if l, _ := repo.List(ctx, tenant, &outsider); len(l) != 0 {
		t.Fatalf("an outsider lists nothing: %d", len(l))
	}
	if l, _ := repo.List(ctx, tenant, &importer); len(l) != 1 {
		t.Fatalf("a member lists the program: %d", len(l))
	}
	if l, _ := repo.List(ctx, other, nil); len(l) != 0 {
		t.Fatalf("another tenant lists nothing: %d", len(l))
	}
	if ids, _ := repo.MemberProgramIDs(ctx, tenant, importer); len(ids) != 1 {
		t.Fatalf("member programs: %v", ids)
	}

	// Duplicate name refused.
	dup := *p
	dup.ID = shared.NewID()
	dup.Name = "ACME"
	if err := repo.Import(ctx, bountyprogram.ImportWrite{Program: &dup,
		Group: bountyprogram.NewGroup{ID: shared.NewID(), Name: "Program: ACME", Slug: "program-" + dup.ID.String()[:8]}}); !errors.Is(err, bountyprogram.ErrNameTaken) {
		t.Fatalf("a duplicate name must be refused: %v", err)
	}

	// Pause: entries inactive; resume: active again.
	p.Status = bountyprogram.StatusPaused
	if err := repo.SetStatus(ctx, p, scope.StatusInactive); err != nil {
		t.Fatal(err)
	}
	if s, _ := targets.GetByID(ctx, tenant, e1.ID()); s.Status() != scope.StatusInactive {
		t.Fatalf("paused entry: %v", s.Status())
	}
	p.Status = bountyprogram.StatusActive
	if err := repo.SetStatus(ctx, p, scope.StatusActive); err != nil {
		t.Fatal(err)
	}
	if s, _ := targets.GetByID(ctx, tenant, e1.ID()); !s.IsActive() {
		t.Fatalf("resumed entry: %v", s.Status())
	}

	// Re-import: drop *.acme.example, add api.acme.example, new exclusions.
	e2 := entry("api.acme.example")
	if err := repo.ReplaceScope(ctx, bountyprogram.ScopeWrite{Program: p, CreateEntries: []*scope.Target{e2},
		DeleteEntryIDs: []shared.ID{e1.ID()}}); err != nil {
		t.Fatal(err)
	}
	es, _ := repo.Entries(ctx, tenant, p.ID)
	if len(es) != 1 || es[0].Pattern() != "api.acme.example" {
		t.Fatalf("entries after re-import: %d", len(es))
	}
	if ex, _ := repo.Exclusions(ctx, tenant, &p.ID); len(ex) != 0 {
		t.Fatalf("exclusions are replaced as a whole: %d", len(ex))
	}
	// Another tenant's re-import cannot touch this program's entries.
	foreign := *p
	foreign.TenantID = other
	if err := repo.ReplaceScope(ctx, bountyprogram.ScopeWrite{Program: &foreign, DeleteEntryIDs: []shared.ID{e2.ID()}}); !errors.Is(err, bountyprogram.ErrNotFound) {
		t.Fatalf("a foreign re-import must find nothing: %v", err)
	}
	if es, _ := repo.Entries(ctx, tenant, p.ID); len(es) != 1 {
		t.Fatal("a foreign re-import must not delete entries")
	}
	// An ownership entry still round-trips as ownership.
	own, _ := scope.NewEntry(tenant, scope.TargetTypeDomain, "own.example", "", importer.String(), scope.EntryOptions{MaxTier: scope.TierActive})
	if err := targets.Create(ctx, own); err != nil {
		t.Fatal(err)
	}
	if s, _ := targets.GetByID(ctx, tenant, own.ID()); s.AuthorizationSource() != scope.AuthOwnership || s.ProgramID() != nil {
		t.Fatalf("ownership entry: %v", s.AuthorizationSource())
	}
}

// Program sync columns (migration 001491): source settings, sync state and
// pending terms round-trip; due programs are listed across tenants; another
// tenant cannot write them.
func TestBountyProgramSync(t *testing.T) {
	db, pdb := openBatchDedupDB(t)
	ctx := context.Background()
	tenant := seedBatchTenant(t, db)
	other := seedBatchTenant(t, db)
	repo := NewBountyProgramRepository(pdb)
	items, _ := bountyprogram.ParseScope("*.sync.example\n")
	now := time.Now().UTC().Truncate(time.Microsecond)
	p := &bountyprogram.Program{ID: shared.NewID(), TenantID: tenant, Name: "Sync", ProgramURL: "https://sync.example/policy",
		Status: bountyprogram.StatusActive, ScopeSource: bountyprogram.ScopeSourcePaste, ScopeItems: items,
		TermsSHA256: strings.Repeat("a", 64), CreatedAt: now, UpdatedAt: now}
	if err := repo.Import(ctx, bountyprogram.ImportWrite{Program: p,
		Group: bountyprogram.NewGroup{ID: shared.NewID(), Name: "Program: Sync", Slug: "program-" + p.ID.String()[:13]}}); err != nil {
		t.Fatal(err)
	}
	p.ScopeSource = bountyprogram.ScopeSourceAPI
	p.Sync = bountyprogram.Sync{Handle: "sync", Username: "jdoe", TokenEncrypted: "ciphertext", LastSyncedAt: &now, LastError: ""}
	p.Pending = &bountyprogram.PendingTerms{TermsSHA256: strings.Repeat("b", 64), Items: items}
	if err := repo.SaveSync(ctx, p); err != nil {
		t.Fatal(err)
	}
	got, err := repo.GetByID(ctx, tenant, p.ID)
	if err != nil || got.ScopeSource != bountyprogram.ScopeSourceAPI || got.Sync.Handle != "sync" || got.Sync.TokenEncrypted != "ciphertext" ||
		got.Pending == nil || got.Pending.TermsSHA256 != strings.Repeat("b", 64) || len(got.Pending.Items) != 1 {
		t.Fatalf("round trip: %+v %+v %v", got.Sync, got.Pending, err)
	}
	due, err := repo.SyncDue(ctx, now.Add(time.Hour), 100)
	found := false
	for _, r := range due {
		found = found || r.ProgramID.Equals(p.ID)
	}
	if err != nil || !found {
		t.Fatalf("due: %v %v", due, err)
	}
	if due, _ := repo.SyncDue(ctx, now.Add(-time.Hour), 100); len(due) != 0 {
		for _, r := range due {
			if r.ProgramID.Equals(p.ID) {
				t.Fatal("a program synced after the cut-off is not due")
			}
		}
	}
	foreign := *p
	foreign.TenantID = other
	if err := repo.SaveSync(ctx, &foreign); !errors.Is(err, bountyprogram.ErrNotFound) {
		t.Fatalf("another tenant must not write the sync settings: %v", err)
	}
	// Accepting clears the pending terms (updateProgram writes them).
	got.Pending = nil
	if err := repo.SetStatus(ctx, got, scope.StatusActive); err != nil {
		t.Fatal(err)
	}
	if again, _ := repo.GetByID(ctx, tenant, p.ID); again.Pending != nil {
		t.Fatal("pending terms must be cleared")
	}
}
