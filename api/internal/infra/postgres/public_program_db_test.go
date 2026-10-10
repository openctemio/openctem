package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The public program catalog (migration 001710): snapshot apply with change
// kinds, refusal of an older sequence, subscriptions unique per tenant, and
// stale subscriptions across tenants. Requires DATABASE_URL.
func TestPublicProgramRepository(t *testing.T) {
	db, pdb := openBatchDedupDB(t)
	ctx := context.Background()
	if _, err := db.Exec(`DELETE FROM program_feed_state; UPDATE bounty_programs SET public_program_id = NULL; DELETE FROM public_programs`); err != nil {
		t.Fatal(err)
	}
	cat := NewPublicProgramRepository(pdb)
	programs := NewBountyProgramRepository(pdb)
	now := time.Now().UTC().Truncate(time.Second)

	mk := func(handle string, open bool, inScope ...string) bountyprogram.PublicProgram {
		items := make([]bountyprogram.Item, 0, len(inScope))
		for _, s := range inScope {
			it := bountyprogram.Classify(s)
			it.InScope = true
			items = append(items, it)
		}
		p := bountyprogram.PublicProgram{FeedID: "acme-bounty:" + handle, Platform: "acme-bounty", Handle: handle,
			Name: "P " + handle, URL: "https://acme-bounty.example/" + handle, Open: open, Items: items,
			Source: "fixture", AsOf: now}
		if err := p.Validate(); err != nil {
			t.Fatal(err)
		}
		return p
	}
	kinds := func(cs []bountyprogram.CatalogChange) map[string]string {
		out := map[string]string{}
		for _, c := range cs {
			out[c.FeedID] = c.Kind
		}
		return out
	}

	ch, err := cat.ApplySnapshot(ctx, bountyprogram.FeedState{AppliedSequence: 1, KeySetVersion: 1},
		[]bountyprogram.PublicProgram{mk("a", true, "*.a.example"), mk("b", true, "b.example")})
	if err != nil {
		t.Fatal(err)
	}
	if k := kinds(ch); k["acme-bounty:a"] != "added" || k["acme-bounty:b"] != "added" {
		t.Fatalf("first apply: %v", k)
	}
	// An older or equal sequence is refused.
	if _, err := cat.ApplySnapshot(ctx, bountyprogram.FeedState{AppliedSequence: 1, KeySetVersion: 1}, nil); err == nil {
		t.Fatal("same sequence applied twice")
	}
	list, total, err := cat.ListPublic(ctx, "", 10, 0)
	if err != nil || total != 2 || len(list) != 2 {
		t.Fatalf("list = %d/%d %v", len(list), total, err)
	}
	a := list[0]

	// Two tenants follow program a; a second subscription of one tenant is
	// refused.
	sub := func(tenant shared.ID, name string) *bountyprogram.Program {
		user := seedGroupsUser(ctx, t, db, "pf.example")
		pid := a.ID
		p := &bountyprogram.Program{ID: shared.NewID(), TenantID: tenant, Name: name, Platform: "acme-bounty",
			ProgramURL: a.URL, Visibility: bountyprogram.VisibilityPublic, Status: bountyprogram.StatusPendingAttestation,
			ScopeSource: bountyprogram.ScopeSourcePublicFeed, ScopeItems: a.Items, TermsSHA256: a.TermsSHA256,
			PublicProgramID: &pid, CreatedBy: &user, CreatedAt: now, UpdatedAt: now}
		err := programs.Import(ctx, bountyprogram.ImportWrite{Program: p, Group: bountyprogram.NewGroup{
			ID: shared.NewID(), Name: "Program: " + name, Slug: "program-" + strings.ReplaceAll(p.ID.String(), "-", "")[:16], Member: &user}})
		if err != nil {
			t.Fatalf("subscribe %s: %v", name, err)
		}
		return p
	}
	t1, t2 := seedBatchTenant(t, db), seedBatchTenant(t, db)
	p1 := sub(t1, "Followed A")
	sub(t2, "Followed A")
	dup := *p1
	dup.ID, dup.Name = shared.NewID(), "Followed A again"
	err = programs.Import(ctx, bountyprogram.ImportWrite{Program: &dup, Group: bountyprogram.NewGroup{
		ID: shared.NewID(), Name: "Program: dup", Slug: "program-" + strings.ReplaceAll(dup.ID.String(), "-", "")[:16]}})
	if !errors.Is(err, bountyprogram.ErrAlreadySubscribed) {
		t.Fatalf("second subscription: %v", err)
	}
	got, err := programs.GetByID(ctx, t1, p1.ID)
	if err != nil || got.PublicProgramID == nil || !got.PublicProgramID.Equals(a.ID) || got.Status != bountyprogram.StatusPendingAttestation {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	if stale, _ := cat.StaleSubscriptions(ctx, 100); len(stale) != 0 {
		t.Fatalf("stale before a change: %v", stale)
	}

	// Program a changes scope, b disappears: changed / removed; both
	// subscriptions of a are stale.
	ch, err = cat.ApplySnapshot(ctx, bountyprogram.FeedState{AppliedSequence: 2, KeySetVersion: 1},
		[]bountyprogram.PublicProgram{mk("a", true, "*.a.example", "new.a2.example")})
	if err != nil {
		t.Fatal(err)
	}
	if k := kinds(ch); k["acme-bounty:a"] != "changed" || k["acme-bounty:b"] != "removed" {
		t.Fatalf("second apply: %v", k)
	}
	stale, err := cat.StaleSubscriptions(ctx, 100)
	if err != nil || len(stale) != 2 {
		t.Fatalf("stale = %v %v", stale, err)
	}
	if _, total, _ := cat.ListPublic(ctx, "", 10, 0); total != 1 {
		t.Fatalf("removed program still listed: %d", total)
	}
	st, err := cat.FeedState(ctx)
	if err != nil || st.AppliedSequence != 2 || st.KeySetVersion != 1 {
		t.Fatalf("state = %+v %v", st, err)
	}
}
