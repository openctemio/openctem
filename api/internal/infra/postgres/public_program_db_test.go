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

// The public program catalog (migration 001736): snapshot apply with change
// kinds, refusal of an older sequence, subscriptions unique per tenant, and
// stale subscriptions across tenants. Requires DATABASE_URL.
func TestPublicProgramRepository(t *testing.T) {
	db, pdb := openBatchDedupDB(t)
	ctx := context.Background()
	if _, err := db.Exec(`DELETE FROM program_feed_state; DELETE FROM feed_checkpoints; UPDATE bounty_programs SET public_program_id = NULL; DELETE FROM public_programs`); err != nil {
		t.Fatal(err)
	}
	cat := NewPublicProgramRepository(pdb)
	programs := NewBountyProgramRepository(pdb)
	now := time.Now().UTC().Truncate(time.Second)

	mk := func(handle string, open bool, inScope ...string) bountyprogram.PublicProgram {
		items := make([]bountyprogram.Item, 0, len(inScope))
		for _, s := range inScope {
			it := bountyprogram.Classify(s)
			it.InScope, it.Confidence = true, bountyprogram.ConfidencePublished
			items = append(items, it)
		}
		status := bountyprogram.FeedStatusOpen
		if !open {
			status = bountyprogram.FeedStatusClosed
		}
		p := bountyprogram.PublicProgram{FeedID: "acme-bounty:" + handle, Source: "acme-bounty", Platform: "self-hosted",
			Name: "P " + handle, URL: "http://acme-bounty.example/" + handle, Type: "bounty", Status: status, Items: items,
			AsOf: now, Provenance: bountyprogram.FeedProvenance{Source: "acme-bounty", SourceURL: "https://acme-bounty.example/list.json",
				Dataset: "acme/programs", DatasetCommit: strings.Repeat("b", 40)}}
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

	ch, err := cat.Apply(ctx, bountyprogram.FeedApply{State: bountyprogram.FeedState{AppliedSequence: 1, KeySetVersion: 1},
		Snapshot: true, Programs: []bountyprogram.PublicProgram{mk("a", true, "*.a.example"), mk("b", true, "b.example"), mk("c", true, "c.example")}})
	if err != nil {
		t.Fatal(err)
	}
	if k := kinds(ch); k["acme-bounty:a"] != "added" || k["acme-bounty:b"] != "added" {
		t.Fatalf("first apply: %v", k)
	}
	// An older or equal sequence is refused.
	if _, err := cat.Apply(ctx, bountyprogram.FeedApply{State: bountyprogram.FeedState{AppliedSequence: 1, KeySetVersion: 1}, Snapshot: true}); err == nil {
		t.Fatal("same sequence applied twice")
	}
	list, total, err := cat.ListPublic(ctx, "", 10, 0)
	if err != nil || total != 3 || len(list) != 3 {
		t.Fatalf("list = %d/%d %v", len(list), total, err)
	}
	a := list[0]
	if a.Provenance.Dataset != "acme/programs" {
		t.Fatalf("provenance not kept: %+v", a.Provenance)
	}

	// Two tenants follow program a; a second subscription of one tenant is
	// refused.
	sub := func(tenant shared.ID, name string) *bountyprogram.Program {
		user := seedGroupsUser(ctx, t, db, "pf.example")
		pid := a.ID
		p := &bountyprogram.Program{ID: shared.NewID(), TenantID: tenant, Name: name, Platform: "acme-bounty",
			ProgramURL: a.ProgramURL(), Visibility: bountyprogram.VisibilityPublic, Status: bountyprogram.StatusPendingAttestation,
			ScopeSource: bountyprogram.ScopeSourcePublicFeed, ScopeItems: a.Items, TermsSHA256: a.TermsSHA256,
			PublicProgramID: &pid, PublicSyncedSHA256: a.TermsSHA256, CreatedBy: &user, CreatedAt: now, UpdatedAt: now}
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

	// A delta: program a changes scope, c is dropped (archived), b is not
	// in the delta and stays; both subscriptions of a are stale.
	ch, err = cat.Apply(ctx, bountyprogram.FeedApply{State: bountyprogram.FeedState{AppliedSequence: 2, KeySetVersion: 1},
		Programs: []bountyprogram.PublicProgram{mk("a", true, "*.a.example", "new.a2.example")}, Dropped: []string{"acme-bounty:c"}})
	if err != nil {
		t.Fatal(err)
	}
	if k := kinds(ch); k["acme-bounty:a"] != "changed" || k["acme-bounty:c"] != "removed" || k["acme-bounty:b"] != "" {
		t.Fatalf("second apply: %v", k)
	}
	stale, err := cat.StaleSubscriptions(ctx, 100)
	if err != nil || len(stale) != 2 {
		t.Fatalf("stale = %v %v", stale, err)
	}
	if _, total, _ := cat.ListPublic(ctx, "", 10, 0); total != 2 {
		t.Fatalf("listed after the delta: %d", total)
	}
	// A snapshot archives what it does not list.
	ch, err = cat.Apply(ctx, bountyprogram.FeedApply{State: bountyprogram.FeedState{AppliedSequence: 3, KeySetVersion: 1},
		Snapshot: true, Programs: []bountyprogram.PublicProgram{mk("a", false, "*.a.example", "new.a2.example")}})
	if err != nil {
		t.Fatal(err)
	}
	if k := kinds(ch); k["acme-bounty:b"] != "removed" || k["acme-bounty:a"] != "changed" {
		t.Fatalf("third apply: %v", k)
	}
	st, err := cat.FeedState(ctx, bountyprogram.StreamSigned)
	if err != nil || st.AppliedSequence != 3 || st.KeySetVersion != 1 {
		t.Fatalf("state = %+v %v", st, err)
	}
}

// The local bundle stream (owner option A): its own sequence, archives only
// its own programs, never replaces a signed record, and the switch is off
// until set.
func TestPublicProgramRepository_LocalStream(t *testing.T) {
	db, pdb := openBatchDedupDB(t)
	ctx := context.Background()
	if _, err := db.Exec(`DELETE FROM program_feed_state; DELETE FROM program_feed_sources; UPDATE bounty_programs SET public_program_id = NULL; DELETE FROM public_programs`); err != nil {
		t.Fatal(err)
	}
	cat := NewPublicProgramRepository(pdb)
	now := time.Now().UTC().Truncate(time.Second)
	mk := func(id string) bountyprogram.PublicProgram {
		it := bountyprogram.Classify("a." + strings.ReplaceAll(id, ":", "-") + ".io")
		it.InScope, it.Confidence = true, bountyprogram.ConfidencePublishedByPlatform
		src := strings.SplitN(id, ":", 2)[0]
		p := bountyprogram.PublicProgram{FeedID: id, Source: src, Platform: "hackerone", Name: "P " + id, Type: "bounty",
			Status: bountyprogram.FeedStatusOpen, Items: []bountyprogram.Item{it}, AsOf: now,
			Provenance: bountyprogram.FeedProvenance{Source: src, SourceURL: "https://example.org/list.json"}}
		if err := p.Validate(); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if st, err := cat.LocalBundle(ctx); err != nil || st.Enabled {
		t.Fatalf("local switch default: %+v %v", st, err)
	}
	if err := cat.SetLocalBundle(ctx, bountyprogram.LocalBundleSetting{Enabled: true, Reason: "own use", ChangedBy: "root@x"}); err != nil {
		t.Fatal(err)
	}
	if st, _ := cat.LocalBundle(ctx); !st.Enabled || st.Reason != "own use" || st.ChangedAt == nil {
		t.Fatalf("local switch = %+v", st)
	}
	if _, err := cat.Apply(ctx, bountyprogram.FeedApply{Stream: bountyprogram.StreamSigned, State: bountyprogram.FeedState{AppliedSequence: 5},
		Snapshot: true, Programs: []bountyprogram.PublicProgram{mk("disclose:shared"), mk("disclose:signed")}}); err != nil {
		t.Fatal(err)
	}
	// The local stream starts at its own sequence 1 and does not archive
	// signed programs; its copy of a signed program is ignored.
	if _, err := cat.Apply(ctx, bountyprogram.FeedApply{Stream: bountyprogram.StreamLocal, State: bountyprogram.FeedState{AppliedSequence: 1},
		Snapshot: true, Programs: []bountyprogram.PublicProgram{mk("disclose:shared"), mk("bounty-targets:local")}}); err != nil {
		t.Fatal(err)
	}
	list, total, err := cat.ListPublic(ctx, "", 50, 0)
	if err != nil || total != 3 {
		t.Fatalf("list = %d %v", total, err)
	}
	for _, p := range list {
		wantLocal := p.FeedID == "bounty-targets:local"
		if p.LocalOnly != wantLocal {
			t.Fatalf("%s local = %v", p.FeedID, p.LocalOnly)
		}
	}
	if st, _ := cat.FeedState(ctx, bountyprogram.StreamLocal); st.AppliedSequence != 1 {
		t.Fatalf("local state = %+v", st)
	}
	if st, _ := cat.FeedState(ctx, bountyprogram.StreamSigned); st.AppliedSequence != 5 {
		t.Fatalf("signed state = %+v", st)
	}
	// A lower local sequence is refused.
	if _, err := cat.Apply(ctx, bountyprogram.FeedApply{Stream: bountyprogram.StreamLocal, State: bountyprogram.FeedState{AppliedSequence: 1}, Snapshot: true}); err == nil {
		t.Fatal("same local sequence applied twice")
	}
	// An empty local snapshot archives only local programs.
	if _, err := cat.Apply(ctx, bountyprogram.FeedApply{Stream: bountyprogram.StreamLocal, State: bountyprogram.FeedState{AppliedSequence: 2}, Snapshot: true}); err != nil {
		t.Fatal(err)
	}
	if _, total, _ := cat.ListPublic(ctx, "", 50, 0); total != 2 {
		t.Fatalf("after an empty local snapshot: %d", total)
	}
}
