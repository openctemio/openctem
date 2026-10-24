package contentsource_test

// The sync claim: one source at a time under a lease, saved only while the
// lease matches, requests made during a sync kept, round-robin across
// organizations; and who may promote a snapshot (the members who changed
// the configuration it came from may not).

import (
	"context"
	"errors"
	"testing"
	"time"

	app "github.com/openctemio/openctem/api/internal/app/contentsource"
	dom "github.com/openctemio/openctem/api/pkg/domain/contentsource"
)

// SECURITY: every member who changed the configuration a snapshot was
// synced from is refused its promotion, not only the last editor.
func TestRuleSources_FourEyesCoversEveryConfigAuthor_DB(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	src := e.create(t, "acme-authors", func(in *app.CreateInput) { in.Policy = "review" }) // user1 creates
	ref := "dev"
	if _, err := e.svc.Update(ctx, e.actor(e.tenantA, e.user2), src.ID, app.UpdateInput{Ref: &ref}); err != nil {
		t.Fatal(err)
	}
	e.git.set(sha('a'), map[string]string{"a.yaml": rulesFile("r1")})
	src = e.runSync(t, src)
	cand := e.snapshots(t, src)[0]
	if !cand.AuthoredBy(e.user1) || !cand.AuthoredBy(e.user2) || cand.AuthoredBy(e.user3) {
		t.Fatalf("snapshot config authors: %v", cand.ConfigAuthors)
	}
	// user2 is the last editor; user1 edited earlier: both are refused.
	for _, u := range []string{"user1", "user2"} {
		uid := e.user1
		if u == "user2" {
			uid = e.user2
		}
		if err := e.svc.Promote(ctx, e.actor(e.tenantA, uid), src.ID, cand.ID); !errors.Is(err, dom.ErrFourEyes) {
			t.Fatalf("promotion by %s: %v, want four-eyes", u, err)
		}
	}
	if err := e.svc.Promote(ctx, e.actor(e.tenantA, e.user3), src.ID, cand.ID); err != nil {
		t.Fatalf("promotion by a member who changed nothing: %v", err)
	}

	// The authors of one snapshot are consumed by its sync: a later change
	// by user3 alone puts only user3 on the next snapshot.
	path := "other"
	if _, err := e.svc.Update(ctx, e.actor(e.tenantA, e.user3), src.ID, app.UpdateInput{Path: &path}); err != nil {
		t.Fatal(err)
	}
	e.git.set(sha('b'), map[string]string{"a.yaml": rulesFile("r1", "r2")})
	src = e.runSync(t, src)
	var next *dom.Snapshot
	for _, sn := range e.snapshots(t, src) {
		if sn.State == dom.StateCandidate {
			next = sn
		}
	}
	if next == nil || next.AuthoredBy(e.user1) || next.AuthoredBy(e.user2) || !next.AuthoredBy(e.user3) {
		t.Fatalf("second snapshot authors: %+v", next)
	}
	if err := e.svc.Promote(ctx, e.actor(e.tenantA, e.user3), src.ID, next.ID); !errors.Is(err, dom.ErrFourEyes) {
		t.Fatalf("promotion by the editor: %v", err)
	}
}

func (e *env) leaseOf(t *testing.T, id string) (leased bool, requested *time.Time) {
	t.Helper()
	var until, req *time.Time
	if err := e.db.QueryRowContext(context.Background(), `SELECT sync_lease_until, sync_requested_at FROM content_sources WHERE id = $1`, id).Scan(&until, &req); err != nil {
		t.Fatal(err)
	}
	return until != nil, req
}

// A claim is one source, held under a lease; the outcome is saved only while
// the lease matches, and a request made after the claim stays queued.
func TestRuleSources_ClaimLeaseAndRequests_DB(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	one := e.create(t, "acme-one", nil)
	two := e.create(t, "acme-two", nil)
	now := e.clock.Add(time.Minute)

	// Only our two sources matter; claim one at a time.
	claimed := map[string]bool{}
	var first *dom.Source
	for i := 0; i < 50 && first == nil; i++ {
		got, err := e.repo.ClaimDueUnscoped(ctx, now, 15*time.Minute, 1)
		if err != nil || len(got) != 1 {
			t.Fatalf("claim: %d %v", len(got), err)
		}
		claimed[got[0].ID.String()] = true
		if got[0].ID.Equals(one.ID) || got[0].ID.Equals(two.ID) {
			first = got[0]
		}
	}
	if first == nil {
		t.Fatal("neither source was claimed")
	}
	other := two
	if first.ID.Equals(two.ID) {
		other = one
	}
	if leased, _ := e.leaseOf(t, other.ID.String()); leased {
		t.Fatal("a claim of one source leased another (claims must be one at a time)")
	}
	if first.LeaseUntil.IsZero() || !first.ClaimedAt.Equal(now) {
		t.Fatalf("claimed source lacks its lease: %+v", first)
	}
	// Claimed: not claimable again while the lease runs.
	if _, err := e.repo.RequestSyncUnscoped(ctx, first.ID, now.Add(time.Second), 0); err != nil {
		t.Fatal(err)
	}
	// A save under another lease is refused and changes nothing.
	out := dom.SyncOutcome{Status: dom.SyncSuccess, At: now, ClearRequest: true, ResetFailures: true, LeaseUntil: first.LeaseUntil.Add(time.Hour), ClaimedAt: now}
	if err := e.repo.SaveSyncUnscoped(ctx, first.ID, out); !errors.Is(err, dom.ErrLeaseLost) {
		t.Fatalf("save with a foreign lease: %v", err)
	}
	if leased, _ := e.leaseOf(t, first.ID.String()); !leased {
		t.Fatal("a refused save released the lease")
	}
	// Under the right lease it is saved, the lease is released and the
	// request made after the claim (Sync now during the sync) is kept.
	out.LeaseUntil = first.LeaseUntil
	if err := e.repo.SaveSyncUnscoped(ctx, first.ID, out); err != nil {
		t.Fatal(err)
	}
	leased, req := e.leaseOf(t, first.ID.String())
	if leased || req == nil {
		t.Fatalf("after save: leased %v, request kept %v", leased, req != nil)
	}
	// A second save with the old lease no longer matches.
	if err := e.repo.SaveSyncUnscoped(ctx, first.ID, out); !errors.Is(err, dom.ErrLeaseLost) {
		t.Fatalf("save after release: %v", err)
	}
	// A request made before the claim is cleared by the save.
	again, err := e.repo.ClaimDueUnscoped(ctx, now.Add(time.Hour), 15*time.Minute, 50)
	if err != nil {
		t.Fatal(err)
	}
	for _, src := range again {
		if src.ID.Equals(first.ID) {
			out = dom.SyncOutcome{Status: dom.SyncSuccess, At: now, ClearRequest: true, LeaseUntil: src.LeaseUntil, ClaimedAt: now.Add(time.Hour)}
			if err := e.repo.SaveSyncUnscoped(ctx, first.ID, out); err != nil {
				t.Fatal(err)
			}
			if _, req := e.leaseOf(t, first.ID.String()); req != nil {
				t.Fatal("a request made before the claim was not cleared")
			}
		}
	}
}

// Fair queueing: a tenant with many requested syncs gets one claim per
// round, so another tenant's due source is claimed second, not last.
func TestRuleSources_ClaimIsRoundRobinPerTenant_DB(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a1 := e.create(t, "fair-a1", nil)
	a2 := e.create(t, "fair-a2", nil)
	a3 := e.create(t, "fair-a3", nil)
	b, err := e.svc.Create(ctx, e.actor(e.tenantB, e.userB), app.CreateInput{Slug: "fair-b", Name: "b", Kind: "semgrep-rules",
		URL: "https://git.example.com/b/rules.git", Ref: "main", Path: "rules"})
	if err != nil {
		t.Fatal(err)
	}
	// Tenant A's sources are all requested (Sync now), the oldest first;
	// tenant B's is only scheduled.
	for i, src := range []*dom.Source{a1, a2, a3} {
		if err := e.repo.RequestSync(ctx, e.tenantA, src.ID, e.clock.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	names := map[string]string{a1.ID.String(): "a1", a2.ID.String(): "a2", a3.ID.String(): "a3", b.ID.String(): "b"}
	var order []string
	for i := 0; i < 100 && len(order) < 4; i++ {
		got, err := e.repo.ClaimDueUnscoped(ctx, e.clock.Add(time.Minute), 15*time.Minute, 1)
		if err != nil || len(got) == 0 {
			t.Fatalf("claim: %d %v", len(got), err)
		}
		if n, ok := names[got[0].ID.String()]; ok {
			order = append(order, n)
		}
	}
	if len(order) != 4 || order[0] != "a1" || order[1] != "b" || order[2] != "a2" || order[3] != "a3" {
		t.Fatalf("claim order %v, want [a1 b a2 a3] (one source per tenant per round, requested first within a tenant)", order)
	}
}

// SECURITY: turning review off takes the approval permission; write alone
// cannot, or one member could switch review off and let the next sync
// promote its own change.
func TestRuleSources_WeakeningReviewNeedsApproval_DB(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	src := e.create(t, "acme-weaken", func(in *app.CreateInput) { in.Policy = "review" })
	auto := "auto"
	writer := e.actor(e.tenantA, e.user2)
	if _, err := e.svc.Update(ctx, writer, src.ID, app.UpdateInput{Policy: &auto}); !errors.Is(err, dom.ErrApprovalRequired) {
		t.Fatalf("review to auto without the approval permission: %v", err)
	}
	if got, _ := e.repo.Get(ctx, e.tenantA, src.ID); got.Policy != dom.PolicyReview {
		t.Fatalf("the refused change was stored: %s", got.Policy)
	}
	// Other edits by the writer are unaffected, and an approver may weaken.
	desc := "x"
	if _, err := e.svc.Update(ctx, writer, src.ID, app.UpdateInput{Description: &desc}); err != nil {
		t.Fatal(err)
	}
	approver := writer
	approver.CanApprove = true
	if _, err := e.svc.Update(ctx, approver, src.ID, app.UpdateInput{Policy: &auto}); err != nil {
		t.Fatalf("review to auto by an approver: %v", err)
	}
	// Raising to review is allowed with write.
	review := "review"
	if _, err := e.svc.Update(ctx, writer, src.ID, app.UpdateInput{Policy: &review}); err != nil {
		t.Fatalf("auto to review: %v", err)
	}
}
