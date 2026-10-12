package domainverify

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/verifieddomain"
)

// An SSO domain is claimed by one organization, platform-wide: a second
// organization may add it (pending) but cannot verify it while another holds
// it, nor within ClaimDisputeWindow after the holder's proof lapsed.

type claimFixture struct {
	repo   *memRepo
	res    *mockResolver
	svc    *Service
	holder shared.ID
	other  shared.ID
}

func newClaimFixture(t *testing.T) *claimFixture {
	t.Helper()
	f := &claimFixture{
		repo:   newMemRepo(),
		res:    &mockResolver{records: map[string][]string{}},
		holder: shared.NewID(),
		other:  shared.NewID(),
	}
	f.svc = NewService(f.repo, f.res, nil)
	return f
}

// publish adds the token's TXT record next to any already there (two
// organizations can both publish theirs at the same host).
func (f *claimFixture) publish(domain, token string) {
	host := "_openctem-verify." + domain
	f.res.records[host] = append(f.res.records[host], "openctem-domain-verification="+token)
}

// verify adds the domain for tid, publishes its record and verifies it.
func (f *claimFixture) verify(t *testing.T, tid shared.ID, domain string) (*verifieddomain.VerifiedDomain, error) {
	t.Helper()
	id, token := mustAdd(t, f.svc, tid, domain)
	f.publish(domain, token)
	return f.svc.VerifyByID(context.Background(), tid, id)
}

func TestClaim_SecondOrganizationCannotVerifyAHeldDomain(t *testing.T) {
	f := newClaimFixture(t)
	if _, err := f.verify(t, f.holder, "acme.com"); err != nil {
		t.Fatalf("holder verify: %v", err)
	}
	// The second organization may add the domain (pending) ...
	id, token := mustAdd(t, f.svc, f.other, "acme.com")
	f.publish("acme.com", token)
	// ... but not verify it, even with its own TXT record published.
	_, err := f.svc.VerifyByID(context.Background(), f.other, id)
	if !errors.Is(err, verifieddomain.ErrDomainClaimed) {
		t.Fatalf("expected ErrDomainClaimed, got %v", err)
	}
	row, _ := f.repo.GetByID(context.Background(), f.other, id)
	if row.Status() != verifieddomain.StatusPending {
		t.Fatalf("the challenger's row must stay pending, got %s", row.Status())
	}
	if ok, _ := f.svc.IsVerifiedDomain(context.Background(), f.other.String(), "acme.com"); ok {
		t.Fatal("the challenger must not admit SSO users for the domain")
	}
	if ok, _ := f.svc.IsVerifiedDomain(context.Background(), f.holder.String(), "acme.com"); !ok {
		t.Fatal("the holder keeps its claim")
	}
}

func TestClaim_WithinDisputeWindowAfterLapseRefused(t *testing.T) {
	f := newClaimFixture(t)
	held, err := f.verify(t, f.holder, "acme.com")
	if err != nil {
		t.Fatalf("holder verify: %v", err)
	}
	// The holder's record disappears; re-verify downgrades it and stamps lapsed_at.
	f.res.records["_openctem-verify.acme.com"] = nil
	if _, err := f.svc.ReverifyDue(context.Background(), 0, 100); err != nil {
		t.Fatalf("reverify: %v", err)
	}
	if held.Status() != verifieddomain.StatusFailed || held.LapsedAt() == nil {
		t.Fatalf("expected failed with lapsed_at, got %s %v", held.Status(), held.LapsedAt())
	}
	if _, err := f.verify(t, f.other, "acme.com"); !errors.Is(err, verifieddomain.ErrDomainClaimed) {
		t.Fatalf("a challenger must wait out the dispute window, got %v", err)
	}
}

func TestClaim_AfterDisputeWindowChallengerMayVerify(t *testing.T) {
	f := newClaimFixture(t)
	held, err := f.verify(t, f.holder, "acme.com")
	if err != nil {
		t.Fatalf("holder verify: %v", err)
	}
	// Lapsed 8 days ago.
	lapsed := time.Now().Add(-verifieddomain.ClaimDisputeWindow - 24*time.Hour)
	held.MarkChecked(lapsed)
	got, err := f.verify(t, f.other, "acme.com")
	if err != nil {
		t.Fatalf("after the window the challenger may verify, got %v", err)
	}
	if !got.IsVerified() {
		t.Fatalf("expected verified, got %s", got.Status())
	}
	// The old holder cannot take it back while the challenger holds it.
	if _, err := f.svc.VerifyByID(context.Background(), f.holder, held.ID()); !errors.Is(err, verifieddomain.ErrDomainClaimed) {
		t.Fatalf("the old holder must not re-verify a domain someone else holds, got %v", err)
	}
}

func TestClaim_HolderMayRestoreWithinWindow(t *testing.T) {
	f := newClaimFixture(t)
	held, err := f.verify(t, f.holder, "acme.com")
	if err != nil {
		t.Fatalf("holder verify: %v", err)
	}
	held.MarkChecked(time.Now()) // lapses now
	// The holder's own TXT is still published: verify-now restores the claim.
	got, err := f.svc.VerifyByID(context.Background(), f.holder, held.ID())
	if err != nil || !got.IsVerified() {
		t.Fatalf("the holder restores its own claim, got %v %v", got.Status(), err)
	}
	if got.LapsedAt() != nil {
		t.Fatal("a restored claim clears lapsed_at")
	}
}

// EASM proof is per organization and never exclusive.
func TestClaim_EASMRowsAreNotExclusive(t *testing.T) {
	f := newClaimFixture(t)
	if _, err := f.verify(t, f.holder, "acme.com"); err != nil {
		t.Fatalf("holder verify: %v", err)
	}
	vd, _, err := f.svc.AddEASMDomain(context.Background(), f.other, "acme.com")
	if err != nil {
		t.Fatalf("EASM add: %v", err)
	}
	f.publish("acme.com", vd.VerificationToken())
	got, err := f.svc.VerifyEASM(context.Background(), f.other, vd.ID())
	if err != nil || !got.IsVerified() {
		t.Fatalf("EASM verification is not exclusive, got %v %v", got, err)
	}
	// Promoting that verified EASM row to SSO is a claim: refused.
	if _, _, err := f.svc.AddDomain(context.Background(), f.other, "acme.com"); !errors.Is(err, verifieddomain.ErrDomainClaimed) {
		t.Fatalf("promoting a verified EASM row to SSO must pass the claim check, got %v", err)
	}
	row, _ := f.repo.GetByID(context.Background(), f.other, vd.ID())
	if row.Purpose() != verifieddomain.PurposeEASM {
		t.Fatal("a refused promotion leaves the EASM row as it was")
	}
}

// A pre-exclusivity conflict keeps both organizations working and is cleared
// by re-verify once only one claim is left.
func TestClaim_ConflictSettlesWhenAlone(t *testing.T) {
	f := newClaimFixture(t)
	a, err := f.verify(t, f.holder, "acme.com")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	// Simulate migration 001303 having flagged a second org's verified row.
	b, _ := verifieddomain.New(shared.NewID(), f.other, "acme.com", "tok-b")
	b.MarkVerified(time.Now())
	b.WithClaimState(nil, true)
	a.WithClaimState(nil, true)
	f.repo.rows[b.ID().String()] = b
	f.publish("acme.com", "tok-b")

	if _, err := f.svc.ReverifyDue(context.Background(), 0, 100); err != nil {
		t.Fatalf("reverify: %v", err)
	}
	if !a.ClaimConflict() || !b.ClaimConflict() {
		t.Fatal("both rows stay flagged while both hold the domain")
	}
	for _, tid := range []shared.ID{f.holder, f.other} {
		if ok, _ := f.svc.IsVerifiedDomain(context.Background(), tid.String(), "acme.com"); !ok {
			t.Fatal("a flagged conflict must not drop either organization's access")
		}
	}
	// The platform administrator removes one; the other settles.
	if err := f.svc.Delete(context.Background(), f.other, b.ID()); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := f.svc.ReverifyDue(context.Background(), 0, 100); err != nil {
		t.Fatalf("reverify: %v", err)
	}
	if a.ClaimConflict() {
		t.Fatal("the remaining claim must be settled")
	}
}

func TestAddDomain_RefusesSharedSuffixesAndDisposable(t *testing.T) {
	for _, d := range []string{"co.uk", "github.io", "alice.github.io", "x.vercel.app", "mailinator.com", "gmx.de", "yahoo.co.jp"} {
		svc := NewService(newMemRepo(), &mockResolver{}, nil)
		if _, _, err := svc.AddDomain(context.Background(), shared.NewID(), d); !errors.Is(err, verifieddomain.ErrBlockedDomain) {
			t.Errorf("%q must be refused as a shared domain, got %v", d, err)
		}
	}
}
