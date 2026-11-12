package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The attestation job's conditional writes (RFC-054 §12.5): a request opens
// once, an attestation closes it, the downgrade happens only for the open
// request it saw, once, and only in its own tenant.
func TestScopeAttestation_ConditionalWrites(t *testing.T) {
	db := openScopeApproversDB(t)
	s := newApproverSeed(t, db)
	other := newApproverSeed(t, db)
	owner := s.member("Olivia Owner", "owner", "active")
	repo := NewScopeTargetRepository(&DB{DB: db})
	ctx := context.Background()
	start := time.Now().UTC().Add(-100 * 24 * time.Hour).Truncate(time.Microsecond)
	e, err := scope.NewEntry(s.tenant, scope.TargetTypeDomain, "perm.t2.attest.example", "", owner, scope.EntryOptions{
		Reason: "contract", MaxTier: scope.TierIntrusive, IntrusivePermanent: true, Now: start,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Create(ctx, e); err != nil {
		t.Fatal(err)
	}

	tenants, err := repo.TenantsWithIntrusiveEntries(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, id := range tenants {
		found = found || id == s.tenant
		if id == other.tenant {
			t.Fatal("a tenant without t2 entries was listed")
		}
	}
	if !found {
		t.Fatal("the tenant with a t2 entry was not listed")
	}
	if list, _ := repo.ListActiveIntrusive(ctx, other.tenant); len(list) != 0 {
		t.Fatal("another tenant listed this tenant's t2 entry")
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	if ok, _ := repo.MarkAttestationRequested(ctx, other.tenant, e.ID(), now); ok {
		t.Fatal("another tenant opened a request")
	}
	if ok, err := repo.MarkAttestationRequested(ctx, s.tenant, e.ID(), now); err != nil || !ok {
		t.Fatalf("open request: %v %v", ok, err)
	}
	if ok, _ := repo.MarkAttestationRequested(ctx, s.tenant, e.ID(), now.Add(time.Hour)); ok {
		t.Fatal("a second request was opened")
	}
	got, err := repo.GetByID(ctx, s.tenant, e.ID())
	if err != nil || got.AttestationRequestedAt() == nil {
		t.Fatalf("request not stored: %v", err)
	}
	req := *got.AttestationRequestedAt()

	// An attestation closes the request; the stale downgrade then does nothing.
	if err := got.Attest(owner, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := repo.Update(ctx, got); err != nil {
		t.Fatal(err)
	}
	if ok, _ := repo.DowngradeUnattested(ctx, s.tenant, e.ID(), req, now.Add(15*24*time.Hour)); ok {
		t.Fatal("an attested entry was downgraded")
	}
	got, _ = repo.GetByID(ctx, s.tenant, e.ID())
	if got.AttestedAt() == nil || got.AttestedBy() != owner || got.MaxTier() != scope.TierIntrusive {
		t.Fatalf("after the attestation: attested %v by %q tier %s", got.AttestedAt(), got.AttestedBy(), got.MaxTier())
	}

	// A new request goes unanswered: one downgrade, then nothing.
	_, _ = repo.MarkAttestationRequested(ctx, s.tenant, e.ID(), now.Add(2*time.Hour))
	got, _ = repo.GetByID(ctx, s.tenant, e.ID())
	req = *got.AttestationRequestedAt()
	if ok, _ := repo.DowngradeUnattested(ctx, other.tenant, e.ID(), req, now); ok {
		t.Fatal("another tenant downgraded the entry")
	}
	if ok, err := repo.DowngradeUnattested(ctx, s.tenant, e.ID(), req, now.Add(15*24*time.Hour)); err != nil || !ok {
		t.Fatalf("downgrade: %v %v", ok, err)
	}
	if ok, _ := repo.DowngradeUnattested(ctx, s.tenant, e.ID(), req, now.Add(16*24*time.Hour)); ok {
		t.Fatal("downgraded twice")
	}
	got, _ = repo.GetByID(ctx, s.tenant, e.ID())
	if got.MaxTier() != scope.TierActive || got.Status() != scope.StatusActive || got.AttestationRequestedAt() != nil {
		t.Fatalf("after the downgrade: tier %s status %s request %v", got.MaxTier(), got.Status(), got.AttestationRequestedAt())
	}
	_ = shared.ID{}
}
