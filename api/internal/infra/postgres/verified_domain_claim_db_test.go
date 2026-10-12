package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/verifieddomain"
)

// An SSO domain is claimed by one organization, platform-wide (migration
// 001303): the partial unique index refuses a second verified SSO row for the
// same domain even when two verifications race past the service check, while
// pending rows and EASM rows stay per organization. Requires DATABASE_URL.
func TestVerifiedDomainRepository_SSOClaimIsExclusive(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	r := NewVerifiedDomainRepository(&DB{DB: sqlDB})
	a := seedTestTenant(ctx, t, sqlDB)
	b := seedTestTenant(ctx, t, sqlDB)
	c := seedTestTenant(ctx, t, sqlDB)
	domain := "claim-" + shared.NewID().String()[28:] + ".example.com"

	rowA, _ := verifieddomain.New(shared.NewID(), a, domain, "tok-a")
	rowB, _ := verifieddomain.New(shared.NewID(), b, domain, "tok-b")
	easmC, _ := verifieddomain.New(shared.NewID(), c, domain, "tok-c")
	easmC.WithPurpose(verifieddomain.PurposeEASM)
	for _, row := range []*verifieddomain.VerifiedDomain{rowA, rowB, easmC} {
		if err := r.Create(ctx, row); err != nil {
			t.Fatalf("create pending rows for several organizations: %v", err)
		}
	}

	now := time.Now()
	rowA.MarkVerified(now)
	if err := r.Update(ctx, rowA); err != nil {
		t.Fatalf("first claim: %v", err)
	}
	// The race the service check cannot close: B verifies too.
	rowB.MarkVerified(now)
	if err := r.Update(ctx, rowB); !errors.Is(err, verifieddomain.ErrDomainClaimed) {
		t.Fatalf("a second verified SSO claim must be refused by the database, got %v", err)
	}
	// EASM proof is not exclusive.
	easmC.MarkVerified(now)
	if err := r.Update(ctx, easmC); err != nil {
		t.Fatalf("an EASM row may be verified next to an SSO claim: %v", err)
	}

	claims, err := r.ListSSOClaims(ctx, domain)
	if err != nil {
		t.Fatalf("ListSSOClaims: %v", err)
	}
	if len(claims) != 2 {
		t.Fatalf("ListSSOClaims must return the SSO rows of every organization (2), got %d", len(claims))
	}
	for _, cl := range claims {
		if cl.Purpose() != verifieddomain.PurposeSSO {
			t.Fatal("ListSSOClaims must not return EASM rows")
		}
	}

	// The holder loses its proof: lapsed_at round-trips, and the challenger
	// may then hold the claim in the database.
	rowA.MarkChecked(now.Add(time.Minute))
	if err := r.Update(ctx, rowA); err != nil {
		t.Fatalf("downgrade: %v", err)
	}
	got, err := r.GetByID(ctx, a, rowA.ID())
	if err != nil || got.LapsedAt() == nil || got.Status() != verifieddomain.StatusFailed {
		t.Fatalf("lapsed_at must persist on a downgrade, got %+v %v", got, err)
	}
	if err := r.Update(ctx, rowB); err != nil {
		t.Fatalf("after the holder lapsed the index admits the challenger: %v", err)
	}

	// A conflict-flagged row (pre-exclusivity data) is outside the index.
	rowA.MarkVerified(now.Add(2 * time.Minute))
	rowA.WithClaimState(nil, true)
	if err := r.Update(ctx, rowA); err != nil {
		t.Fatalf("a flagged conflict row may stay verified next to the claim: %v", err)
	}
	got, _ = r.GetByID(ctx, a, rowA.ID())
	if !got.ClaimConflict() {
		t.Fatal("claim_conflict must round-trip")
	}
}
