package unit

// The organization's maximum duration of an intrusive (t2) scope entry
// (RFC-054 §12.4): enforced on create and on every update, independent of
// the one-off bound, permanent only when the owner allows it, and never
// without an approval.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/scope"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

func t2(daysN *int) func(*scope.CreateTargetInput) {
	return func(in *scope.CreateTargetInput) {
		in.MaxTier, in.ExpiresInDays, in.Reason = "t2", daysN, "pentest window"
	}
}

func TestScopeT2Duration_DefaultIs30Days(t *testing.T) {
	svc, _, _ := entryService(t, 2, tenant.ScopeSettings{})
	tid := shared.NewID()
	e, err := create(svc, tid, approverA, "a.t2.example", t2(days(30)))
	if err != nil {
		t.Fatalf("30 days under the default: %v", err)
	}
	if !e.IsPending() || e.ApprovalsRequired() < 1 {
		t.Fatalf("a t2 entry took effect without an approval: %s/%d", e.Status(), e.ApprovalsRequired())
	}
	if _, err := create(svc, tid, approverA, "b.t2.example", t2(days(31))); !errors.Is(err, scopedom.ErrIntrusiveTooLong) {
		t.Fatalf("31 days: %v", err)
	}
	if _, err := create(svc, tid, approverA, "c.t2.example", t2(nil)); !errors.Is(err, scopedom.ErrIntrusiveNeeds) {
		t.Fatalf("permanent t2 without the owner allowing it: %v", err)
	}
	// The t2 bound does not lengthen t1 one-offs.
	if _, err := create(svc, tid, approverA, "d.t1.example", func(in *scope.CreateTargetInput) {
		in.ExpiresInDays, in.Reason = days(8), "short"
	}); !errors.Is(err, scope.ErrOneOffTooLong) {
		t.Fatalf("an 8-day t1 one-off with the 7-day bound: %v", err)
	}
}

func TestScopeT2Duration_OwnerSettings(t *testing.T) {
	// A single admin: t2 still needs one approval (S3).
	svc, _, _ := entryService(t, 1, tenant.ScopeSettings{T2MaxDuration: tenant.T2Max365Days})
	tid := shared.NewID()
	if _, err := create(svc, tid, approverA, "a.year.example", t2(days(365))); err != nil {
		t.Fatalf("365 days: %v", err)
	}
	if _, err := create(svc, tid, approverA, "b.year.example", t2(days(366))); !errors.Is(err, scopedom.ErrIntrusiveTooLong) {
		t.Fatalf("366 days: %v", err)
	}

	svc, _, _ = entryService(t, 1, tenant.ScopeSettings{T2MaxDuration: tenant.T2MaxPermanent})
	e, err := create(svc, tid, approverA, "perm.t2.example", t2(nil))
	if err != nil {
		t.Fatalf("permanent t2 when allowed: %v", err)
	}
	if e.ExpiresAt() != nil || !e.IsPending() || e.ApprovalsRequired() != 1 {
		t.Fatalf("permanent t2: expires %v status %s approvals %d, want permanent, pending, 1", e.ExpiresAt(), e.Status(), e.ApprovalsRequired())
	}
	// Turning one-offs off does not stop t2 entries from expiring.
	svc, _, _ = entryService(t, 2, tenant.ScopeSettings{OneOffTargets: tenant.OneOffDisabled})
	if _, err := create(svc, tid, approverA, "noof.t2.example", t2(days(7))); err != nil {
		t.Fatalf("expiring t2 with one-offs off: %v", err)
	}
	if _, err := create(svc, tid, approverA, "noof.t1.example", func(in *scope.CreateTargetInput) {
		in.ExpiresInDays, in.Reason = days(3), "x"
	}); !errors.Is(err, scope.ErrOneOffDisabled) {
		t.Fatalf("t1 one-off with one-offs off: %v", err)
	}
}

func TestScopeT2Duration_EnforcedOnUpdate(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := entryService(t, 1, tenant.ScopeSettings{OneOffMaxDays: 30, T2MaxDuration: tenant.T2Max7Days})
	tid := shared.NewID()
	perm, err := create(svc, tid, approverA, "perm.t1.example", nil)
	if err != nil {
		t.Fatal(err)
	}
	t2tier := "t2"
	if _, err := svc.UpdateTarget(ctx, perm.ID().String(), tid.String(), scope.UpdateTargetInput{MaxTier: &t2tier, Actor: approverA}); !errors.Is(err, scopedom.ErrIntrusiveNeeds) {
		t.Fatalf("raising a permanent entry to t2: %v", err)
	}
	long, err := create(svc, tid, approverA, "long.t1.example", func(in *scope.CreateTargetInput) {
		in.ExpiresInDays, in.Reason = days(25), "x"
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.UpdateTarget(ctx, long.ID().String(), tid.String(), scope.UpdateTargetInput{MaxTier: &t2tier, Actor: approverA}); !errors.Is(err, scopedom.ErrIntrusiveTooLong) {
		t.Fatalf("raising a 25-day entry to t2 with a 7-day bound: %v", err)
	}
	if long.MaxTier() != scopedom.TierActive {
		t.Fatal("a refused update changed the tier")
	}
	if _, err := svc.UpdateTarget(ctx, long.ID().String(), tid.String(), scope.UpdateTargetInput{MaxTier: &t2tier, ExpiresInDays: days(5), Actor: approverA}); err != nil {
		t.Fatalf("raising to t2 with a 5-day expiry: %v", err)
	}
	if _, err := svc.UpdateTarget(ctx, long.ID().String(), tid.String(), scope.UpdateTargetInput{ExpiresInDays: days(8), Actor: approverA}); !errors.Is(err, scopedom.ErrIntrusiveTooLong) {
		t.Fatalf("extending a t2 entry past the bound: %v", err)
	}
	if _, err := svc.UpdateTarget(ctx, long.ID().String(), tid.String(), scope.UpdateTargetInput{ClearExpiry: true, Actor: approverA}); !errors.Is(err, scopedom.ErrIntrusiveNeeds) {
		t.Fatalf("making a t2 entry permanent: %v", err)
	}
}

func TestScopeSettings_OwnerFieldsSurviveTheGeneralUpdate(t *testing.T) {
	before := tenant.ScopeSettings{T2MaxDuration: tenant.T2MaxPermanent}
	sent := tenant.ScopeSettings{OneOffMaxDays: 10} // the general PUT knows nothing of t2
	got := sent.WithIntrusive(before.Intrusive())
	if got.T2MaxDuration != tenant.T2MaxPermanent || got.OneOffMaxDays != 10 {
		t.Fatalf("merged %+v", got)
	}
	if err := (tenant.ScopeSettings{T2MaxDuration: "forever"}).Validate(); err == nil {
		t.Fatal("an unknown t2 duration was accepted")
	}
	if d, p := (tenant.ScopeSettings{}).T2Max(); d != 30 || p {
		t.Fatalf("default t2 bound %d/%v, want 30 days", d, p)
	}
	_ = time.Now
}
