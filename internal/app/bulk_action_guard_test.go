package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// Q2/WS-E: unit tests for the bulk-action guard. Full handler-level
// integration (the "operator approved" flag is set from middleware) is
// covered in the respective handler tests once the middleware lands.

func fixedClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

func TestBulkGuard_UnderCeiling_Allowed(t *testing.T) {
	g := NewBulkGuard(BulkGuardConfig{
		SizeCeiling:  500,
		HourlyBudget: 10_000,
		Now:          fixedClock(time.Now()),
	})
	if err := g.CheckBulk(context.Background(), shared.NewID(), 100, false); err != nil {
		t.Fatalf("small request rejected: %v", err)
	}
}

func TestBulkGuard_OverCeilingWithoutApproval_Rejected(t *testing.T) {
	g := NewBulkGuard(BulkGuardConfig{SizeCeiling: 500, HourlyBudget: 10_000, Now: fixedClock(time.Now())})
	err := g.CheckBulk(context.Background(), shared.NewID(), 1000, false)
	if !errors.Is(err, ErrBulkTooLarge) {
		t.Fatalf("want ErrBulkTooLarge, got %v", err)
	}
}

func TestBulkGuard_OverCeilingWithApproval_Allowed(t *testing.T) {
	// Operator-approved bypasses the per-request ceiling.
	g := NewBulkGuard(BulkGuardConfig{SizeCeiling: 500, HourlyBudget: 10_000, Now: fixedClock(time.Now())})
	if err := g.CheckBulk(context.Background(), shared.NewID(), 1000, true); err != nil {
		t.Fatalf("approved request rejected: %v", err)
	}
}

func TestBulkGuard_HourlyBudgetExhausted(t *testing.T) {
	// Even with approval, the tenant's hourly budget is enforced so
	// one operator cannot blast the entire tenant.
	g := NewBulkGuard(BulkGuardConfig{SizeCeiling: 10_000, HourlyBudget: 10_000, Now: fixedClock(time.Now())})
	tid := shared.NewID()

	// First call consumes 8000 of 10000.
	if err := g.CheckBulk(context.Background(), tid, 8000, true); err != nil {
		t.Fatalf("first call: %v", err)
	}
	// Second call for 3000 would push us to 11000 → rejected.
	err := g.CheckBulk(context.Background(), tid, 3000, true)
	if !errors.Is(err, ErrBulkBudgetExceeded) {
		t.Fatalf("want budget exceeded, got %v", err)
	}
	// Third call for 2000 fits (8000+2000=10000 exactly).
	if err := g.CheckBulk(context.Background(), tid, 2000, true); err != nil {
		t.Fatalf("exact-fit call rejected: %v", err)
	}
}

func TestBulkGuard_HourlyBudget_IsolatedPerTenant(t *testing.T) {
	g := NewBulkGuard(BulkGuardConfig{SizeCeiling: 10_000, HourlyBudget: 10_000, Now: fixedClock(time.Now())})
	tenantA := shared.NewID()
	tenantB := shared.NewID()
	// Tenant A uses full budget.
	if err := g.CheckBulk(context.Background(), tenantA, 10_000, true); err != nil {
		t.Fatalf("tenant A: %v", err)
	}
	// Tenant B is unaffected.
	if err := g.CheckBulk(context.Background(), tenantB, 10_000, true); err != nil {
		t.Fatalf("tenant B must have its own budget, got: %v", err)
	}
}

func TestBulkGuard_BudgetResetsAfterOneHour(t *testing.T) {
	now := time.Now().UTC()
	cur := now
	g := NewBulkGuard(BulkGuardConfig{
		SizeCeiling:  10_000,
		HourlyBudget: 10_000,
		Now:          func() time.Time { return cur },
	})
	tid := shared.NewID()
	if err := g.CheckBulk(context.Background(), tid, 10_000, true); err != nil {
		t.Fatalf("first: %v", err)
	}
	// Jump clock 61 minutes — the rolling window drops the prior entry.
	cur = now.Add(61 * time.Minute)
	if err := g.CheckBulk(context.Background(), tid, 10_000, true); err != nil {
		t.Fatalf("second after reset: %v", err)
	}
}

func TestBulkGuard_NegativeOrZeroSize_Rejected(t *testing.T) {
	g := NewBulkGuard(BulkGuardConfig{Now: fixedClock(time.Now())})
	for _, size := range []int{0, -1, -999} {
		if err := g.CheckBulk(context.Background(), shared.NewID(), size, true); !errors.Is(err, ErrBulkNegativeSize) {
			t.Errorf("size %d: want ErrBulkNegativeSize, got %v", size, err)
		}
	}
}

func TestBulkGuard_UsageThisHour(t *testing.T) {
	g := NewBulkGuard(BulkGuardConfig{SizeCeiling: 10_000, HourlyBudget: 10_000, Now: fixedClock(time.Now())})
	tid := shared.NewID()
	if got := g.UsageThisHour(tid); got != 0 {
		t.Fatalf("empty tenant = %d, want 0", got)
	}
	_ = g.CheckBulk(context.Background(), tid, 200, true)
	_ = g.CheckBulk(context.Background(), tid, 150, true)
	if got := g.UsageThisHour(tid); got != 350 {
		t.Fatalf("usage = %d, want 350", got)
	}
}

func TestBulkGuard_ContextCancelled(t *testing.T) {
	g := NewBulkGuard(BulkGuardConfig{Now: fixedClock(time.Now())})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := g.CheckBulk(ctx, shared.NewID(), 10, false); err == nil {
		t.Fatal("cancelled ctx must reject")
	}
}

func TestBulkGuard_RejectedCallsDoNotConsumeBudget(t *testing.T) {
	// A rejected call MUST not affect the hourly tally — otherwise
	// spamming rejected calls would DOS the tenant's own bulk ops.
	g := NewBulkGuard(BulkGuardConfig{SizeCeiling: 100, HourlyBudget: 1000, Now: fixedClock(time.Now())})
	tid := shared.NewID()
	// Two rejected calls (over ceiling, no approval).
	_ = g.CheckBulk(context.Background(), tid, 500, false)
	_ = g.CheckBulk(context.Background(), tid, 500, false)
	if got := g.UsageThisHour(tid); got != 0 {
		t.Fatalf("rejected calls must not consume budget, usage=%d", got)
	}
}
