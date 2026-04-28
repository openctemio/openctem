package finding

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
)

func TestPriorityFlood_BelowProtectedClass_BypassesBudget(t *testing.T) {
	// Any class below the protected one never touches the budget.
	g := NewPriorityFloodGuard(PriorityFloodConfig{MaxPerHour: 1})
	tid := shared.NewID()
	for _, c := range []vulnerability.PriorityClass{vulnerability.PriorityP1, vulnerability.PriorityP2, vulnerability.PriorityP3} {
		ok, err := g.ShouldFanOut(context.Background(), tid, c)
		if err != nil || !ok {
			t.Fatalf("class %s rejected: ok=%v err=%v", c, ok, err)
		}
	}
	if g.CurrentUsage(tid) != 0 {
		t.Fatalf("non-protected class must not consume budget, got %d", g.CurrentUsage(tid))
	}
}

func TestPriorityFlood_UnderBudget_Allows(t *testing.T) {
	g := NewPriorityFloodGuard(PriorityFloodConfig{MaxPerHour: 3})
	tid := shared.NewID()
	for i := 0; i < 3; i++ {
		ok, err := g.ShouldFanOut(context.Background(), tid, vulnerability.PriorityP0)
		if !ok || err != nil {
			t.Fatalf("call %d rejected: ok=%v err=%v", i, ok, err)
		}
	}
	if g.CurrentUsage(tid) != 3 {
		t.Fatalf("usage = %d, want 3", g.CurrentUsage(tid))
	}
}

func TestPriorityFlood_OverBudget_Suppresses(t *testing.T) {
	g := NewPriorityFloodGuard(PriorityFloodConfig{MaxPerHour: 2})
	tid := shared.NewID()
	_, _ = g.ShouldFanOut(context.Background(), tid, vulnerability.PriorityP0)
	_, _ = g.ShouldFanOut(context.Background(), tid, vulnerability.PriorityP0)
	ok, err := g.ShouldFanOut(context.Background(), tid, vulnerability.PriorityP0)
	if ok {
		t.Fatal("3rd call should be suppressed")
	}
	if !errors.Is(err, ErrPriorityFloodSuppressed) {
		t.Fatalf("want ErrPriorityFloodSuppressed, got %v", err)
	}
}

func TestPriorityFlood_IsolatedPerTenant(t *testing.T) {
	g := NewPriorityFloodGuard(PriorityFloodConfig{MaxPerHour: 1})
	a := shared.NewID()
	b := shared.NewID()
	_, _ = g.ShouldFanOut(context.Background(), a, vulnerability.PriorityP0) // a uses 1/1
	ok, err := g.ShouldFanOut(context.Background(), b, vulnerability.PriorityP0)
	if !ok || err != nil {
		t.Fatal("tenant b must have its own budget")
	}
}

func TestPriorityFlood_ResetsAfterOneHour(t *testing.T) {
	now := time.Now().UTC()
	cur := now
	g := NewPriorityFloodGuard(PriorityFloodConfig{MaxPerHour: 1, Now: func() time.Time { return cur }})
	tid := shared.NewID()
	_, _ = g.ShouldFanOut(context.Background(), tid, vulnerability.PriorityP0) // 1/1
	cur = now.Add(61 * time.Minute)
	ok, err := g.ShouldFanOut(context.Background(), tid, vulnerability.PriorityP0)
	if !ok || err != nil {
		t.Fatalf("window should have rolled over: ok=%v err=%v", ok, err)
	}
}

func TestPriorityFlood_Refund_ReturnsSlot(t *testing.T) {
	g := NewPriorityFloodGuard(PriorityFloodConfig{MaxPerHour: 2})
	tid := shared.NewID()
	_, _ = g.ShouldFanOut(context.Background(), tid, vulnerability.PriorityP0) // 1/2
	_, _ = g.ShouldFanOut(context.Background(), tid, vulnerability.PriorityP0) // 2/2
	g.Refund(tid)                                                              // back to 1/2
	if g.CurrentUsage(tid) != 1 {
		t.Fatalf("after refund usage = %d, want 1", g.CurrentUsage(tid))
	}
	ok, err := g.ShouldFanOut(context.Background(), tid, vulnerability.PriorityP0)
	if !ok || err != nil {
		t.Fatalf("refund should have freed a slot: %v", err)
	}
}

func TestPriorityFlood_Refund_BelowZeroSafe(t *testing.T) {
	// A stray refund must not panic or produce negative usage.
	g := NewPriorityFloodGuard(PriorityFloodConfig{MaxPerHour: 2})
	tid := shared.NewID()
	g.Refund(tid) // no calls recorded
	g.Refund(tid)
	if g.CurrentUsage(tid) != 0 {
		t.Fatalf("empty refund must be a no-op")
	}
}

func TestPriorityFlood_ContextCancelled(t *testing.T) {
	g := NewPriorityFloodGuard(PriorityFloodConfig{MaxPerHour: 10})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ok, err := g.ShouldFanOut(ctx, shared.NewID(), vulnerability.PriorityP0)
	if ok || err == nil {
		t.Fatalf("cancelled ctx should reject: ok=%v err=%v", ok, err)
	}
}

func TestPriorityFlood_DefaultBudget(t *testing.T) {
	// Zero cfg must apply the documented defaults: MaxPerHour=50,
	// ProtectedClass=PriorityP0.
	g := NewPriorityFloodGuard(PriorityFloodConfig{})
	tid := shared.NewID()
	for i := 0; i < 50; i++ {
		ok, _ := g.ShouldFanOut(context.Background(), tid, vulnerability.PriorityP0)
		if !ok {
			t.Fatalf("default budget should be ≥50, failed at %d", i)
		}
	}
	ok, _ := g.ShouldFanOut(context.Background(), tid, vulnerability.PriorityP0)
	if ok {
		t.Fatal("51st call should be suppressed under default budget")
	}
}

func TestPriorityFlood_CustomProtectedClass(t *testing.T) {
	// The guard must protect whichever class the config names.
	g := NewPriorityFloodGuard(PriorityFloodConfig{
		ProtectedClass: vulnerability.PriorityP1,
		MaxPerHour:     1,
	})
	tid := shared.NewID()
	// P0 is NOT protected here → bypasses budget.
	for i := 0; i < 5; i++ {
		if ok, err := g.ShouldFanOut(context.Background(), tid, vulnerability.PriorityP0); !ok || err != nil {
			t.Fatalf("P0 must bypass when ProtectedClass=P1: %v", err)
		}
	}
	// P1 consumes the budget.
	if ok, err := g.ShouldFanOut(context.Background(), tid, vulnerability.PriorityP1); !ok || err != nil {
		t.Fatalf("first P1 should pass: %v", err)
	}
	if ok, _ := g.ShouldFanOut(context.Background(), tid, vulnerability.PriorityP1); ok {
		t.Fatal("second P1 should be suppressed at MaxPerHour=1")
	}
}
