package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
)

func TestP0Flood_NonP0_BypassesBudget(t *testing.T) {
	// P1, P2, P3 don't consume the P0 budget — they never touch it.
	g := NewP0FloodGuard(P0FloodConfig{MaxPerHour: 1})
	tid := shared.NewID()
	for _, c := range []vulnerability.PriorityClass{"P1", "P2", "P3"} {
		ok, err := g.ShouldFanOut(context.Background(), tid, c)
		if err != nil || !ok {
			t.Fatalf("class %s rejected: ok=%v err=%v", c, ok, err)
		}
	}
	if g.CurrentUsage(tid) != 0 {
		t.Fatalf("non-P0 must not consume budget, got %d", g.CurrentUsage(tid))
	}
}

func TestP0Flood_UnderBudget_Allows(t *testing.T) {
	g := NewP0FloodGuard(P0FloodConfig{MaxPerHour: 3})
	tid := shared.NewID()
	for i := 0; i < 3; i++ {
		ok, err := g.ShouldFanOut(context.Background(), tid, "P0")
		if !ok || err != nil {
			t.Fatalf("call %d rejected: ok=%v err=%v", i, ok, err)
		}
	}
	if g.CurrentUsage(tid) != 3 {
		t.Fatalf("usage = %d, want 3", g.CurrentUsage(tid))
	}
}

func TestP0Flood_OverBudget_Suppresses(t *testing.T) {
	g := NewP0FloodGuard(P0FloodConfig{MaxPerHour: 2})
	tid := shared.NewID()
	_, _ = g.ShouldFanOut(context.Background(), tid, "P0")
	_, _ = g.ShouldFanOut(context.Background(), tid, "P0")
	ok, err := g.ShouldFanOut(context.Background(), tid, "P0")
	if ok {
		t.Fatal("3rd call should be suppressed")
	}
	if !errors.Is(err, ErrP0FloodSuppressed) {
		t.Fatalf("want ErrP0FloodSuppressed, got %v", err)
	}
}

func TestP0Flood_IsolatedPerTenant(t *testing.T) {
	g := NewP0FloodGuard(P0FloodConfig{MaxPerHour: 1})
	a := shared.NewID()
	b := shared.NewID()
	_, _ = g.ShouldFanOut(context.Background(), a, "P0") // a uses 1/1
	ok, err := g.ShouldFanOut(context.Background(), b, "P0")
	if !ok || err != nil {
		t.Fatal("tenant b must have its own budget")
	}
}

func TestP0Flood_ResetsAfterOneHour(t *testing.T) {
	now := time.Now().UTC()
	cur := now
	g := NewP0FloodGuard(P0FloodConfig{MaxPerHour: 1, Now: func() time.Time { return cur }})
	tid := shared.NewID()
	_, _ = g.ShouldFanOut(context.Background(), tid, "P0") // 1/1
	cur = now.Add(61 * time.Minute)
	ok, err := g.ShouldFanOut(context.Background(), tid, "P0")
	if !ok || err != nil {
		t.Fatalf("window should have rolled over: ok=%v err=%v", ok, err)
	}
}

func TestP0Flood_Refund_ReturnsSlot(t *testing.T) {
	g := NewP0FloodGuard(P0FloodConfig{MaxPerHour: 2})
	tid := shared.NewID()
	_, _ = g.ShouldFanOut(context.Background(), tid, "P0") // 1/2
	_, _ = g.ShouldFanOut(context.Background(), tid, "P0") // 2/2
	g.Refund(tid)                                          // back to 1/2
	if g.CurrentUsage(tid) != 1 {
		t.Fatalf("after refund usage = %d, want 1", g.CurrentUsage(tid))
	}
	ok, err := g.ShouldFanOut(context.Background(), tid, "P0")
	if !ok || err != nil {
		t.Fatalf("refund should have freed a slot: %v", err)
	}
}

func TestP0Flood_Refund_BelowZeroSafe(t *testing.T) {
	// A stray refund must not panic or produce negative usage.
	g := NewP0FloodGuard(P0FloodConfig{MaxPerHour: 2})
	tid := shared.NewID()
	g.Refund(tid) // no calls recorded
	g.Refund(tid)
	if g.CurrentUsage(tid) != 0 {
		t.Fatalf("empty refund must be a no-op")
	}
}

func TestP0Flood_ContextCancelled(t *testing.T) {
	g := NewP0FloodGuard(P0FloodConfig{MaxPerHour: 10})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ok, err := g.ShouldFanOut(ctx, shared.NewID(), "P0")
	if ok || err == nil {
		t.Fatalf("cancelled ctx should reject: ok=%v err=%v", ok, err)
	}
}

func TestP0Flood_DefaultBudget(t *testing.T) {
	// Zero cfg must apply default MaxPerHour of 50 (documented in
	// the CTEM roadmap for this task).
	g := NewP0FloodGuard(P0FloodConfig{})
	tid := shared.NewID()
	for i := 0; i < 50; i++ {
		ok, _ := g.ShouldFanOut(context.Background(), tid, "P0")
		if !ok {
			t.Fatalf("default budget should be ≥50, failed at %d", i)
		}
	}
	ok, _ := g.ShouldFanOut(context.Background(), tid, "P0")
	if ok {
		t.Fatal("51st call should be suppressed under default budget")
	}
}
