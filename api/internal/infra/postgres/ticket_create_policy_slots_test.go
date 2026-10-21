package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Finding locks pin pool connections: one tenant gets at most its share of
// slots, other tenants still get theirs, the process-wide bound holds, and a
// canceled wait leaves nothing behind.
func TestLockSlots_BoundPerTenantAndGlobally(t *testing.T) {
	l := newLockSlots(3, 2)
	a, b, c := shared.NewID(), shared.NewID(), shared.NewID()
	ctx := context.Background()
	short := func() context.Context {
		cctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
		t.Cleanup(cancel)
		return cctx
	}

	ra1, err := l.acquire(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	ra2, err := l.acquire(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.acquire(short(), a); err == nil {
		t.Fatal("a tenant got more than its per-tenant slots")
	}
	rb, err := l.acquire(short(), b)
	if err != nil {
		t.Fatalf("another tenant was blocked by the first: %v", err)
	}
	if _, err := l.acquire(short(), c); err == nil {
		t.Fatal("the process-wide bound was exceeded")
	}

	ra1()
	ra1() // idempotent
	rc, err := l.acquire(short(), c)
	if err != nil {
		t.Fatalf("a freed slot was not reusable: %v", err)
	}
	ra2()
	rb()
	rc()
	l.mu.Lock()
	n := len(l.tenants)
	l.mu.Unlock()
	if n != 0 || len(l.global) != 0 {
		t.Fatalf("slots left behind: tenants %d global %d", n, len(l.global))
	}
}
