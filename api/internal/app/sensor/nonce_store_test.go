package sensor

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// The per-replica nonce store refuses a replay, and bounds each signing key
// on its own: one key that fills its share (a flooding sensor, or every
// request while Redis is down) is refused, other keys keep working
// (sensor → platform review, M10).
func TestMemoryNonceStore_PerKeyBound(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0)
	m := newMemoryNonceStore(3)
	m.now = func() time.Time { return now }

	for i := range 3 {
		if fresh, err := m.Use(ctx, "flood", fmt.Sprint(i), time.Minute); !fresh || err != nil {
			t.Fatalf("nonce %d: fresh=%v err=%v", i, fresh, err)
		}
	}
	if fresh, _ := m.Use(ctx, "flood", "0", time.Minute); fresh {
		t.Fatal("a replayed nonce was accepted")
	}
	if fresh, err := m.Use(ctx, "flood", "3", time.Minute); fresh || err == nil {
		t.Fatalf("a key over its share must be refused: fresh=%v err=%v", fresh, err)
	}
	if fresh, err := m.Use(ctx, "other", "0", time.Minute); !fresh || err != nil {
		t.Fatalf("another key must not be affected by the flood: fresh=%v err=%v", fresh, err)
	}

	// Once the window passes, the flooding key works again.
	now = now.Add(2 * time.Minute)
	if fresh, err := m.Use(ctx, "flood", "4", time.Minute); !fresh || err != nil {
		t.Fatalf("after the window: fresh=%v err=%v", fresh, err)
	}
}

// Keys that stopped signing are dropped by the periodic sweep.
func TestMemoryNonceStore_SweepDropsIdleKeys(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0)
	m := newMemoryNonceStore(10)
	m.now = func() time.Time { return now }
	for i := range 100 {
		_, _ = m.Use(ctx, fmt.Sprint("k", i), "n", time.Minute)
	}
	now = now.Add(2 * time.Minute)
	for i := range nonceSweepEvery {
		_, _ = m.Use(ctx, "live", fmt.Sprint(i%5), time.Hour)
	}
	if len(m.keys) != 1 {
		t.Fatalf("%d keys kept, want only the live one", len(m.keys))
	}
}
