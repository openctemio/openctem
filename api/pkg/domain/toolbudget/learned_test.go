package toolbudget

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestSampleIsClampedPerTarget(t *testing.T) {
	b := For("httpx") // 25 at a time, [2s, 1m]
	if s, ok := b.Sample(10*time.Minute, 72); !ok || s != time.Minute {
		// 600s × 25 / 72 = 208s, clamped to the 1m ceiling.
		t.Fatalf("sample = %s %v", s, ok)
	}
	if s, _ := b.Sample(3*time.Second, 1); s != 3*time.Second {
		t.Fatalf("one target: %s", s)
	}
	if s, _ := b.Sample(time.Millisecond, 100); s != b.Floor {
		t.Fatalf("below the floor: %s", s)
	}
	if _, ok := b.Sample(0, 5); ok {
		t.Fatal("no time is no sample")
	}
	if _, ok := b.Sample(time.Second, 0); ok {
		t.Fatal("no target is no sample")
	}
}

func TestWithStatsNeedsSamplesAndStaysBounded(t *testing.T) {
	b := For("nuclei") // expected 5m, [1m, 1h]
	if got := b.WithStats(Stats{Samples: 4, P95: 2 * time.Minute}); got != b {
		t.Fatal("too few samples changed the budget")
	}
	if got := b.WithStats(Stats{Samples: 9, P95: 4 * time.Minute}); got.Expected != 2*time.Minute {
		t.Fatalf("expected = %s, want 2m", got.Expected)
	}
	// A learned value can never leave the band.
	if got := b.WithStats(Stats{Samples: 9, P95: 100 * time.Hour}); got.Expected != b.Ceiling {
		t.Fatalf("expected = %s, want the ceiling", got.Expected)
	}
	if got := b.WithStats(Stats{Samples: 9, P95: time.Second}); got.Expected != b.Floor {
		t.Fatalf("expected = %s, want the floor", got.Expected)
	}
}

type fakeStats struct {
	s   Stats
	ok  bool
	err error
}

func (f fakeStats) ObservePerTarget(context.Context, shared.ID, string, time.Duration, time.Duration, time.Duration) error {
	return nil
}
func (f fakeStats) ToolStats(context.Context, shared.ID, string) (Stats, bool, error) {
	return f.s, f.ok, f.err
}

func TestLookup(t *testing.T) {
	ctx, tenant := context.Background(), shared.NewID()
	if got := Lookup(ctx, nil, tenant, "nuclei"); got != For("nuclei") {
		t.Fatal("no store must give the default")
	}
	if got := Lookup(ctx, fakeStats{err: errors.New("down")}, tenant, "nuclei"); got != For("nuclei") {
		t.Fatal("a store error must give the default")
	}
	got := Lookup(ctx, fakeStats{s: Stats{Samples: 6, P95: 4 * time.Minute}, ok: true}, tenant, "Nuclei")
	if got.Expected != 2*time.Minute {
		t.Fatalf("learned expected = %s", got.Expected)
	}
}
