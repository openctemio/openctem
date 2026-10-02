package main

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

type stubThreatReader struct {
	set     map[string]bool
	calls   int
	lastMin float64
}

func (r *stubThreatReader) AssetsOnOpenThreatPaths(_ context.Context, _ shared.ID, minScore float64) (map[string]bool, error) {
	r.calls++
	r.lastMin = minScore
	return r.set, nil
}

// The oracle caches per tenant for the TTL: a second lookup within the window
// hits the cache (reader NOT re-queried), keeping per-finding classification
// cheap. It also forwards the configured score threshold.
func TestThreatModelOracle_CachesWithinTTL(t *testing.T) {
	tenant := shared.NewID()
	asset := shared.NewID().String()
	reader := &stubThreatReader{set: map[string]bool{asset: true}}
	oracle := newThreatModelOracle(reader, defaultThreatScoreThreshold, time.Minute)

	set, err := oracle.OnOpenThreatPath(context.Background(), tenant)
	if err != nil {
		t.Fatalf("first lookup: %v", err)
	}
	if !set[asset] {
		t.Fatal("expected asset in set")
	}
	if _, err := oracle.OnOpenThreatPath(context.Background(), tenant); err != nil {
		t.Fatalf("second lookup: %v", err)
	}
	if reader.calls != 1 {
		t.Fatalf("expected 1 reader call within TTL, got %d", reader.calls)
	}
	if reader.lastMin != defaultThreatScoreThreshold {
		t.Fatalf("oracle must forward score threshold, got %v", reader.lastMin)
	}
}

// A zero TTL forces recomputation every call (cache immediately expired).
func TestThreatModelOracle_ExpiredCacheRecomputes(t *testing.T) {
	tenant := shared.NewID()
	reader := &stubThreatReader{set: map[string]bool{}}
	oracle := newThreatModelOracle(reader, 1.0, 0)

	_, _ = oracle.OnOpenThreatPath(context.Background(), tenant)
	_, _ = oracle.OnOpenThreatPath(context.Background(), tenant)
	if reader.calls != 2 {
		t.Fatalf("zero TTL should recompute each call, got %d calls", reader.calls)
	}
}
