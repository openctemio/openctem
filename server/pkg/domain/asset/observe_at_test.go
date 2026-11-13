package asset

import (
	"testing"
	"time"
)

// An older observation is recorded as the observation time but never
// reactivates a stale asset; a newer one does.
func TestObserveAt(t *testing.T) {
	a, err := NewAsset("web01.example.com", AssetTypeHost, CriticalityLow)
	if err != nil {
		t.Fatal(err)
	}
	seen := time.Now().Add(-48 * time.Hour).UTC()
	a.MarkSeenAt(seen)
	if !a.MarkStale() {
		t.Fatal("expected the asset to go stale")
	}

	older := seen.Add(-24 * time.Hour)
	a.ObserveAt(older)
	if a.Status() != StatusStale || !a.LastSeen().Equal(older) {
		t.Fatalf("after an older observation: status %s last_seen %v, want stale at %v", a.Status(), a.LastSeen(), older)
	}

	a.ObserveAt(seen.Add(time.Hour))
	if a.Status() != StatusActive {
		t.Fatalf("after a newer observation: status %s, want active", a.Status())
	}
}

// The ingest path revives a stale asset only: an inactive asset (a closed
// port, a person's decision) stays inactive, as the store's upsert keeps it.
func TestObserveAt_InactiveStaysInactive(t *testing.T) {
	a, err := NewAsset("web02.example.com", AssetTypeHost, CriticalityLow)
	if err != nil {
		t.Fatal(err)
	}
	a.Deactivate()
	seen := time.Now().UTC()
	a.ObserveAt(seen)
	if a.Status() != StatusInactive {
		t.Fatalf("status %s, want inactive", a.Status())
	}
	if !a.LastSeen().Equal(seen) {
		t.Fatalf("last_seen %v, want %v", a.LastSeen(), seen)
	}
}
