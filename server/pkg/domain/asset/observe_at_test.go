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

// A new asset built from a report is first seen when the report's source saw
// it, not when the report arrived: last_seen is never before first_seen.
// Ingest used to store first_seen = the insert time and last_seen = the
// (earlier) observation time, so the asset read "first seen" after "last seen".
func TestSeenAt_FirstSeenNeverAfterLastSeen(t *testing.T) {
	for name, observe := range map[string]func(*Asset, time.Time){
		"MarkSeenAt": (*Asset).MarkSeenAt,
		"ObserveAt":  (*Asset).ObserveAt,
	} {
		t.Run(name, func(t *testing.T) {
			a, err := NewAsset("api.example.com", AssetTypeService, CriticalityLow)
			if err != nil {
				t.Fatal(err)
			}
			observed := a.FirstSeen().Add(-2 * time.Second)
			observe(a, observed)
			if !a.LastSeen().Equal(observed) {
				t.Fatalf("last_seen %v, want %v", a.LastSeen(), observed)
			}
			if a.FirstSeen().After(a.LastSeen()) {
				t.Fatalf("first_seen %v is after last_seen %v", a.FirstSeen(), a.LastSeen())
			}
			if !a.FirstSeen().Equal(observed) {
				t.Fatalf("first_seen %v, want the observation time %v", a.FirstSeen(), observed)
			}

			// A later sighting moves last_seen only.
			later := observed.Add(time.Second)
			observe(a, later)
			if !a.FirstSeen().Equal(observed) || !a.LastSeen().Equal(later) {
				t.Fatalf("after a later sighting first_seen %v last_seen %v, want %v and %v", a.FirstSeen(), a.LastSeen(), observed, later)
			}
		})
	}
}
