package asset

import (
	"fmt"
	"testing"
)

// An asset holds at most MaxTagsPerAsset tags, whichever path adds them.
// Ingest merges scanner tags into an existing asset on every run; before the
// cap, an asset could grow past what the update API accepts and could then
// not be saved from the UI, not even to remove a tag.
func TestAddTagStopsAtTheCap(t *testing.T) {
	a, err := NewAsset("api.example.com", AssetTypeDomain, CriticalityMedium)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < MaxTagsPerAsset+10; i++ {
		a.AddTag(fmt.Sprintf("tag-%d", i))
	}
	if got := len(a.Tags()); got != MaxTagsPerAsset {
		t.Fatalf("asset has %d tags, want the cap %d", got, MaxTagsPerAsset)
	}

	// Removing one makes room again.
	a.RemoveTag("tag-0")
	a.AddTag("late")
	if got := len(a.Tags()); got != MaxTagsPerAsset {
		t.Fatalf("after remove+add: %d tags, want %d", got, MaxTagsPerAsset)
	}
}

func TestTagCapIsFifty(t *testing.T) {
	// Owner decision D5 (2026-10): one cap of 50 everywhere.
	if MaxTagsPerAsset != 50 {
		t.Fatalf("MaxTagsPerAsset = %d, want 50", MaxTagsPerAsset)
	}
}
