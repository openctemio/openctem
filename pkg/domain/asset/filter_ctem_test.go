package asset

import (
	"testing"
	"time"
)

// TestFilter_IsEmpty_CTEMDimensions ensures every CTEM inventory dimension is
// accounted for in IsEmpty — a field left out of IsEmpty is a silent bug (the
// filter would read as "empty" and callers may skip applying it).
func TestFilter_IsEmpty_CTEMDimensions(t *testing.T) {
	if !NewFilter().IsEmpty() {
		t.Fatal("a fresh filter must be empty")
	}

	cases := map[string]Filter{
		"business_unit_ids":      NewFilter().WithBusinessUnitIDs("bu"),
		"has_owner":              NewFilter().WithHasOwner(true),
		"data_classifications":   NewFilter().WithDataClassifications("secret"),
		"is_control_plane":       NewFilter().WithIsControlPlane(true),
		"is_internet_accessible": NewFilter().WithIsInternetAccessible(true),
		"environments":           NewFilter().WithEnvironments("production"),
		"last_seen_after":        NewFilter().WithLastSeenAfter(time.Now()),
		"last_seen_before":       NewFilter().WithLastSeenBefore(time.Now()),
	}
	for name, f := range cases {
		if f.IsEmpty() {
			t.Errorf("filter with %s set must not be empty", name)
		}
	}
}
