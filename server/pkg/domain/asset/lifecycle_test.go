package asset

import (
	"testing"
	"time"
)

func TestAsset_MarkSeen_AutoReactivatesFromStale(t *testing.T) {
	// The E4.4 race insurance: a fresh MarkSeen() must never leave
	// an asset stuck in stale. If the worker and ingest race on the
	// same asset, the "last writer" reverts stale to active.
	a, err := NewAsset("example.com", AssetTypeDomain, CriticalityMedium)
	if err != nil {
		t.Fatal(err)
	}
	a.MarkStale()
	if a.Status() != StatusStale {
		t.Fatalf("setup failed, status = %v", a.Status())
	}

	a.MarkSeen()
	if a.Status() != StatusActive {
		t.Errorf("expected auto-reactivate to Active, got %v", a.Status())
	}
	if a.LifecyclePausedUntil() != nil {
		t.Errorf("reactivation must clear any snooze, got %v", a.LifecyclePausedUntil())
	}
}

func TestAsset_MarkSeen_AutoReactivatesFromInactive(t *testing.T) {
	a, err := NewAsset("example.com", AssetTypeDomain, CriticalityMedium)
	if err != nil {
		t.Fatal(err)
	}
	a.Deactivate()
	a.MarkSeen()
	if a.Status() != StatusActive {
		t.Errorf("expected Active after MarkSeen, got %v", a.Status())
	}
}

func TestAsset_MarkSeen_RespectsManualOverride(t *testing.T) {
	// Operator took manual control → worker and ingest reactivation
	// both defer to the operator's chosen status.
	a, err := NewAsset("example.com", AssetTypeDomain, CriticalityMedium)
	if err != nil {
		t.Fatal(err)
	}
	a.MarkStale()
	a.SetManualStatusOverride(true)
	a.MarkSeen()
	if a.Status() != StatusStale {
		t.Errorf("manual override bypassed, status = %v", a.Status())
	}
}

func TestAsset_MarkSeen_NeverReactivatesArchived(t *testing.T) {
	// Archived is a terminal state — only a manual Activate() call
	// can un-archive. A scanner re-seeing an archived asset should
	// not silently bring it back into active rotation.
	a, err := NewAsset("example.com", AssetTypeDomain, CriticalityMedium)
	if err != nil {
		t.Fatal(err)
	}
	a.Archive()
	a.MarkSeen()
	if a.Status() != StatusArchived {
		t.Errorf("archived must not auto-reactivate, status = %v", a.Status())
	}
}

func TestAsset_MarkStale_OnlyTransitionsFromActive(t *testing.T) {
	a, err := NewAsset("example.com", AssetTypeDomain, CriticalityMedium)
	if err != nil {
		t.Fatal(err)
	}
	if !a.MarkStale() {
		t.Fatal("expected MarkStale to transition from Active")
	}
	// Calling again is a no-op — idempotent.
	if a.MarkStale() {
		t.Error("second MarkStale should return false")
	}
}

func TestAsset_MarkStale_RefusesManualOverride(t *testing.T) {
	a, err := NewAsset("example.com", AssetTypeDomain, CriticalityMedium)
	if err != nil {
		t.Fatal(err)
	}
	a.SetManualStatusOverride(true)
	if a.MarkStale() {
		t.Error("MarkStale must refuse when manual override is true")
	}
	if a.Status() != StatusActive {
		t.Errorf("status should stay Active, got %v", a.Status())
	}
}

func TestAsset_SnoozeLifecycle(t *testing.T) {
	a, err := NewAsset("example.com", AssetTypeDomain, CriticalityMedium)
	if err != nil {
		t.Fatal(err)
	}

	a.SnoozeLifecycle(30 * 24 * time.Hour)
	if p := a.LifecyclePausedUntil(); p == nil || !p.After(time.Now()) {
		t.Errorf("expected paused_until in future, got %v", p)
	}
	if !a.IsLifecyclePaused(time.Now()) {
		t.Error("IsLifecyclePaused should be true")
	}
	if a.IsLifecyclePaused(time.Now().Add(60 * 24 * time.Hour)) {
		t.Error("IsLifecyclePaused should be false 60 days from now")
	}

	// Zero/negative duration clears the snooze.
	a.SnoozeLifecycle(0)
	if a.LifecyclePausedUntil() != nil {
		t.Errorf("duration 0 should clear snooze, got %v", a.LifecyclePausedUntil())
	}
}

func TestAsset_MarkSeen_UsesServerTime(t *testing.T) {
	// Clock-skew defense: MarkSeen must always set last_seen to
	// server time, never trust an externally-supplied timestamp.
	// Callers that bypass this would be able to keep an asset
	// "forever fresh" by sending MarkSeen with future timestamps.
	a, err := NewAsset("example.com", AssetTypeDomain, CriticalityMedium)
	if err != nil {
		t.Fatal(err)
	}
	before := time.Now().UTC()
	a.MarkSeen()
	after := time.Now().UTC()

	// Asset's lastSeen must be between before and after (plus a
	// small tolerance for comparison granularity).
	if a.LastSeen().Before(before) || a.LastSeen().After(after.Add(time.Second)) {
		t.Errorf("last_seen not in expected window: got %v, range [%v, %v]",
			a.LastSeen(), before, after)
	}
}
