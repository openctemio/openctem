package asset

import (
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestClassifyObservation(t *testing.T) {
	t0 := time.Date(2026, 10, 10, 8, 0, 0, 0, time.UTC)
	stored := &AttributeObservation{Value: "public", ObservedAt: t0}
	in := func(value string, at time.Time) AttributeObservation {
		return AttributeObservation{Value: value, ObservedAt: at}
	}
	tests := []struct {
		name   string
		stored *AttributeObservation
		in     AttributeObservation
		want   ObservationVerdict
	}{
		{"first observation of the source", nil, in("public", t0), ObservationNew},
		{"newer, different value", stored, in("private", t0.Add(time.Second)), ObservationChanged},
		{"older report delivered late", stored, in("private", t0.Add(-time.Hour)), ObservationOutOfOrder},
		{"older report with the same value", stored, in("public", t0.Add(-time.Hour)), ObservationOutOfOrder},
		{"replayed report (same time, same value)", stored, in("public", t0), ObservationReplay},
		{"same time, different value cannot be ordered", stored, in("private", t0), ObservationReplay},
		{"re-sighting within the refresh interval writes nothing", stored, in("public", t0.Add(59*time.Minute)), ObservationResighted},
		{"re-sighting after the refresh interval refreshes", stored, in("public", t0.Add(time.Hour)), ObservationRefresh},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyObservation(tc.stored, tc.in, ResightingRefreshInterval)
			if got != tc.want {
				t.Fatalf("verdict = %s, want %s", got, tc.want)
			}
			if got.Accepted() == got.Rejected() && got != ObservationResighted {
				t.Fatalf("%s is both or neither accepted and rejected", got)
			}
		})
	}
}

func TestChangeEventCoalesces(t *testing.T) {
	now := time.Date(2026, 10, 10, 8, 0, 0, 0, time.UTC)
	asset := shared.NewID()
	ev := func(old, new string, flaps int, created time.Time) *ChangeEvent {
		return &ChangeEvent{AssetID: asset, Attribute: "exposure", Old: old, New: new, FlapCount: flaps, CreatedAt: created, Reason: ChangeReasonNewerObservation}
	}
	next := func(old, new string) ChangeEvent { return *ev(old, new, 1, now) }
	tests := []struct {
		name   string
		latest *ChangeEvent
		next   ChangeEvent
		want   bool
	}{
		{"no previous event", nil, next("a", "b"), false},
		{"A->B then B->A within the window folds", ev("a", "b", 1, now.Add(-10*time.Minute)), next("b", "a"), true},
		{"a flapping event keeps folding", ev("a", "a", 2, now.Add(-30*time.Minute)), next("a", "b"), true},
		{"A->B then B->C is a real change", ev("a", "b", 1, now.Add(-time.Minute)), next("b", "c"), false},
		{"outside the window starts a new event", ev("a", "b", 1, now.Add(-2*time.Hour)), next("b", "a"), false},
		{"a broken chain (latest ended elsewhere) does not fold", ev("a", "b", 1, now.Add(-time.Minute)), next("c", "a"), false},
		{"a source-only change (same value) never folds", ev("a", "b", 1, now.Add(-time.Minute)), next("b", "b"), false},
		{"another attribute never folds", &ChangeEvent{AssetID: asset, Attribute: "criticality", Old: "a", New: "b", FlapCount: 1, CreatedAt: now}, next("b", "a"), false},
		{"a person's lock never folds", &ChangeEvent{AssetID: asset, Attribute: "exposure", Old: "a", New: "b", Reason: ChangeReasonManualLock, FlapCount: 1, CreatedAt: now}, next("b", "a"), false},
		{"a TTL expiry is its own entry", ev("a", "b", 1, now.Add(-time.Minute)), ChangeEvent{AssetID: asset, Attribute: "exposure", Old: "b", New: "a", Reason: ChangeReasonTTLExpiry, CreatedAt: now}, false},
		{"set changes keep their diff", &ChangeEvent{AssetID: asset, Attribute: "exposure", Old: "a", New: "b", Added: []string{"x"}, FlapCount: 1, CreatedAt: now}, next("b", "a"), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.latest.Coalesces(tc.next, now); got != tc.want {
				t.Fatalf("Coalesces = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestChangeReasonIsValid(t *testing.T) {
	for _, r := range []ChangeReason{ChangeReasonNewerObservation, ChangeReasonManualLock, ChangeReasonLockReleased,
		ChangeReasonTTLExpiry, ChangeReasonPolicyChange, ChangeReasonSourceRemoved} {
		if !r.IsValid() {
			t.Errorf("%s should be valid", r)
		}
	}
	if ChangeReason("").IsValid() || ChangeReason("other").IsValid() {
		t.Error("unknown reasons must be invalid")
	}
}
