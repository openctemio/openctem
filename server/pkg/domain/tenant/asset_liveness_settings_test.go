package tenant

import (
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/liveness"
)

func TestAssetLivenessSettingsFloors(t *testing.T) {
	bad := []AssetLivenessSettings{
		{UnreachableAttempts: 1},
		{UnreachableWindowHours: 1},
		{GoneAttempts: 2},
		{GoneWindowHours: 12},
		{GoneSingleObserverWindowHours: 24},
		{GoneWindowHours: 200, GoneSingleObserverWindowHours: 100},
		{MaxGonePerDay: 100000},
	}
	for _, s := range bad {
		if err := s.Validate(); err == nil {
			t.Errorf("%+v: accepted, want refused", s)
		}
	}
	if err := (AssetLivenessSettings{GoneAttempts: 3, GoneWindowHours: 24, GoneSingleObserverWindowHours: 72}).Validate(); err != nil {
		t.Fatalf("floors refused: %v", err)
	}
	// The lifecycle validator checks the nested settings.
	al := AssetLifecycleSettings{Liveness: &AssetLivenessSettings{GoneAttempts: 1}}
	if err := al.Validate(); err == nil {
		t.Fatal("lifecycle settings accepted a liveness value under its floor")
	}
}

func TestAssetLivenessThresholds(t *testing.T) {
	if got := (AssetLivenessSettings{}).Thresholds(); got != liveness.DefaultThresholds().Floored() {
		t.Fatalf("defaults: %+v", got)
	}
	got := AssetLivenessSettings{GoneAttempts: 5, GoneWindowHours: 96}.Thresholds()
	if got.GoneAttempts != 5 || got.GoneWindow.Hours() != 96 {
		t.Fatalf("custom: %+v", got)
	}
}

func TestLivenessLoosened(t *testing.T) {
	on := AssetLivenessSettings{CloseFindingsWhenGone: true}
	cases := []struct {
		name          string
		before, after AssetLivenessSettings
		want          bool
	}{
		{"closing turned on", AssetLivenessSettings{}, on, true},
		{"closing turned off", on, AssetLivenessSettings{}, false},
		{"unchanged", on, on, false},
		{"fewer attempts", AssetLivenessSettings{CloseFindingsWhenGone: true, GoneAttempts: 5}, on, true},
		{"longer window", on, AssetLivenessSettings{CloseFindingsWhenGone: true, GoneWindowHours: 120}, false},
		{"higher daily bound", on, AssetLivenessSettings{CloseFindingsWhenGone: true, MaxGonePerDay: 500}, true},
		{"thresholds lowered while closing is off", AssetLivenessSettings{GoneAttempts: 5}, AssetLivenessSettings{}, false},
	}
	for _, c := range cases {
		if got := LivenessLoosened(c.before, c.after); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}
