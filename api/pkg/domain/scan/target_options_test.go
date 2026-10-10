package scan

import (
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestTargetOptions_Validate(t *testing.T) {
	for _, tc := range []struct {
		name string
		o    TargetOptions
		ok   bool
	}{
		{"zero", TargetOptions{}, true},
		{"sweep", TargetOptions{CIDRMode: CIDRModeSweep}, true},
		{"inventory", TargetOptions{CIDRMode: CIDRModeInventory, SeenWithinDays: 30, IncludeStale: true}, true},
		{"max window", TargetOptions{SeenWithinDays: MaxSeenWithinDays}, true},
		{"unknown mode", TargetOptions{CIDRMode: "all"}, false},
		{"negative window", TargetOptions{SeenWithinDays: -1}, false},
		{"window too long", TargetOptions{SeenWithinDays: MaxSeenWithinDays + 1}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.o.Validate()
			if (err == nil) != tc.ok {
				t.Fatalf("Validate() = %v, want ok=%v", err, tc.ok)
			}
			if err != nil && !errors.Is(err, shared.ErrValidation) {
				t.Errorf("error %v is not a validation error", err)
			}
		})
	}
}

func TestTargetOptions_DefaultsAndSetter(t *testing.T) {
	if (TargetOptions{}).EffectiveCIDRMode() != CIDRModeSweep || !(TargetOptions{}).IsZero() {
		t.Error("the zero value must sweep and be the default")
	}
	s := &Scan{}
	if err := s.SetTargetOptions(TargetOptions{CIDRMode: CIDRModeSweep}); err != nil {
		t.Fatal(err)
	}
	if s.TargetOptions.CIDRMode != "" {
		t.Errorf("sweep stored as %q, want the default (empty)", s.TargetOptions.CIDRMode)
	}
	if err := s.SetTargetOptions(TargetOptions{CIDRMode: "x"}); err == nil || s.TargetOptions.CIDRMode != "" {
		t.Error("an invalid option was stored")
	}
}
