package tenant

import (
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestClosureSettings_ValidateAndEffectiveMode(t *testing.T) {
	for _, m := range []ClosingMode{"", ClosingModeAuto, ClosingModeReview, ClosingModeOff} {
		if err := (ClosureSettings{Mode: m}).Validate(); err != nil {
			t.Errorf("mode %q: %v", m, err)
		}
	}
	if err := (ClosureSettings{Mode: "enforce"}).Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("unknown mode: err = %v", err)
	}
	if got := (ClosureSettings{}).EffectiveMode(); got != ClosingModeReview {
		t.Fatalf("unset mode = %q, want review", got)
	}
}

func TestClosureSettings_Loosens(t *testing.T) {
	off, review, auto := ClosureSettings{Mode: ClosingModeOff}, ClosureSettings{}, ClosureSettings{Mode: ClosingModeAuto}
	autoCrit := ClosureSettings{Mode: ClosingModeAuto, CriticalAutoClose: true}
	cases := []struct {
		name       string
		from, to   ClosureSettings
		wantLooser bool
	}{
		{"off to review", off, review, true},
		{"off to auto", off, auto, true},
		{"review to auto", review, auto, true},
		{"critical out of review", auto, autoCrit, true},
		{"critical flag set while going to off", off, ClosureSettings{Mode: ClosingModeOff, CriticalAutoClose: true}, true},
		{"auto to review", auto, review, false},
		{"review to off", review, off, false},
		{"critical back to review", autoCrit, auto, false},
		{"unchanged", auto, auto, false},
		{"explicit review equals unset", ClosureSettings{Mode: ClosingModeReview}, review, false},
	}
	for _, c := range cases {
		if got := c.from.Loosens(c.to); got != c.wantLooser {
			t.Errorf("%s: Loosens = %v, want %v", c.name, got, c.wantLooser)
		}
	}
}

// A new organization starts in auto; one whose settings carry no closure
// section (created before) reads as review.
func TestClosureSettings_Defaults(t *testing.T) {
	nt, err := NewTenant("Acme", "acme", "user-1")
	if err != nil {
		t.Fatal(err)
	}
	if got := nt.TypedSettings().Closure.EffectiveMode(); got != ClosingModeAuto {
		t.Fatalf("new organization mode = %q, want auto", got)
	}
	if nt.TypedSettings().Closure.CriticalAutoClose {
		t.Fatal("new organization must keep critical findings in review")
	}
	old, _ := SettingsFromMapChecked(map[string]any{"general": map[string]any{"timezone": "UTC"}})
	if got := old.Closure.EffectiveMode(); got != ClosingModeReview {
		t.Fatalf("existing organization mode = %q, want review", got)
	}
	if got := DefaultSettings().Closure.EffectiveMode(); got != ClosingModeReview {
		t.Fatalf("empty settings mode = %q, want review", got)
	}
	if err := nt.UpdateClosureSettings(ClosureSettings{Mode: "bogus"}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("UpdateClosureSettings accepted a bad mode: %v", err)
	}
}
