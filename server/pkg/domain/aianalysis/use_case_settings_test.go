package aianalysis

import (
	"errors"
	"math"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestUseCaseSetting_DefaultsAndValidate(t *testing.T) {
	d := DefaultUseCaseSetting()
	if d.Mode != UseCaseSuggest || d.Ceiling != DataClassInternal || d.MinConfidence != 0.85 {
		t.Fatalf("default: %+v", d)
	}
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := []UseCaseSetting{
		{Mode: "always", Ceiling: DataClassInternal, MinConfidence: 0.85},
		{Mode: UseCaseSuggest, Ceiling: DataClassTenantOnly, MinConfidence: 0.85},
		{Mode: UseCaseSuggest, Ceiling: "secret", MinConfidence: 0.85},
		{Mode: UseCaseSuggest, Ceiling: DataClassInternal, MinConfidence: 0.49},
		{Mode: UseCaseSuggest, Ceiling: DataClassInternal, MinConfidence: 1},
		{Mode: UseCaseSuggest, Ceiling: DataClassInternal, MinConfidence: math.NaN()},
	}
	for _, s := range bad {
		if err := s.Validate(); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("%+v must be invalid, got %v", s, err)
		}
	}
}

// A stored value that does not read is replaced by the safe default.
func TestUseCasePolicy_ForFailsClosed(t *testing.T) {
	p := UseCasePolicy{UseCaseTriage: {Mode: "garbage", Ceiling: DataClassTenantOnly, MinConfidence: 0.1}}
	got := p.For(UseCaseTriage)
	if got.Mode != UseCaseSuggest || got.Ceiling != DataClassInternal || got.MinConfidence != DefaultMinConfidence {
		t.Fatalf("normalized: %+v", got)
	}
	if p.For(UseCaseSummary) != DefaultUseCaseSetting() {
		t.Fatal("an unsaved use case has the default")
	}
}

func TestUseCaseSetting_EffectiveCeilingAndMayApply(t *testing.T) {
	s := DefaultUseCaseSetting()
	if s.EffectiveCeiling(DataClassRestricted) != DataClassInternal {
		t.Fatal("the lower ceiling wins (use case)")
	}
	s.Ceiling = DataClassRestricted
	if s.EffectiveCeiling(DataClassPublic) != DataClassPublic {
		t.Fatal("the lower ceiling wins (AI agent)")
	}
	if s.MayApply(0.99) {
		t.Fatal("suggest never applies")
	}
	s.Mode = UseCaseAutoApply
	if !s.MayApply(0.85) || s.MayApply(0.84) || s.MayApply(math.NaN()) {
		t.Fatal("auto-apply applies at or above the minimum only")
	}
}

func TestUseCaseLoosened(t *testing.T) {
	sug := DefaultUseCaseSetting()
	auto := sug
	auto.Mode = UseCaseAutoApply
	restricted := sug
	restricted.Ceiling = DataClassRestricted
	lowerConf := auto
	lowerConf.MinConfidence = 0.6
	off := sug
	off.Mode = UseCaseOff
	public := sug
	public.Ceiling = DataClassPublic

	cases := []struct {
		name          string
		before, after UseCaseSetting
		want          []string
	}{
		{"auto-apply on", sug, auto, []string{LoosenAutoApplyOn}},
		{"ceiling above internal", sug, restricted, []string{LoosenCeilingRaised}},
		{"ceiling public to internal is not above internal", public, sug, nil},
		{"lower confidence while auto", auto, lowerConf, []string{LoosenConfidenceLower}},
		{"turning off", auto, off, nil},
		{"auto to suggest", auto, sug, nil},
		{"lowering the ceiling", restricted, sug, nil},
		{"lower confidence in suggest", sug, func() UseCaseSetting { x := sug; x.MinConfidence = 0.5; return x }(), nil},
	}
	for _, tc := range cases {
		got := UseCaseLoosened(tc.before, tc.after)
		if len(got) != len(tc.want) {
			t.Fatalf("%s: got %v want %v", tc.name, got, tc.want)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Fatalf("%s: got %v want %v", tc.name, got, tc.want)
			}
		}
	}
}

func TestOverrideStats_ShouldDowngrade(t *testing.T) {
	cases := []struct {
		s    OverrideStats
		want bool
	}{
		{OverrideStats{Decisions: 9, Overrides: 9}, false}, // too few decisions
		{OverrideStats{Decisions: 10, Overrides: 1}, false},
		{OverrideStats{Decisions: 10, Overrides: 2}, true}, // 20 percent
		{OverrideStats{Decisions: 50, Overrides: 9}, false},
		{OverrideStats{Decisions: 50, Overrides: 10}, true},
	}
	for _, tc := range cases {
		if got := tc.s.ShouldDowngrade(); got != tc.want {
			t.Fatalf("%+v: got %v", tc.s, got)
		}
	}
}
