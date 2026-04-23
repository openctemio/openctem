package tenant

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

func TestAssetLifecycleSettings_Defaults(t *testing.T) {
	d := DefaultAssetLifecycleSettings()
	// Pin values — if anyone changes these they have to update the
	// test, forcing the decision to be conscious. Changing a default
	// silently changes behavior for every tenant on next upgrade.
	if d.Enabled {
		t.Error("default must be disabled (backward-compat)")
	}
	if d.StaleThresholdDays != 14 {
		t.Errorf("default StaleThresholdDays = %d, want 14", d.StaleThresholdDays)
	}
	if d.GracePeriodDays != 3 {
		t.Errorf("default GracePeriodDays = %d, want 3", d.GracePeriodDays)
	}
	if d.ManualReactivationGraceDays != 30 {
		t.Errorf("default ManualReactivationGraceDays = %d, want 30", d.ManualReactivationGraceDays)
	}
	if !d.PauseOnIntegrationFailure {
		t.Error("default PauseOnIntegrationFailure must be true — safer default")
	}
	if len(d.ExcludedSourceTypes) != 2 {
		t.Errorf("default excluded types should be [manual, import], got %v", d.ExcludedSourceTypes)
	}
}

func TestAssetLifecycleSettings_Effective_ZeroFallsBackToDefault(t *testing.T) {
	// Legacy rows may have been persisted with zero-valued fields
	// before the defaults existed. Effective*() must paper over this
	// so callers never see a nonsensical 0.
	var s AssetLifecycleSettings
	if got := s.EffectiveStaleThresholdDays(); got != 14 {
		t.Errorf("effective = %d, want 14", got)
	}
	if got := s.EffectiveManualReactivationGraceDays(); got != 30 {
		t.Errorf("effective = %d, want 30", got)
	}
	if got := s.EffectiveExcludedSourceTypes(); len(got) != 2 {
		t.Errorf("effective = %v, want default pair", got)
	}
}

func TestAssetLifecycleSettings_Effective_ExplicitZeroGraceRespected(t *testing.T) {
	// "Grace 0" is a legitimate configuration (operator wants no
	// grace period) and must NOT be overridden by the default. Only
	// the < 0 "uninitialized" case falls back.
	s := AssetLifecycleSettings{GracePeriodDays: 0}
	if got := s.EffectiveGracePeriodDays(); got != 0 {
		t.Errorf("explicit zero grace overridden to %d", got)
	}
}

func TestAssetLifecycleSettings_Validate_Ranges(t *testing.T) {
	cases := []struct {
		name    string
		s       AssetLifecycleSettings
		wantErr bool
	}{
		{"zero is valid", AssetLifecycleSettings{}, false},
		{"threshold below min", AssetLifecycleSettings{StaleThresholdDays: 1}, true},
		{"threshold at min", AssetLifecycleSettings{StaleThresholdDays: 3}, false},
		{"threshold above max", AssetLifecycleSettings{StaleThresholdDays: 400}, true},
		{"threshold at max", AssetLifecycleSettings{StaleThresholdDays: 365}, false},
		{"grace negative", AssetLifecycleSettings{GracePeriodDays: -1}, true},
		{"grace above max", AssetLifecycleSettings{GracePeriodDays: 91}, true},
		{"grace at max", AssetLifecycleSettings{GracePeriodDays: 90}, false},
		{"reactivation grace below min", AssetLifecycleSettings{ManualReactivationGraceDays: 1}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.s.Validate()
			if tc.wantErr && err == nil {
				t.Fatal("expected validation error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if err != nil && !errors.Is(err, shared.ErrValidation) {
				t.Errorf("expected ErrValidation wrap, got %v", err)
			}
		})
	}
}

func TestAssetLifecycleSettings_Validate_ExcludedSourceTypes(t *testing.T) {
	cases := []struct {
		name    string
		types   []string
		wantErr bool
	}{
		{"nil is OK", nil, false},
		{"defaults OK", []string{"manual", "import"}, false},
		{"empty string rejected", []string{""}, true},
		{"unknown source type rejected", []string{"nessus"}, true},
		{"duplicate rejected", []string{"manual", "manual"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := AssetLifecycleSettings{ExcludedSourceTypes: tc.types}
			err := s.Validate()
			if tc.wantErr && err == nil {
				t.Fatal("expected validation error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestAssetLifecycleSettings_Validate_EnableRequiresDryRun(t *testing.T) {
	// The first-enable gate: admin cannot flip Enabled=true unless
	// they have completed a dry-run. Prevents the pathological
	// "enable on 2-year-old tenant → 1M assets go stale overnight"
	// scenario. Service layer stamps DryRunCompletedAt after a
	// successful dry-run.
	s := AssetLifecycleSettings{Enabled: true}
	if err := s.Validate(); err == nil {
		t.Fatal("enable without DryRunCompletedAt must fail")
	} else if !strings.Contains(err.Error(), "dry-run") {
		t.Errorf("error should mention dry-run: %v", err)
	}

	ts := time.Now().Unix()
	s.DryRunCompletedAt = &ts
	if err := s.Validate(); err != nil {
		t.Errorf("enable with DryRunCompletedAt should pass, got %v", err)
	}
}

func TestAssetLifecycleSettings_Validate_ErrorsAreErrValidation(t *testing.T) {
	// Every failure mode must wrap shared.ErrValidation so HTTP
	// handlers can classify as 400 without string-matching the
	// message.
	cases := []AssetLifecycleSettings{
		{StaleThresholdDays: 1},
		{GracePeriodDays: 200},
		{ExcludedSourceTypes: []string{"unknown-type"}},
		{Enabled: true}, // missing dry-run
	}
	for i, s := range cases {
		if err := s.Validate(); err == nil {
			t.Errorf("case %d: expected error", i)
		} else if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("case %d: not ErrValidation: %v", i, err)
		}
	}
}
