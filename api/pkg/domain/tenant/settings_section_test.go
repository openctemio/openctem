package tenant

import (
	"errors"
	"testing"
)

func TestSettingsFromMapChecked_CorruptSectionIsIsolated(t *testing.T) {
	m := map[string]any{
		"security": map[string]any{"mfa_required": "yes", "ip_whitelist": []any{"10.0.0.0/8"}},
		"general":  map[string]any{"website": "https://example.com"},
	}
	s, errs := SettingsFromMapChecked(m)
	if !errors.Is(errs[SectionSecurity], ErrSettingsSectionCorrupt) {
		t.Fatalf("security error = %v, want ErrSettingsSectionCorrupt", errs[SectionSecurity])
	}
	if len(errs) != 1 {
		t.Fatalf("errs = %v, want only security", errs)
	}
	if s.General.Website != "https://example.com" {
		t.Fatalf("general not decoded: %+v", s.General)
	}
	// The corrupt section falls back to its default, not a half-decoded value.
	if len(s.Security.IPWhitelist) != 0 || s.Security.MFARequired {
		t.Fatalf("corrupt security section partially decoded: %+v", s.Security)
	}
}

func TestSettingsFromMap_MatchesWholeBlobDecode(t *testing.T) {
	if got := SettingsFromMap(nil); got.Security.SessionTimeoutMin != DefaultSettings().Security.SessionTimeoutMin {
		t.Fatalf("empty blob must give DefaultSettings")
	}
	s := SettingsFromMap(map[string]any{"general": map[string]any{"timezone": "UTC"}})
	if s.RiskScoring.Preset != LegacyRiskScoringSettings().Preset {
		t.Fatalf("absent risk_scoring must use the legacy formula, got %+v", s.RiskScoring.Preset)
	}
	if s.Security.SessionTimeoutMin != 0 {
		t.Fatalf("absent section must keep its zero value (as the whole-blob decode did), got %d", s.Security.SessionTimeoutMin)
	}
}

func TestSecuritySettingsStrict(t *testing.T) {
	tn := &Tenant{settings: map[string]any{"security": map[string]any{"mfa_required": true}}}
	sec, err := tn.SecuritySettingsStrict()
	if err != nil || !sec.MFARequired {
		t.Fatalf("readable section: sec=%+v err=%v", sec, err)
	}
	tn = &Tenant{settings: map[string]any{"security": "not an object"}}
	if _, err := tn.SecuritySettingsStrict(); !errors.Is(err, ErrSettingsSectionCorrupt) {
		t.Fatalf("corrupt section: err = %v, want ErrSettingsSectionCorrupt", err)
	}
}

func TestSectionETag(t *testing.T) {
	a := SectionETag(map[string]any{"a": 1, "b": []any{"x"}})
	b := SectionETag(map[string]any{"b": []any{"x"}, "a": 1})
	if a != b {
		t.Fatalf("ETag depends on key order: %s vs %s", a, b)
	}
	if a == SectionETag(map[string]any{"a": 2, "b": []any{"x"}}) {
		t.Fatalf("different content, same ETag")
	}
	if nilTag := SectionETag(nil); nilTag != SectionETag(nil) || nilTag == a {
		t.Fatalf("absent-section ETag is not stable or collides")
	}
	for _, ifMatch := range []string{a, "W/" + a, a[1 : len(a)-1], `"other", ` + a, "*"} {
		if !ETagMatches(ifMatch, a) {
			t.Errorf("ETagMatches(%q) = false", ifMatch)
		}
	}
	if ETagMatches(`"nope"`, a) {
		t.Errorf("ETagMatches matched a different tag")
	}
}

func TestIsSettingsSection(t *testing.T) {
	for _, k := range []string{SectionSecurity, SectionGeneral, SectionAssetIdentity, SectionRetest} {
		if !IsSettingsSection(k) {
			t.Errorf("%s should be a section", k)
		}
	}
	for _, k := range []string{"subscribed_bundles", "", "security; drop"} {
		if IsSettingsSection(k) {
			t.Errorf("%q must not be a section", k)
		}
	}
}
