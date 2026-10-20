package tenant

import (
	"testing"
	"time"
)

// AI triage is off until an organization administrator opts in, whatever
// the stored mode says.
func TestAISettings_EffectiveMode(t *testing.T) {
	var s AISettings
	if s.EffectiveMode() != AIModeDisabled || s.OptedIn() {
		t.Fatalf("zero settings: %s, want disabled", s.EffectiveMode())
	}
	s.Mode = AIModePlatform
	if s.EffectiveMode() != AIModeDisabled {
		t.Fatalf("platform mode without consent: %s, want disabled", s.EffectiveMode())
	}
	s.Mode = ""
	s.SetOptIn(true, "admin-id", time.Now())
	if s.EffectiveMode() != AIModePlatform || s.EnabledBy != "admin-id" || s.EnabledAt.Location() != time.UTC {
		t.Fatalf("opted in, no mode: %s by %q at %v", s.EffectiveMode(), s.EnabledBy, s.EnabledAt)
	}
	s.Mode = AIModeBYOK
	if s.EffectiveMode() != AIModeBYOK {
		t.Fatalf("opted in byok: %s", s.EffectiveMode())
	}
	s.Mode = AIModeDisabled
	if s.EffectiveMode() != AIModeDisabled {
		t.Fatalf("opted in but disabled: %s", s.EffectiveMode())
	}
	s.SetOptIn(false, "ignored", time.Now())
	if s.OptedIn() || s.EnabledBy != "" {
		t.Fatalf("withdrawn: %+v", s)
	}
}
