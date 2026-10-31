package tenant

import (
	"testing"

	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

func TestLifecycleLoosened(t *testing.T) {
	on := tenantdom.DefaultAssetLifecycleSettings()
	on.Enabled = true
	with := func(f func(*tenantdom.AssetLifecycleSettings)) tenantdom.AssetLifecycleSettings {
		s := on
		s.ExcludedSourceTypes = append([]string(nil), on.ExcludedSourceTypes...)
		f(&s)
		return s
	}
	cases := []struct {
		name          string
		before, after tenantdom.AssetLifecycleSettings
		want          bool
	}{
		{"turn on", tenantdom.DefaultAssetLifecycleSettings(), on, true},
		{"turn off", on, tenantdom.DefaultAssetLifecycleSettings(), false},
		{"same", on, on, false},
		{"shorter stale threshold", on, with(func(s *tenantdom.AssetLifecycleSettings) { s.StaleThresholdDays = 7 }), true},
		{"longer stale threshold", on, with(func(s *tenantdom.AssetLifecycleSettings) { s.StaleThresholdDays = 60 }), false},
		{"shorter grace", on, with(func(s *tenantdom.AssetLifecycleSettings) { s.GracePeriodDays = 0 }), true},
		{"unhealthy integration no longer pauses", on, with(func(s *tenantdom.AssetLifecycleSettings) { s.PauseOnIntegrationFailure = false }), true},
		{"pause turned on", with(func(s *tenantdom.AssetLifecycleSettings) { s.PauseOnIntegrationFailure = false }), on, false},
		{"fewer excluded sources", on, with(func(s *tenantdom.AssetLifecycleSettings) { s.ExcludedSourceTypes = []string{"manual"} }), true},
		{"more excluded sources", on, with(func(s *tenantdom.AssetLifecycleSettings) {
			s.ExcludedSourceTypes = []string{"manual", "import", "scanner"}
		}), false},
		{"default written out", on, with(func(s *tenantdom.AssetLifecycleSettings) { s.StaleThresholdDays = 14 }), false},
	}
	for _, c := range cases {
		if got := lifecycleLoosened(c.before, c.after); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestCycleLoosened(t *testing.T) {
	on, off := tenantdom.CycleSettings{EnforceCoverageSLO: true}, tenantdom.CycleSettings{}
	if !cycleLoosened(on, off) || cycleLoosened(off, on) || cycleLoosened(on, on) || cycleLoosened(off, off) {
		t.Fatal("only turning the coverage requirement off loosens")
	}
}

func TestEASMLoosened(t *testing.T) {
	base := tenantdom.EASMSettings{}
	cases := []struct {
		name          string
		before, after tenantdom.EASMSettings
		want          bool
	}{
		{"same", base, base, false},
		{"ct off", base, tenantdom.EASMSettings{CTDisabled: true}, true},
		{"ct on again", tenantdom.EASMSettings{CTDisabled: true}, base, false},
		{"dns checks off", base, tenantdom.EASMSettings{DNSChecksDisabled: true}, true},
		{"enrichment off", base, tenantdom.EASMSettings{EnrichmentDisabled: true}, true},
		{"digest off", base, tenantdom.EASMSettings{WeeklyDigestDisabled: true}, true},
		{"screenshots on", base, tenantdom.EASMSettings{WebScreenshotsEnabled: true}, true},
		{"screenshots off", tenantdom.EASMSettings{WebScreenshotsEnabled: true}, base, false},
		{"longer interval", tenantdom.EASMSettings{CTIntervalHours: 12}, tenantdom.EASMSettings{CTIntervalHours: 48}, true},
		{"shorter interval", tenantdom.EASMSettings{DNSIntervalHours: 48}, tenantdom.EASMSettings{DNSIntervalHours: 12}, false},
		{"default to longer", base, tenantdom.EASMSettings{DNSIntervalHours: 72}, true},
		{"default to shorter", base, tenantdom.EASMSettings{DNSIntervalHours: 6}, false},
		{"longer reappear window", tenantdom.EASMSettings{ReappearAfterDays: 14}, tenantdom.EASMSettings{ReappearAfterDays: 90}, true},
		{"digest weekday only", base, tenantdom.EASMSettings{DigestWeekday: 3}, false},
	}
	for _, c := range cases {
		if got := easmLoosened(c.before, c.after); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}
