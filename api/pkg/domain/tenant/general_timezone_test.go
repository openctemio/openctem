package tenant

import "testing"

// The organization's time zone is any IANA zone: it sets alert quiet hours,
// the digest hour and scan approval clocks, which load it the same way.
func TestGeneralSettingsTimezoneAcceptsIANAZones(t *testing.T) {
	for _, tz := range []string{"UTC", "Europe/Berlin", "America/Argentina/Buenos_Aires", "Asia/Kolkata", "Pacific/Chatham", "Africa/Lagos"} {
		g := GeneralSettings{Timezone: tz}
		if err := g.Validate(); err != nil {
			t.Errorf("%s refused: %v", tz, err)
		}
	}
	for _, tz := range []string{"Local", "Mars/Olympus", "Europe/../etc/passwd", "UTC+7", "europe berlin"} {
		g := GeneralSettings{Timezone: tz}
		if err := g.Validate(); err == nil {
			t.Errorf("%q accepted", tz)
		}
	}
}
