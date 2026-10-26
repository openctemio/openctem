package tenant

import (
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// EASM monitoring bounds (research/22 P0-11). Zero means the platform
// default (CERT_MONITOR_INTERVAL, EASM_DNS_CHECK_INTERVAL; 24 h).
const (
	MinEASMIntervalHours = 6
	MaxEASMIntervalHours = 168

	// DefaultReappearAfterDays is how long an active exposure must go unseen
	// before its next sighting is announced again as "reappeared".
	DefaultReappearAfterDays = 30
	MinReappearAfterDays     = 7
	MaxReappearAfterDays     = 365
)

// EASMSettings is the organization's attack-surface monitoring (research/22
// P0-11, owner decisions E3 and E8). The zero value is the default: the
// Certificate Transparency monitor and the DNS-only checks are on at the
// platform cadence. Stored as "disabled" flags so a tenant that never saved
// the section gets the defaults.
type EASMSettings struct {
	// CTDisabled stops the Certificate Transparency monitor for the tenant:
	// its domain names are no longer sent to crt.sh or Cert Spotter (E8 opt-out).
	CTDisabled bool `json:"ct_disabled,omitempty"`
	// DNSChecksDisabled stops the DNS-only checks (dangling CNAME/NS, lame
	// delegation, email posture) for the tenant (E3 opt-out).
	DNSChecksDisabled bool `json:"dns_checks_disabled,omitempty"`
	// CTIntervalHours is how often each watched domain is re-queried.
	CTIntervalHours int `json:"ct_interval_hours,omitempty"`
	// DNSIntervalHours is how often each name is re-checked.
	DNSIntervalHours int `json:"dns_interval_hours,omitempty"`
	// EnrichmentDisabled stops automatic passive enrichment of new assets
	// (docs/architecture/asset-freshness.md); on by default.
	EnrichmentDisabled bool `json:"enrichment_disabled,omitempty"`
	// LookalikeCTDisabled stops asking Certificate Transparency (crt.sh)
	// about lookalike candidates: their names are no longer sent there
	// (docs/rfcs/RFC-083-lookalike-domains.md). DNS checks continue.
	LookalikeCTDisabled bool `json:"lookalike_ct_disabled,omitempty"`
	// NetworkLookupsDisabled stops looking network seeds up in public routing
	// data (RIPEstat): their AS numbers and organization names are no longer
	// sent there (docs/rfcs/RFC-082-network-seeds.md).
	NetworkLookupsDisabled bool `json:"network_lookups_disabled,omitempty"`
	// WebScreenshotsEnabled keeps the screenshots sensors send with web
	// evidence (docs/rfcs/RFC-081-web-evidence-screenshots.md); off by
	// default: a screenshot can show whatever the page shows.
	WebScreenshotsEnabled bool `json:"web_screenshots_enabled,omitempty"`
	// WeeklyDigestDisabled stops the weekly "what changed" digest of the
	// attack surface (docs/rfcs/RFC-080-attack-surface-changes-and-digest.md);
	// on by default.
	WeeklyDigestDisabled bool `json:"weekly_digest_disabled,omitempty"`
	// DigestWeekday is the UTC weekday the digest goes out: 0 for the
	// default (Monday), else 1..7 = Monday..Sunday (ISO 8601).
	DigestWeekday int `json:"digest_weekday,omitempty"`
	// ReappearAfterDays is the alert fingerprint's lifetime: an exposure
	// not seen for this long and then seen again is announced as
	// "reappeared". 0 is the default (30 days), else 7..365.
	ReappearAfterDays int `json:"reappear_after_days,omitempty"`
}

// ReappearAfter is the effective alert fingerprint lifetime.
func (s EASMSettings) ReappearAfter() time.Duration {
	d := s.ReappearAfterDays
	if d == 0 {
		d = DefaultReappearAfterDays
	}
	return time.Duration(d) * 24 * time.Hour
}

// Validate checks the floors: an interval is 0 (default) or 6..168 hours.
func (s EASMSettings) Validate() error {
	for name, v := range map[string]int{"ct_interval_hours": s.CTIntervalHours, "dns_interval_hours": s.DNSIntervalHours} {
		if v != 0 && (v < MinEASMIntervalHours || v > MaxEASMIntervalHours) {
			return fmt.Errorf("%w: %s must be between %d and %d (or 0 for the platform default)",
				shared.ErrValidation, name, MinEASMIntervalHours, MaxEASMIntervalHours)
		}
	}
	if s.DigestWeekday < 0 || s.DigestWeekday > 7 {
		return fmt.Errorf("%w: digest_weekday must be between 1 (Monday) and 7 (Sunday), or 0 for the default",
			shared.ErrValidation)
	}
	if s.ReappearAfterDays != 0 && (s.ReappearAfterDays < MinReappearAfterDays || s.ReappearAfterDays > MaxReappearAfterDays) {
		return fmt.Errorf("%w: reappear_after_days must be between %d and %d (or 0 for the default of %d)",
			shared.ErrValidation, MinReappearAfterDays, MaxReappearAfterDays, DefaultReappearAfterDays)
	}
	return nil
}

// UpdateEASMSettings replaces the tenant's EASM settings.
func (t *Tenant) UpdateEASMSettings(s EASMSettings) error {
	if err := s.Validate(); err != nil {
		return err
	}
	settings := t.TypedSettings()
	settings.EASM = s
	return t.UpdateSettings(settings)
}
