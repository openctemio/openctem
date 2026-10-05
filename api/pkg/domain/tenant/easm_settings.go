package tenant

import (
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// EASM monitoring bounds (research/22 P0-11). Zero means the platform
// default (CERT_MONITOR_INTERVAL, EASM_DNS_CHECK_INTERVAL; 24 h).
const (
	MinEASMIntervalHours = 6
	MaxEASMIntervalHours = 168
)

// EASMSettings is the organization\x27s attack-surface monitoring (research/22
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
}

// Validate checks the floors: an interval is 0 (default) or 6..168 hours.
func (s EASMSettings) Validate() error {
	for name, v := range map[string]int{"ct_interval_hours": s.CTIntervalHours, "dns_interval_hours": s.DNSIntervalHours} {
		if v != 0 && (v < MinEASMIntervalHours || v > MaxEASMIntervalHours) {
			return fmt.Errorf("%w: %s must be between %d and %d (or 0 for the platform default)",
				shared.ErrValidation, name, MinEASMIntervalHours, MaxEASMIntervalHours)
		}
	}
	return nil
}

// UpdateEASMSettings replaces the tenant\x27s EASM settings.
func (t *Tenant) UpdateEASMSettings(s EASMSettings) error {
	if err := s.Validate(); err != nil {
		return err
	}
	settings := t.TypedSettings()
	settings.EASM = s
	return t.UpdateSettings(settings)
}
