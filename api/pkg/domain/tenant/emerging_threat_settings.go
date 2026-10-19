package tenant

import (
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Emerging-threat alert defaults and bounds
// (docs/rfcs/RFC-117-emerging-threat-alerts.md §3.2).
const (
	DefaultEmergingImmediateThreshold = 70
	DefaultEmergingDigestThreshold    = 35
	DefaultEmergingDigestHour         = 8
	DefaultEmergingQuietOverride      = 90
	// MaxEmergingAssetNames is how many asset names an external message
	// may carry when the organization turns names on.
	MaxEmergingAssetNames = 5
)

// SectionEmergingThreats is the settings section key.
const SectionEmergingThreats = "emerging_threats"

// QuietHours is an organization-local window during which immediate alerts
// below the override score are held.
type QuietHours struct {
	Enabled   bool `json:"enabled"`
	StartHour int  `json:"start_hour"`
	EndHour   int  `json:"end_hour"`
}

// EmergingThreatSettings is the organization's emerging-threat alert
// policy. Zero values mean the defaults, so an organization that never
// saved the section gets them; alerts are on unless Disabled.
type EmergingThreatSettings struct {
	Disabled bool `json:"disabled"`
	// ImmediateThreshold (60-90; 0 = 70) is the score an alert needs, with
	// exploitation evidence, to be sent at once.
	ImmediateThreshold int `json:"immediate_threshold,omitempty"`
	// DigestThreshold (20-60; 0 = 35) is the score for the daily digest.
	DigestThreshold int `json:"digest_threshold,omitempty"`
	// DigestHour (0-23, organization time; nil = 8).
	DigestHour *int       `json:"digest_hour,omitempty"`
	QuietHours QuietHours `json:"quiet_hours"`
	// QuietOverride (70-100; 0 = 90): an alert at or above it is sent
	// during quiet hours.
	QuietOverride int `json:"quiet_override,omitempty"`
	// IncludePossibleInImmediate lets possibly affected assets (version
	// unknown) page; otherwise only when the CVE is in KEV and the asset is
	// internet-facing.
	IncludePossibleInImmediate bool `json:"include_possible_in_immediate"`
	// AssetNamesInMessages puts up to MaxEmergingAssetNames asset names in
	// external messages (Slack, Teams, e-mail, webhooks). Off by default:
	// counts and a link only.
	AssetNamesInMessages bool `json:"asset_names_in_messages"`
}

// Validate checks the bounds.
func (s EmergingThreatSettings) Validate() error {
	if s.ImmediateThreshold != 0 && (s.ImmediateThreshold < 60 || s.ImmediateThreshold > 90) {
		return fmt.Errorf("%w: immediate_threshold must be between 60 and 90", shared.ErrValidation)
	}
	if s.DigestThreshold != 0 && (s.DigestThreshold < 20 || s.DigestThreshold > 60) {
		return fmt.Errorf("%w: digest_threshold must be between 20 and 60", shared.ErrValidation)
	}
	if s.DigestHour != nil && (*s.DigestHour < 0 || *s.DigestHour > 23) {
		return fmt.Errorf("%w: digest_hour must be between 0 and 23", shared.ErrValidation)
	}
	if s.QuietHours.StartHour < 0 || s.QuietHours.StartHour > 23 || s.QuietHours.EndHour < 0 || s.QuietHours.EndHour > 23 {
		return fmt.Errorf("%w: quiet hours must be between 0 and 23", shared.ErrValidation)
	}
	if s.QuietHours.Enabled && s.QuietHours.StartHour == s.QuietHours.EndHour {
		return fmt.Errorf("%w: quiet hours must start and end at different hours", shared.ErrValidation)
	}
	if s.QuietOverride != 0 && (s.QuietOverride < 70 || s.QuietOverride > 100) {
		return fmt.Errorf("%w: quiet_override must be between 70 and 100", shared.ErrValidation)
	}
	return nil
}

// Effective returns the settings with every default filled.
func (s EmergingThreatSettings) Effective() EmergingThreatSettings {
	if s.ImmediateThreshold == 0 {
		s.ImmediateThreshold = DefaultEmergingImmediateThreshold
	}
	if s.DigestThreshold == 0 {
		s.DigestThreshold = DefaultEmergingDigestThreshold
	}
	if s.DigestHour == nil {
		h := DefaultEmergingDigestHour
		s.DigestHour = &h
	}
	if s.QuietOverride == 0 {
		s.QuietOverride = DefaultEmergingQuietOverride
	}
	return s
}

// InQuietHours reports whether the local hour falls in the window (which
// may wrap midnight: 22-7).
func (s EmergingThreatSettings) InQuietHours(hour int) bool {
	q := s.QuietHours
	if !q.Enabled || q.StartHour == q.EndHour {
		return false
	}
	if q.StartHour < q.EndHour {
		return hour >= q.StartHour && hour < q.EndHour
	}
	return hour >= q.StartHour || hour < q.EndHour
}

// UpdateEmergingThreatSettings updates only the emerging-threat policy.
func (t *Tenant) UpdateEmergingThreatSettings(es EmergingThreatSettings) error {
	if err := es.Validate(); err != nil {
		return err
	}
	settings := t.TypedSettings()
	settings.EmergingThreats = es
	return t.UpdateSettings(settings)
}
