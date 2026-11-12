package tenant

// The organization's API key policy (docs/architecture/api-keys.md,
// "Maximum lifetime"): how long a new organization API key may live. The
// platform ceiling bounds it; an organization may only tighten below it.

import (
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// SectionAPIKeys is the settings section key.
const SectionAPIKeys = "api_keys"

// APIKeyLifetimeCeilingDays is the platform ceiling: no API key lives longer
// than a year (settings decision B14).
const APIKeyLifetimeCeilingDays = 365

// DefaultAPIKeyMaxLifetimeDays is the maximum lifetime of a new key in an
// organization that never chose one.
const DefaultAPIKeyMaxLifetimeDays = 90

// APIKeySettings is the organization's API key policy.
type APIKeySettings struct {
	// MaxLifetimeDays is the longest a new key may live, 1 to
	// APIKeyLifetimeCeilingDays; 0 is DefaultAPIKeyMaxLifetimeDays.
	MaxLifetimeDays int `json:"max_lifetime_days,omitempty"`
}

// Validate checks the bounds.
func (s APIKeySettings) Validate() error {
	if s.MaxLifetimeDays < 0 || s.MaxLifetimeDays > APIKeyLifetimeCeilingDays {
		return fmt.Errorf("%w: max_lifetime_days must be 1 to %d", shared.ErrValidation, APIKeyLifetimeCeilingDays)
	}
	return nil
}

// EffectiveMaxLifetimeDays is the maximum in force, never above the ceiling.
func (s APIKeySettings) EffectiveMaxLifetimeDays() int {
	switch {
	case s.MaxLifetimeDays <= 0:
		return DefaultAPIKeyMaxLifetimeDays
	case s.MaxLifetimeDays > APIKeyLifetimeCeilingDays:
		return APIKeyLifetimeCeilingDays
	default:
		return s.MaxLifetimeDays
	}
}

// UpdateAPIKeySettings updates only the API key policy.
func (t *Tenant) UpdateAPIKeySettings(s APIKeySettings) error {
	if err := s.Validate(); err != nil {
		return err
	}
	settings := t.TypedSettings()
	settings.APIKeys = s
	return t.UpdateSettings(settings)
}
