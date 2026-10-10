package scan

// Scan intensity: RFC-071 (docs/rfcs/RFC-071-scan-intensity.md). The
// intensity is the ceiling a scan's runs may probe at, chosen when the scan
// is created: passive (no packets from our sensors to the target hosts),
// active (non-intrusive probing) or intrusive. A tool or workflow step above
// it is refused when the scan is saved and never dispatched by a run.

import (
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Intensity is the probe ceiling of a scan.
type Intensity string

// Intensities, from the least to the most traffic toward the targets. Each
// is the ceiling of one tier (scope.Tier, stage.Tier): passive = T0,
// active = T1, intrusive = T2.
const (
	IntensityPassive   Intensity = "passive"
	IntensityActive    Intensity = "active"
	IntensityIntrusive Intensity = "intrusive"
)

// DefaultIntensity is what a new scan gets when nothing else decides.
const DefaultIntensity = IntensityActive

// CodeIntensityExceeded is the error code of a scan whose tool or workflow
// step probes above the scan's intensity.
const CodeIntensityExceeded = "INTENSITY_EXCEEDED"

// ParseIntensity reads passive, active or intrusive (case-insensitive).
func ParseIntensity(s string) (Intensity, error) {
	switch i := Intensity(strings.ToLower(strings.TrimSpace(s))); i {
	case IntensityPassive, IntensityActive, IntensityIntrusive:
		return i, nil
	}
	return "", fmt.Errorf("%w: intensity must be passive, active or intrusive", shared.ErrValidation)
}

// Valid reports whether i is a known intensity.
func (i Intensity) Valid() bool {
	_, err := ParseIntensity(string(i))
	return err == nil && string(i) == strings.ToLower(strings.TrimSpace(string(i)))
}

// MaxTier is the highest tier the intensity allows (0 passive, 1 active,
// 2 intrusive). An unknown or empty intensity allows nothing above active:
// it never widens what a scan may do.
func (i Intensity) MaxTier() int {
	switch i {
	case IntensityPassive:
		return 0
	case IntensityIntrusive:
		return 2
	}
	return 1
}

// Allows reports whether a probe of the given tier fits under i.
func (i Intensity) Allows(tier int) bool { return tier <= i.MaxTier() }

// IntensityForTier is the lowest intensity that allows tier.
func IntensityForTier(tier int) Intensity {
	switch {
	case tier <= 0:
		return IntensityPassive
	case tier == 1:
		return IntensityActive
	}
	return IntensityIntrusive
}

// TierLabel is the tier's label in messages ("T0".."T2").
func TierLabel(tier int) string { return fmt.Sprintf("T%d", tier) }

// SetIntensity sets the scan's intensity after validating it.
func (s *Scan) SetIntensity(i Intensity) error {
	p, err := ParseIntensity(string(i))
	if err != nil {
		return err
	}
	s.Intensity = p
	s.UpdatedAt = time.Now()
	return nil
}

// EffectiveIntensity is the scan's intensity, the default when unset (a
// scan built in memory before the field existed).
func (s *Scan) EffectiveIntensity() Intensity {
	if s == nil || !s.Intensity.Valid() {
		return DefaultIntensity
	}
	return s.Intensity
}

// IntensityExceededError says which tool or step probes above the ceiling.
func IntensityExceededError(i Intensity, what string, tier int) error {
	return shared.NewDomainError(CodeIntensityExceeded,
		fmt.Sprintf("%s probes at %s, above this scan's %s intensity. Choose a higher intensity or a tool that stays within it.",
			what, TierLabel(tier), i), shared.ErrValidation)
}
