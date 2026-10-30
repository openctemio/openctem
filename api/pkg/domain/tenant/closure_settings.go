package tenant

import (
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// SectionClosure is the settings section key of ClosureSettings.
const SectionClosure = "closure"

// ClosingMode is how the organization lets the platform close findings
// without a person (docs/architecture/finding-verification-plan.md, "Closing
// mode").
type ClosingMode string

const (
	// ClosingModeAuto: the platform closes per the tier rule (a critical
	// finding that a plain scan no longer sees still waits for a person).
	ClosingModeAuto ClosingMode = "auto"
	// ClosingModeReview: every automatic close becomes a proposal a person
	// confirms.
	ClosingModeReview ClosingMode = "review"
	// ClosingModeOff: only a person closes findings.
	ClosingModeOff ClosingMode = "off"
)

// ClosureSettings is the organization's closing policy. The platform env
// INGEST_COVERAGE_AUTO_RESOLVE stays the ceiling: when it is off or dry_run
// nothing closes, whatever the mode.
type ClosureSettings struct {
	// Mode: empty means review (organizations created before the setting
	// existed); new organizations start in auto.
	Mode ClosingMode `json:"mode,omitempty"`
	// CriticalAutoClose lets a plain covered scan close critical, P0 and KEV
	// findings in auto mode. Off by default; only the owner may turn it on.
	CriticalAutoClose bool `json:"critical_auto_close"`
}

// Validate checks the mode.
func (s ClosureSettings) Validate() error {
	switch s.Mode {
	case "", ClosingModeAuto, ClosingModeReview, ClosingModeOff:
		return nil
	}
	return fmt.Errorf("%w: mode must be auto, review or off", shared.ErrValidation)
}

// EffectiveMode returns the mode, review when unset.
func (s ClosureSettings) EffectiveMode() ClosingMode {
	if s.Mode == "" {
		return ClosingModeReview
	}
	return s.Mode
}

// closingModeRank orders the modes by how much the platform closes alone.
func closingModeRank(m ClosingMode) int {
	switch m {
	case ClosingModeAuto:
		return 2
	case ClosingModeReview:
		return 1
	default:
		return 0
	}
}

// Loosens reports whether going from s to next lets the platform close more
// findings without a person: a mode with more automation, or critical
// findings taken out of review.
func (s ClosureSettings) Loosens(next ClosureSettings) bool {
	if closingModeRank(next.EffectiveMode()) > closingModeRank(s.EffectiveMode()) {
		return true
	}
	return next.CriticalAutoClose && !s.CriticalAutoClose
}

// UpdateClosureSettings updates only the closing policy.
func (t *Tenant) UpdateClosureSettings(cs ClosureSettings) error {
	if err := cs.Validate(); err != nil {
		return err
	}
	settings := t.TypedSettings()
	settings.Closure = cs
	return t.UpdateSettings(settings)
}
