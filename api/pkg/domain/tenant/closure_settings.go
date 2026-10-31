package tenant

import (
	"fmt"
	"time"

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
	// PendingMode, PendingCriticalAutoClose and PendingAt hold a loosening
	// chosen less than ClosureRelaxationDelay ago: it takes effect at
	// PendingAt (a stolen administrator session cannot loosen the policy
	// and use it in the same sitting, and the owners are told first).
	// Until then the stricter of the old and the new policy applies. Only
	// the platform writes them; a request's values are ignored.
	PendingMode              ClosingMode `json:"pending_mode,omitempty"`
	PendingCriticalAutoClose *bool       `json:"pending_critical_auto_close,omitempty"`
	PendingAt                *time.Time  `json:"pending_at,omitempty"`
}

// ClosureRelaxationDelay is how long a loosening of the closing policy waits
// before it takes effect.
const ClosureRelaxationDelay = 24 * time.Hour

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

// hasPending reports whether a loosening is stored.
func (s ClosureSettings) hasPending() bool { return s.PendingAt != nil }

// EffectiveAt is the policy in force at now, without pending fields: the
// pending loosening once its time has come, else the stored policy.
func (s ClosureSettings) EffectiveAt(now time.Time) ClosureSettings {
	out := ClosureSettings{Mode: s.Mode, CriticalAutoClose: s.CriticalAutoClose}
	if s.hasPending() && !now.Before(*s.PendingAt) {
		out.Mode = s.PendingMode
		if s.PendingCriticalAutoClose != nil {
			out.CriticalAutoClose = *s.PendingCriticalAutoClose
		}
	}
	return out
}

// PendingIn answers the waiting loosening and when it takes effect, when one
// still waits at now.
func (s ClosureSettings) PendingIn(now time.Time) (ClosureSettings, *time.Time, bool) {
	if !s.hasPending() || !now.Before(*s.PendingAt) {
		return ClosureSettings{}, nil, false
	}
	next := ClosureSettings{Mode: s.PendingMode}
	if s.PendingCriticalAutoClose != nil {
		next.CriticalAutoClose = *s.PendingCriticalAutoClose
	}
	return next, s.PendingAt, true
}

// ViewAt is the policy in force at now, with the waiting loosening (if any)
// in the pending fields: what readers and the settings page see.
func (s ClosureSettings) ViewAt(now time.Time) ClosureSettings {
	out := s.EffectiveAt(now)
	if next, at, ok := s.PendingIn(now); ok {
		crit := next.CriticalAutoClose
		out.PendingMode, out.PendingCriticalAutoClose, out.PendingAt = next.Mode, &crit, at
	}
	return out
}

// stricter is, field by field, the policy that closes less alone.
func stricter(a, b ClosureSettings) ClosureSettings {
	out := ClosureSettings{CriticalAutoClose: a.CriticalAutoClose && b.CriticalAutoClose}
	out.Mode = a.EffectiveMode()
	if closingModeRank(b.EffectiveMode()) < closingModeRank(out.Mode) {
		out.Mode = b.EffectiveMode()
	}
	return out
}

// Choose sets the policy chosen at now (only mode and critical auto-close of
// next are read). A choice that does not loosen the policy in force applies
// at once and cancels a waiting loosening. A loosening waits
// ClosureRelaxationDelay; meanwhile the stricter of the policy in force and
// the new one applies, so the tightening part of a mixed change takes
// effect at once. It answers whether the change waits.
func (s *ClosureSettings) Choose(next ClosureSettings, now time.Time) (bool, error) {
	next = ClosureSettings{Mode: next.Mode, CriticalAutoClose: next.CriticalAutoClose}
	if err := next.Validate(); err != nil {
		return false, err
	}
	current := s.EffectiveAt(now)
	if !current.Loosens(next) {
		*s = next
		return false, nil
	}
	at := now.Add(ClosureRelaxationDelay).UTC()
	crit := next.CriticalAutoClose
	*s = stricter(current, next)
	s.PendingMode, s.PendingCriticalAutoClose, s.PendingAt = next.EffectiveMode(), &crit, &at
	return true, nil
}

// CancelPending drops a waiting loosening; the policy in force at now stays
// (a loosening whose time has come is in force and stays).
func (s *ClosureSettings) CancelPending(now time.Time) bool {
	waiting := s.hasPending() && now.Before(*s.PendingAt)
	*s = s.EffectiveAt(now)
	return waiting
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
