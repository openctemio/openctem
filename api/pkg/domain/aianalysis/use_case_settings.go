package aianalysis

// Per-use-case AI settings (docs/architecture/ai-use-cases.md): for each use
// case the organization decides whether its results wait for a person
// (suggest), apply on their own when that is safe (auto_apply) or the use
// case does not run (off); the most sensitive data class it may send; and
// the minimum confidence to apply on its own.
//
// What auto_apply may never do is fixed here and in the executor, not by a
// setting: a severity change, a risk-lowering change and a result flagged
// for review are never applied (a risk-lowering change becomes a request a
// person decides).

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// UseCaseMode is what happens to a use case's results.
type UseCaseMode string

const (
	// UseCaseOff: the use case does not run.
	UseCaseOff UseCaseMode = "off"
	// UseCaseSuggest: results wait for a person.
	UseCaseSuggest UseCaseMode = "suggest"
	// UseCaseAutoApply: results that only add information apply at once.
	UseCaseAutoApply UseCaseMode = "auto_apply"
)

// ParseUseCaseMode validates a mode.
func ParseUseCaseMode(s string) (UseCaseMode, error) {
	switch UseCaseMode(s) {
	case UseCaseOff, UseCaseSuggest, UseCaseAutoApply:
		return UseCaseMode(s), nil
	}
	return "", fmt.Errorf("%w: mode is off, suggest or auto_apply", shared.ErrValidation)
}

// Bounds and defaults of a use case's settings.
const (
	DefaultMinConfidence = 0.85
	MinConfidenceFloor   = 0.50
	MinConfidenceCeiling = 0.99
	// DefaultUseCaseCeiling is the data class a use case sends by default.
	DefaultUseCaseCeiling = DataClassInternal
)

// Automatic downgrade: over the last DowngradeWindow person decisions on a
// use case's automatic results, when at least DowngradeMinDecisions were made
// and the share of overrides reaches DowngradeOverrideRate, auto_apply falls
// back to suggest.
const (
	DowngradeWindow       = 50
	DowngradeMinDecisions = 10
	DowngradeOverrideRate = 0.20
	// DowngradeReasonOverrides is the fixed reason of an automatic downgrade.
	DowngradeReasonOverrides = "override_rate"
)

// UseCaseSetting is one use case's settings.
type UseCaseSetting struct {
	Mode          UseCaseMode
	Ceiling       DataClass
	MinConfidence float64

	// AutoApplySince is when auto_apply was last turned on. Only decisions
	// on results made since count toward an automatic downgrade.
	AutoApplySince *time.Time
	// DowngradedAt, DowngradeReason, DowngradeDecisions and
	// DowngradeOverrides describe the last automatic downgrade (cleared when
	// auto_apply is turned back on).
	DowngradedAt       *time.Time
	DowngradeReason    string
	DowngradeDecisions int
	DowngradeOverrides int

	UpdatedAt *time.Time
	UpdatedBy string
}

// DefaultUseCaseSetting is the setting of a use case nobody changed.
func DefaultUseCaseSetting() UseCaseSetting {
	return UseCaseSetting{Mode: UseCaseSuggest, Ceiling: DefaultUseCaseCeiling, MinConfidence: DefaultMinConfidence}
}

// Validate checks the editable fields.
func (s UseCaseSetting) Validate() error {
	if _, err := ParseUseCaseMode(string(s.Mode)); err != nil {
		return err
	}
	switch s.Ceiling {
	case DataClassPublic, DataClassInternal, DataClassRestricted:
	default:
		// tenant_only is never sent, so it is no ceiling to choose.
		return fmt.Errorf("%w: the most sensitive data sent is public, internal or restricted", shared.ErrValidation)
	}
	if math.IsNaN(s.MinConfidence) || s.MinConfidence < MinConfidenceFloor || s.MinConfidence > MinConfidenceCeiling {
		return fmt.Errorf("%w: minimum confidence is %.2f to %.2f", shared.ErrValidation, MinConfidenceFloor, MinConfidenceCeiling)
	}
	return nil
}

// Normalized fills a stored setting's missing fields with the defaults and
// replaces invalid ones (fail closed: an unreadable mode is suggest, an
// unreadable ceiling is internal).
func (s UseCaseSetting) Normalized() UseCaseSetting {
	d := DefaultUseCaseSetting()
	if _, err := ParseUseCaseMode(string(s.Mode)); err != nil {
		s.Mode = d.Mode
	}
	switch s.Ceiling {
	case DataClassPublic, DataClassInternal, DataClassRestricted:
	default:
		s.Ceiling = d.Ceiling
	}
	if math.IsNaN(s.MinConfidence) || s.MinConfidence < MinConfidenceFloor || s.MinConfidence > MinConfidenceCeiling {
		s.MinConfidence = d.MinConfidence
	}
	return s
}

// EffectiveCeiling is the lower of the use case's ceiling and another one
// (an AI agent's own ceiling).
func (s UseCaseSetting) EffectiveCeiling(other DataClass) DataClass {
	if other.Rank() == 0 {
		return s.Ceiling
	}
	if s.Ceiling.Rank() < other.Rank() {
		return s.Ceiling
	}
	return other
}

// MayApply reports whether a result with this confidence may apply on its
// own: auto_apply, at or above the minimum confidence. Severity changes,
// risk-lowering changes and flagged results are refused by the caller
// whatever this says.
func (s UseCaseSetting) MayApply(confidence float64) bool {
	return s.Mode == UseCaseAutoApply && !math.IsNaN(confidence) && confidence >= s.MinConfidence
}

// Loosening reasons: a change that lets AI results apply on their own, or
// sends more data, needs a recent sign-in and is a critical audit event.
const (
	LoosenAutoApplyOn     = "auto_apply_on"
	LoosenCeilingRaised   = "ceiling_raised"
	LoosenConfidenceLower = "confidence_lowered"
)

// UseCaseLoosened lists why a change loosens a use case: turning auto_apply
// on, raising the ceiling above internal, or lowering the minimum confidence
// while auto_apply stays on. Turning a use case off or down, and lowering the
// ceiling, are never loosening (one click in an incident).
func UseCaseLoosened(before, after UseCaseSetting) []string {
	var out []string
	if after.Mode == UseCaseAutoApply && before.Mode != UseCaseAutoApply {
		out = append(out, LoosenAutoApplyOn)
	}
	if after.Mode != UseCaseOff && after.Ceiling.Rank() > before.Ceiling.Rank() && after.Ceiling.Rank() > DataClassInternal.Rank() {
		out = append(out, LoosenCeilingRaised)
	}
	if after.Mode == UseCaseAutoApply && before.Mode == UseCaseAutoApply && after.MinConfidence < before.MinConfidence {
		out = append(out, LoosenConfidenceLower)
	}
	return out
}

// UseCasePolicy is an organization's settings by use case. A use case not
// in it has the default setting.
type UseCasePolicy map[UseCase]UseCaseSetting

// For returns a use case's setting, normalized.
func (p UseCasePolicy) For(uc UseCase) UseCaseSetting {
	if s, ok := p[uc]; ok {
		return s.Normalized()
	}
	return DefaultUseCaseSetting()
}

// OverrideStats counts person decisions on a use case's automatic results:
// how many were made and how many overrode the AI (a rejected request).
type OverrideStats struct {
	Decisions int
	Overrides int
}

// ShouldDowngrade reports whether the stats call for falling back to
// suggest.
func (s OverrideStats) ShouldDowngrade() bool {
	if s.Decisions < DowngradeMinDecisions {
		return false
	}
	return float64(s.Overrides) >= DowngradeOverrideRate*float64(s.Decisions)
}

// AutoApplyUseCase is one organization's use case in auto_apply (the
// downgrade sweep).
type AutoApplyUseCase struct {
	TenantID shared.ID
	UseCase  UseCase
	Setting  UseCaseSetting
}

// UseCaseRepository stores the per-use-case settings with the
// organization's other AI settings (tenant_ai_settings.use_cases).
type UseCaseRepository interface {
	// GetUseCases returns the stored settings (empty for an organization
	// without a row).
	GetUseCases(ctx context.Context, tenantID shared.ID) (UseCasePolicy, error)
	// SaveUseCase writes one use case's setting; the others are untouched.
	SaveUseCase(ctx context.Context, tenantID shared.ID, uc UseCase, s UseCaseSetting) error
	// DowngradeUseCase writes next only while the stored setting is still
	// exactly expected (nobody changed it since it was read); false when it
	// was not written.
	DowngradeUseCase(ctx context.Context, tenantID shared.ID, uc UseCase, expected, next UseCaseSetting) (bool, error)
	// ListAutoApply lists the use cases in auto_apply of every organization
	// (a system job).
	ListAutoApply(ctx context.Context, limit int) ([]AutoApplyUseCase, error)
}

// OverrideStatsReader counts person decisions on requests the
// organization's AI filed for a use case since a time, newest first, at
// most window decisions.
type OverrideStatsReader interface {
	OverrideStats(ctx context.Context, tenantID shared.ID, uc UseCase, since time.Time, window int) (OverrideStats, error)
}
