package aianalysis

import (
	"fmt"
	"math"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Policy limits.
const (
	DefaultMinConfidence = 0.85
	MinMinConfidence     = 0.50
	MaxMinConfidence     = 0.99

	// DowngradeWindow is the number of most recent decisions the override
	// rate is computed over, and DowngradeThreshold the override share at or
	// above which auto-apply falls back to suggest.
	DowngradeWindow    = 50
	DowngradeThreshold = 0.20
	// DowngradeMinDecisions is the number of decisions needed before the
	// rate is trusted (one dismissal out of one is not a trend).
	DowngradeMinDecisions = 10

	// DowngradeReasonOverrideRate is the stored reason of an automatic
	// downgrade.
	DowngradeReasonOverrideRate = "override_rate"
)

// UseCasePolicy is an organization's policy for one use case.
type UseCasePolicy struct {
	TenantID         shared.ID
	UseCase          UseCase
	Mode             Mode
	Executor         Executor
	DataClassCeiling DataClass
	MinConfidence    float64
	Triggers         []Trigger
	BudgetShare      int
	DowngradedAt     *time.Time
	DowngradeReason  string
	UpdatedBy        *shared.ID
	UpdatedAt        time.Time
	// Stored is false for the platform default (no row yet).
	Stored bool
}

// DefaultPolicy is the platform default for a use case: off until the
// organization consented to AI, then suggest.
func DefaultPolicy(tenantID shared.ID, u UseCase, consented bool) UseCasePolicy {
	mode := ModeOff
	if consented {
		mode = ModeSuggest
	}
	return UseCasePolicy{
		TenantID:         tenantID,
		UseCase:          u,
		Mode:             mode,
		Executor:         ExecutorBuiltin,
		DataClassCeiling: DataClassInternal,
		MinConfidence:    DefaultMinConfidence,
		Triggers:         []Trigger{TriggerOnDemand},
		BudgetShare:      100,
	}
}

// Effective is the mode in force: off whatever is stored while the
// organization has not consented to AI.
func (p UseCasePolicy) Effective(consented bool) Mode {
	if !consented {
		return ModeOff
	}
	return p.Mode
}

// Validate checks the policy against the platform ceilings. The built-in
// executor runs in the API process with the organization's or the
// platform's provider: tenant-only data never goes there.
func (p UseCasePolicy) Validate() error {
	if _, err := ParseUseCase(string(p.UseCase)); err != nil {
		return err
	}
	if _, err := ParseMode(string(p.Mode)); err != nil {
		return err
	}
	if _, err := ParseExecutor(string(p.Executor)); err != nil {
		return err
	}
	if _, err := ParseDataClass(string(p.DataClassCeiling)); err != nil {
		return err
	}
	if p.Executor != ExecutorTenantWorker && p.DataClassCeiling == DataClassTenantOnly {
		return fmt.Errorf("%w: tenant-only data goes only to a worker the organization runs", shared.ErrValidation)
	}
	if p.Executor != ExecutorBuiltin {
		return fmt.Errorf("%w: only the built-in executor is available", shared.ErrValidation)
	}
	if math.IsNaN(p.MinConfidence) || p.MinConfidence < MinMinConfidence || p.MinConfidence > MaxMinConfidence {
		return fmt.Errorf("%w: minimum confidence must be between %.2f and %.2f", shared.ErrValidation, MinMinConfidence, MaxMinConfidence)
	}
	if len(p.Triggers) == 0 || len(p.Triggers) > 4 {
		return fmt.Errorf("%w: choose at least one trigger", shared.ErrValidation)
	}
	seen := map[Trigger]bool{}
	for _, t := range p.Triggers {
		if _, err := ParseTrigger(string(t)); err != nil {
			return err
		}
		if seen[t] {
			return fmt.Errorf("%w: duplicate trigger", shared.ErrValidation)
		}
		seen[t] = true
	}
	if p.BudgetShare < 1 || p.BudgetShare > 100 {
		return fmt.Errorf("%w: budget share must be between 1 and 100", shared.ErrValidation)
	}
	return nil
}

// LoosensFrom reports whether p sends more data or applies more on its own
// than old: turning auto-apply on or raising the data class ceiling above
// internal. Such a change needs a fresh sign-in.
func (p UseCasePolicy) LoosensFrom(old UseCasePolicy) bool {
	if p.Mode == ModeAutoApply && old.Mode != ModeAutoApply {
		return true
	}
	return p.DataClassCeiling.Rank() > old.DataClassCeiling.Rank() && p.DataClassCeiling.Rank() > DataClassInternal.Rank()
}

// Decisions is the recent decision record of a use case: Total decisions,
// of which Overrides were a person saying no (dismissed, undone, or an
// approval request rejected).
type Decisions struct {
	Total     int
	Overrides int
}

// ShouldDowngrade reports whether an auto-apply use case falls back to
// suggest: at least DowngradeMinDecisions decisions in the window and an
// override share at or above DowngradeThreshold.
func ShouldDowngrade(mode Mode, d Decisions) bool {
	if mode != ModeAutoApply || d.Total < DowngradeMinDecisions {
		return false
	}
	return float64(d.Overrides) >= DowngradeThreshold*float64(d.Total)
}
