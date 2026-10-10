package tenant

// The organization's scan approval governance (RFC-072,
// docs/rfcs/RFC-072-scan-approval-governance.md): the mode an owner chooses
// and the approval rules. Off by default.

import (
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/scangov"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// SectionScanGovernance is the settings section key.
const SectionScanGovernance = "scan_governance"

// ScanGovernanceSettings is the organization's scan approval setting.
type ScanGovernanceSettings struct {
	// Mode: off (default), on or strict. Owner-only, step-up and a reason.
	Mode scangov.Mode `json:"mode,omitempty"`
	// Rules decide which scans need approval when the mode is on or strict
	// (first match in order decides the approvers; all matches are shown).
	Rules []scangov.Rule `json:"rules,omitempty"`
	// PendingExpiryDays: a request nobody approved expires after this many
	// days (1-90, 0 = 14).
	PendingExpiryDays int `json:"pending_expiry_days,omitempty"`
}

// EffectiveMode is the stored mode, off when unset.
func (s ScanGovernanceSettings) EffectiveMode() scangov.Mode { return s.Mode.Normalized() }

// PendingDays is the pending expiry in days.
func (s ScanGovernanceSettings) PendingDays() int {
	if s.PendingExpiryDays < 1 {
		return scangov.DefaultPendingDays
	}
	return s.PendingExpiryDays
}

// Normalized validates s and returns the cleaned copy.
func (s ScanGovernanceSettings) Normalized() (ScanGovernanceSettings, error) {
	if s.Mode != "" {
		m, err := scangov.ParseMode(string(s.Mode))
		if err != nil {
			return s, err
		}
		s.Mode = m
	}
	if s.PendingExpiryDays < 0 || s.PendingExpiryDays > scangov.MaxPendingDays {
		return s, fmt.Errorf("%w: pending_expiry_days must be 1 to %d", shared.ErrValidation, scangov.MaxPendingDays)
	}
	rules, err := scangov.Normalize(s.Rules)
	if err != nil {
		return s, err
	}
	s.Rules = rules
	return s, nil
}

// UpdateScanGovernanceSettings replaces the section after validating it.
func (t *Tenant) UpdateScanGovernanceSettings(s ScanGovernanceSettings) error {
	n, err := s.Normalized()
	if err != nil {
		return err
	}
	settings := t.TypedSettings()
	settings.ScanGovernance = n
	return t.UpdateSettings(settings)
}
