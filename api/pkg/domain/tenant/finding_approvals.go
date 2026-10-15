package tenant

// The organization's finding approval settings
// (api/docs/architecture/finding-status-lifecycle.md, "Approvals").

import (
	"fmt"
	"net/mail"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// SectionFindingApprovals is the settings section key.
const SectionFindingApprovals = "finding_approvals"

// maxContactEmailLen bounds the backup contact address.
const maxContactEmailLen = 254

// FindingApprovalSettings is how the organization governs finding
// false-positive and accepted-risk decisions.
type FindingApprovalSettings struct {
	// BackupContactEmail is told whenever the sole member of the
	// organization approves their own request (an advisor or auditor who is
	// not a member). Empty: nobody outside is told.
	BackupContactEmail string `json:"backup_contact_email,omitempty"`
	// FPApproval is who decides a false positive: all (default; a second
	// person always), high_and_above (a second person only for a material
	// finding) or off (one person). An accepted risk always needs a second
	// person, whatever this says.
	FPApproval string `json:"fp_approval,omitempty"`
	// PendingFPApproval is a lower level chosen less than
	// FPApprovalLoweringDelay ago; it takes effect at
	// PendingFPApprovalAt. Raising the level is immediate and clears it.
	PendingFPApproval   string     `json:"pending_fp_approval,omitempty"`
	PendingFPApprovalAt *time.Time `json:"pending_fp_approval_at,omitempty"`
	// SecondLookPercent is the share (0-10) of single-person false
	// positives flagged for a second person to look at.
	SecondLookPercent int `json:"second_look_percent,omitempty"`
}

// EffectiveFPApproval is the level in force at now: a pending lower level
// once its time has come, else the stored level (all when unset).
func (s FindingApprovalSettings) EffectiveFPApproval(now time.Time) string {
	if s.PendingFPApproval != "" && s.PendingFPApprovalAt != nil && !now.Before(*s.PendingFPApprovalAt) {
		return s.PendingFPApproval
	}
	if s.FPApproval == "" {
		return FPApprovalAll
	}
	return s.FPApproval
}

// SetFPApproval chooses a new level at now. A level at or above the one in
// force applies at once and cancels a pending lowering; a lower level waits
// FPApprovalLoweringDelay (so a stolen administrator session
// cannot lower the bar and use it in the same sitting, and the other
// approvers are told first).
func (s *FindingApprovalSettings) SetFPApproval(level string, now time.Time) error {
	level, err := ParseFPApprovalLevel(level)
	if err != nil {
		return err
	}
	current := s.EffectiveFPApproval(now)
	if FPApprovalLevelRank(level) >= FPApprovalLevelRank(current) {
		s.FPApproval, s.PendingFPApproval, s.PendingFPApprovalAt = level, "", nil
		return nil
	}
	at := now.Add(FPApprovalLoweringDelay).UTC()
	s.FPApproval, s.PendingFPApproval, s.PendingFPApprovalAt = current, level, &at
	return nil
}

// Normalized validates s and returns the cleaned copy.
func (s FindingApprovalSettings) Normalized() (FindingApprovalSettings, error) {
	s.BackupContactEmail = strings.ToLower(strings.TrimSpace(s.BackupContactEmail))
	if s.FPApproval != "" {
		if _, err := ParseFPApprovalLevel(s.FPApproval); err != nil {
			return s, err
		}
	}
	if s.PendingFPApproval != "" {
		if _, err := ParseFPApprovalLevel(s.PendingFPApproval); err != nil {
			return s, err
		}
	}
	if s.SecondLookPercent < 0 || s.SecondLookPercent > MaxSecondLookPercent {
		return s, fmt.Errorf("%w: second_look_percent must be 0 to %d", shared.ErrValidation, MaxSecondLookPercent)
	}
	if s.BackupContactEmail != "" {
		addr, err := mail.ParseAddress(s.BackupContactEmail)
		if err != nil || addr.Address != s.BackupContactEmail || len(s.BackupContactEmail) > maxContactEmailLen {
			return s, fmt.Errorf("%w: backup_contact_email must be one email address", shared.ErrValidation)
		}
	}
	return s, nil
}

// UpdateFindingApprovalSettings replaces the section after validating it.
func (t *Tenant) UpdateFindingApprovalSettings(s FindingApprovalSettings) error {
	n, err := s.Normalized()
	if err != nil {
		return err
	}
	settings := t.TypedSettings()
	settings.FindingApprovals = n
	return t.UpdateSettings(settings)
}

// FP approval levels, strictest first.
const (
	// FPApprovalAll: every false positive needs a second person (default).
	FPApprovalAll = "all"
	// FPApprovalHighAndAbove: only a material finding needs a second person
	// (FPFacts.Material); others one person may decide.
	FPApprovalHighAndAbove = "high_and_above"
	// FPApprovalOff: one person may decide any false positive.
	FPApprovalOff = "off"
)

// FPApprovalLevelRank orders the levels: a higher rank asks for more
// approvals. An unknown level ranks as the strictest.
func FPApprovalLevelRank(level string) int {
	switch level {
	case FPApprovalOff:
		return 0
	case FPApprovalHighAndAbove:
		return 1
	}
	return 2
}

// ParseFPApprovalLevel validates a level ("" is the default, all).
func ParseFPApprovalLevel(s string) (string, error) {
	switch strings.TrimSpace(s) {
	case "", FPApprovalAll:
		return FPApprovalAll, nil
	case FPApprovalHighAndAbove:
		return FPApprovalHighAndAbove, nil
	case FPApprovalOff:
		return FPApprovalOff, nil
	}
	return "", fmt.Errorf("%w: fp_approval must be all, high_and_above or off", shared.ErrValidation)
}

// FPApprovalLoweringDelay is how long a lower false-positive approval level
// waits before it takes effect (raising takes effect at once).
const FPApprovalLoweringDelay = 24 * time.Hour

// MaxSecondLookPercent bounds the share of single-person false positives
// sent to a second person for a look.
const MaxSecondLookPercent = 10
