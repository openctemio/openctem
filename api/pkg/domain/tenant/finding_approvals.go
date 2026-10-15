package tenant

// The organization's finding approval settings
// (api/docs/architecture/finding-status-lifecycle.md, "Approvals").

import (
	"fmt"
	"net/mail"
	"strings"

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
}

// Normalized validates s and returns the cleaned copy.
func (s FindingApprovalSettings) Normalized() (FindingApprovalSettings, error) {
	s.BackupContactEmail = strings.ToLower(strings.TrimSpace(s.BackupContactEmail))
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
