package tenant

// The organization's scan approval settings section (RFC-073,
// docs/rfcs/RFC-073-scan-approval-governance.md). The routes require the
// owner (mode) or an administrator (rules), step-up and a reason; the scan
// governance service checks the platform policy before it writes the mode.

import (
	"context"
	"fmt"
	"strings"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/scangov"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// GetScanGovernanceSettings returns the organization's scan approval
// settings (the zero value: Off, no rules).
func (s *TenantService) GetScanGovernanceSettings(ctx context.Context, tenantID string) (*tenantdom.ScanGovernanceSettings, error) {
	parsedID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}
	t, err := s.repo.GetByID(ctx, parsedID)
	if err != nil {
		return nil, err
	}
	gs := t.TypedSettings().ScanGovernance
	return &gs, nil
}

// UpdateScanGovernanceSettings applies change to the section (one
// compare-and-swap write) and audits the before/after values at high
// severity with the reason. action is the audit action of the change.
func (s *TenantService) UpdateScanGovernanceSettings(
	ctx context.Context,
	tenantID string,
	change func(*tenantdom.ScanGovernanceSettings) error,
	action audit.Action,
	reason string,
	actx auditapp.AuditContext,
) (*tenantdom.ScanGovernanceSettings, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" || len(reason) > scangov.MaxNoteLen {
		return nil, fmt.Errorf("%w: a reason (at most %d characters) is required", shared.ErrValidation, scangov.MaxNoteLen)
	}
	var before tenantdom.ScanGovernanceSettings
	t, err := s.writeSettingsSection(ctx, tenantID, tenantdom.SectionScanGovernance, func(t *tenantdom.Tenant) error {
		before = t.TypedSettings().ScanGovernance
		next := before
		next.Rules = append([]scangov.Rule(nil), before.Rules...)
		if err := change(&next); err != nil {
			return err
		}
		return t.UpdateScanGovernanceSettings(next)
	})
	if err != nil {
		return nil, err
	}
	after := t.TypedSettings().ScanGovernance
	actx.TenantID = tenantID
	event := auditapp.NewSuccessEvent(action, audit.ResourceTypeTenant, tenantID).
		WithChanges(auditapp.DiffChanges(before, after)).
		WithMessage("Scan approval settings changed").
		WithMetadata("reason", reason).
		WithMetadata("mode_before", string(before.EffectiveMode())).
		WithMetadata("mode_after", string(after.EffectiveMode())).
		WithSeverity(audit.SeverityHigh)
	s.logAudit(ctx, actx, event)
	return &after, nil
}
