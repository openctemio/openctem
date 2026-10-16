package tenant

// The organization's finding approval settings section
// (api/docs/architecture/finding-status-lifecycle.md, "Approvals"). The route
// requires settings:write and a recent re-authentication; every change is
// audited at high severity with the values before and after.

import (
	"context"
	"fmt"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// GetFindingApprovalSettings returns the organization's finding approval
// settings (the zero value: defaults).
func (s *TenantService) GetFindingApprovalSettings(ctx context.Context, tenantID string) (*tenantdom.FindingApprovalSettings, error) {
	parsedID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}
	t, err := s.repo.GetByID(ctx, parsedID)
	if err != nil {
		return nil, err
	}
	fa := t.TypedSettings().FindingApprovals
	return &fa, nil
}

// UpdateFindingApprovalSettings applies change to the section (one
// compare-and-swap write) and audits before and after at high severity. It
// answers the settings before and after the change.
func (s *TenantService) UpdateFindingApprovalSettings(
	ctx context.Context,
	tenantID string,
	change func(*tenantdom.FindingApprovalSettings) error,
	actx auditapp.AuditContext,
) (before, after *tenantdom.FindingApprovalSettings, err error) {
	var prev tenantdom.FindingApprovalSettings
	t, err := s.writeSettingsSection(ctx, tenantID, tenantdom.SectionFindingApprovals, func(t *tenantdom.Tenant) error {
		prev = t.TypedSettings().FindingApprovals
		next := prev
		if err := change(&next); err != nil {
			return err
		}
		return t.UpdateFindingApprovalSettings(next)
	})
	if err != nil {
		return nil, nil, err
	}
	next := t.TypedSettings().FindingApprovals
	actx.TenantID = tenantID
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(audit.ActionFindingApprovalSettingsChanged, audit.ResourceTypeTenant, tenantID).
		WithChanges(auditapp.DiffChanges(prev, next)).
		WithMessage("Finding approval settings changed").
		WithSeverity(audit.SeverityHigh))
	return &prev, &next, nil
}
