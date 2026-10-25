package tenant

import (
	"context"
	"fmt"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// GetFindingViewSettings returns the organization's findings work-view
// defaults (docs/architecture/findings-work-views.md).
func (s *TenantService) GetFindingViewSettings(ctx context.Context, tenantID string) (*tenantdom.FindingViewSettings, error) {
	parsedID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}
	t, err := s.repo.GetByID(ctx, parsedID)
	if err != nil {
		return nil, err
	}
	fv := t.TypedSettings().FindingViews
	return &fv, nil
}

// UpdateFindingViewSettingsInput: nil = unchanged.
type UpdateFindingViewSettingsInput struct {
	IncludeInformational *bool
}

// UpdateFindingViewSettings changes the findings work-view defaults and
// audits the before/after values.
func (s *TenantService) UpdateFindingViewSettings(ctx context.Context, tenantID string, input UpdateFindingViewSettingsInput, actx auditapp.AuditContext) (*tenantdom.FindingViewSettings, error) {
	var before tenantdom.FindingViewSettings
	t, err := s.writeSettingsSection(ctx, tenantID, tenantdom.SectionFindingViews, func(t *tenantdom.Tenant) error {
		before = t.TypedSettings().FindingViews
		fv := before
		if input.IncludeInformational != nil {
			fv.IncludeInformational = *input.IncludeInformational
		}
		return t.UpdateFindingViewSettings(fv)
	})
	if err != nil {
		return nil, err
	}
	actx.TenantID = tenantID
	after := t.TypedSettings().FindingViews
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(audit.ActionTenantSettingsUpdated, audit.ResourceTypeTenant, tenantID).
		WithChanges(auditapp.DiffChanges(before, after)).
		WithMessage("Finding view settings updated"))
	return &after, nil
}
