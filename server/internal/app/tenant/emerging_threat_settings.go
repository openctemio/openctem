package tenant

import (
	"context"
	"fmt"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// GetEmergingThreatSettings returns the organization's emerging-threat
// alert policy with its defaults filled (docs/rfcs/RFC-117-emerging-threat-alerts.md).
func (s *TenantService) GetEmergingThreatSettings(ctx context.Context, tenantID string) (*tenantdom.EmergingThreatSettings, error) {
	parsedID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}
	t, err := s.repo.GetByID(ctx, parsedID)
	if err != nil {
		return nil, err
	}
	es := t.TypedSettings().EmergingThreats.Effective()
	return &es, nil
}

// UpdateEmergingThreatSettings replaces the organization's emerging-threat
// alert policy and audits the before/after values.
func (s *TenantService) UpdateEmergingThreatSettings(ctx context.Context, tenantID string, es tenantdom.EmergingThreatSettings, actx auditapp.AuditContext) (*tenantdom.EmergingThreatSettings, error) {
	var before tenantdom.EmergingThreatSettings
	t, err := s.writeSettingsSection(ctx, tenantID, tenantdom.SectionEmergingThreats, func(t *tenantdom.Tenant) error {
		before = t.TypedSettings().EmergingThreats
		return t.UpdateEmergingThreatSettings(es)
	})
	if err != nil {
		return nil, err
	}
	actx.TenantID = tenantID
	event := auditapp.NewSuccessEvent(audit.ActionTenantEmergingThreatsUpdated, audit.ResourceTypeTenant, tenantID).
		WithChanges(auditapp.DiffChanges(before, t.TypedSettings().EmergingThreats)).
		WithMessage("Emerging-threat alert settings updated").
		WithMetadata("disabled", es.Disabled).
		WithMetadata("asset_names_in_messages", es.AssetNamesInMessages)
	s.logAudit(ctx, actx, event)
	out := t.TypedSettings().EmergingThreats.Effective()
	return &out, nil
}
