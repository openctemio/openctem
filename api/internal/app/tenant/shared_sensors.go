package tenant

// The organization owner's shared sensor opt-out
// (docs/rfcs/RFC-100-shared-sensors.md §5, layer 3). The route requires the
// owner; every change is audited at high severity.

import (
	"context"
	"fmt"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// GetSharedSensorsSettings returns the organization's shared sensor choice
// (the zero value: use them when available).
func (s *TenantService) GetSharedSensorsSettings(ctx context.Context, tenantID string) (*tenantdom.SharedSensorsSettings, error) {
	parsedID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}
	t, err := s.repo.GetByID(ctx, parsedID)
	if err != nil {
		return nil, err
	}
	ss := t.TypedSettings().SharedSensors
	return &ss, nil
}

// SharedSensorsOptedOut reports whether the organization's owner opted out
// of shared sensors. An unreadable setting is an error (the access policy
// refuses on it).
func (s *TenantService) SharedSensorsOptedOut(ctx context.Context, tenantID shared.ID) (bool, error) {
	ss, err := s.GetSharedSensorsSettings(ctx, tenantID.String())
	if err != nil {
		return false, err
	}
	return ss.OptOut, nil
}

// UpdateSharedSensorsSettings replaces the organization's shared sensor
// choice (one compare-and-swap section write) and audits it.
func (s *TenantService) UpdateSharedSensorsSettings(
	ctx context.Context,
	tenantID string,
	ss tenantdom.SharedSensorsSettings,
	actx auditapp.AuditContext,
) (*tenantdom.SharedSensorsSettings, error) {
	var before tenantdom.SharedSensorsSettings
	t, err := s.writeSettingsSection(ctx, tenantID, tenantdom.SectionSharedSensors, func(t *tenantdom.Tenant) error {
		before = t.TypedSettings().SharedSensors
		return t.UpdateSharedSensorsSettings(ss)
	})
	if err != nil {
		return nil, err
	}
	after := t.TypedSettings().SharedSensors
	actx.TenantID = tenantID
	msg := "Shared sensors: use them when available"
	if after.OptOut {
		msg = "Shared sensors: opted out"
	}
	event := auditapp.NewSuccessEvent(audit.ActionTenantSharedSensorsUpdated, audit.ResourceTypeTenant, tenantID).
		WithChanges(auditapp.DiffChanges(before, after)).
		WithMessage(msg).
		WithMetadata("opt_out", after.OptOut).
		WithSeverity(audit.SeverityHigh)
	s.logAudit(ctx, actx, event)
	return &after, nil
}
