package tenant

import (
	"context"
	"fmt"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// GetDashboardSettings returns the organization's dashboard defaults (the
// zero value means the defaults).
func (s *TenantService) GetDashboardSettings(ctx context.Context, tenantID string) (*tenantdom.DashboardSettings, error) {
	parsedID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}
	t, err := s.repo.GetByID(ctx, parsedID)
	if err != nil {
		return nil, err
	}
	ds := t.TypedSettings().Dashboards
	return &ds, nil
}

// UpdateDashboardSettings replaces the organization's dashboard defaults and
// audits the before/after values. The caller (the dashboard service) has
// validated them against the organization's refresh floor.
func (s *TenantService) UpdateDashboardSettings(ctx context.Context, tenantID string, ds tenantdom.DashboardSettings, actx auditapp.AuditContext) (*tenantdom.DashboardSettings, error) {
	var before tenantdom.DashboardSettings
	t, err := s.writeSettingsSection(ctx, tenantID, tenantdom.SectionDashboards, func(t *tenantdom.Tenant) error {
		before = t.TypedSettings().Dashboards
		return t.UpdateDashboardSettings(ds)
	})
	if err != nil {
		return nil, err
	}
	actx.TenantID = tenantID
	event := auditapp.NewSuccessEvent(audit.ActionDashboardSettingsUpdated, audit.ResourceTypeTenant, tenantID).
		WithChanges(auditapp.DiffChanges(before, t.TypedSettings().Dashboards)).
		WithMessage("Dashboard defaults updated").
		WithMetadata("default_refresh_schedule", ds.DefaultRefreshSchedule)
	s.logAudit(ctx, actx, event)
	out := t.TypedSettings().Dashboards
	return &out, nil
}
