package tenant

import (
	"context"
	"fmt"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// GetAssetReconciliationSettings returns which sources decide asset
// attributes for the tenant (RFC-069). Empty: the defaults.
func (s *TenantService) GetAssetReconciliationSettings(ctx context.Context, tenantID string) (*tenantdom.AssetReconciliationSettings, error) {
	parsedID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}
	t, err := s.repo.GetByID(ctx, parsedID)
	if err != nil {
		return nil, err
	}
	ar := t.TypedSettings().AssetReconciliation
	return &ar, nil
}

// UpdateAssetReconciliationSettings replaces the section and audits the
// change. Values already on assets change when their sources next report or
// a lock is released; nothing is re-resolved in bulk.
func (s *TenantService) UpdateAssetReconciliationSettings(
	ctx context.Context,
	tenantID string,
	ar tenantdom.AssetReconciliationSettings,
	actx auditapp.AuditContext,
) (*tenantdom.AssetReconciliationSettings, error) {
	var before tenantdom.AssetReconciliationSettings
	t, err := s.writeSettingsSection(ctx, tenantID, tenantdom.SectionAssetReconciliation, func(t *tenantdom.Tenant) error {
		before = t.TypedSettings().AssetReconciliation
		return t.UpdateAssetReconciliationSettings(ar)
	})
	if err != nil {
		return nil, err
	}
	actx.TenantID = tenantID
	event := auditapp.NewSuccessEvent(audit.ActionTenantAssetSourceUpdated, audit.ResourceTypeTenant, tenantID).
		WithChanges(auditapp.DiffChanges(before, t.TypedSettings().AssetReconciliation)).
		WithMessage("Asset source precedence updated").
		WithSeverity(audit.SeverityMedium)
	s.logAudit(ctx, actx, event)
	out := t.TypedSettings().AssetReconciliation
	return &out, nil
}
