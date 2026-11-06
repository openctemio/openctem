package tenant

import (
	"context"
	"fmt"
	"reflect"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
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

// AssetPolicyListener re-resolves the organization's assets after its
// source precedence changed (*assetapp.AssetService), in the background.
type AssetPolicyListener interface {
	AssetPolicyChanged(tenantID shared.ID)
}

// SetAssetPolicyListener wires the bulk re-resolution after a precedence
// change (nil: values move when their sources next report).
func (s *TenantService) SetAssetPolicyListener(l AssetPolicyListener) { s.assetPolicy = l }

// UpdateAssetReconciliationSettings replaces the section and audits the
// change. A change that demotes a connector (authoritative) source in any
// class needs step-up re-authentication. The organization's assets are then
// re-resolved in the background; only values that change get a timeline
// event.
func (s *TenantService) UpdateAssetReconciliationSettings(
	ctx context.Context,
	tenantID string,
	ar tenantdom.AssetReconciliationSettings,
	actx auditapp.AuditContext,
) (*tenantdom.AssetReconciliationSettings, error) {
	var before tenantdom.AssetReconciliationSettings
	demoted := false
	t, err := s.writeSettingsSection(ctx, tenantID, tenantdom.SectionAssetReconciliation, func(t *tenantdom.Tenant) error {
		before = t.TypedSettings().AssetReconciliation
		next, err := ar.Policy()
		if err != nil {
			return err
		}
		prev, err := before.Policy()
		if err != nil {
			prev = asset.DefaultReconciliationPolicy()
		}
		if asset.DemotesAuthoritative(prev, next) {
			demoted = true
			if err := s.requireStepUp(ctx, actx.ActorID); err != nil {
				return err
			}
		}
		return t.UpdateAssetReconciliationSettings(ar)
	})
	if err != nil {
		return nil, err
	}
	if s.assetPolicy != nil && !reflect.DeepEqual(before, t.TypedSettings().AssetReconciliation) {
		if pid, perr := shared.IDFromString(tenantID); perr == nil {
			s.assetPolicy.AssetPolicyChanged(pid)
		}
	}
	actx.TenantID = tenantID
	event := auditapp.NewSuccessEvent(audit.ActionTenantAssetSourceUpdated, audit.ResourceTypeTenant, tenantID).
		WithChanges(auditapp.DiffChanges(before, t.TypedSettings().AssetReconciliation)).
		WithMessage("Asset source precedence updated").
		WithMetadata("demotes_connector", demoted).
		WithSeverity(audit.SeverityMedium)
	s.logAudit(ctx, actx, event)
	out := t.TypedSettings().AssetReconciliation
	return &out, nil
}
