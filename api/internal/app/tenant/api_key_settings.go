package tenant

// The organization's API key policy (docs/architecture/api-keys.md,
// "Maximum lifetime"). Owners and administrators with settings:write change
// it. A longer maximum is a loosening: it needs a recent re-authentication,
// is audited high and every owner and administrator is told. A shorter one
// applies at once (existing keys keep their expiry and are flagged).

import (
	"context"
	"fmt"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// GetAPIKeySettings returns the organization's API key policy.
func (s *TenantService) GetAPIKeySettings(ctx context.Context, tenantID string) (*tenantdom.APIKeySettings, error) {
	parsedID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}
	t, err := s.repo.GetByID(ctx, parsedID)
	if err != nil {
		return nil, err
	}
	ks := t.TypedSettings().APIKeys
	return &ks, nil
}

// MaxAPIKeyLifetimeDays is the longest a new API key of the organization may
// live (the apikey service's lifetime policy).
func (s *TenantService) MaxAPIKeyLifetimeDays(ctx context.Context, tenantID shared.ID) (int, error) {
	t, err := s.repo.GetByID(ctx, tenantID)
	if err != nil {
		return 0, err
	}
	return t.TypedSettings().APIKeys.EffectiveMaxLifetimeDays(), nil
}

// UpdateAPIKeySettings replaces the organization's API key policy.
func (s *TenantService) UpdateAPIKeySettings(ctx context.Context, tenantID string, ks tenantdom.APIKeySettings, actx auditapp.AuditContext) (*tenantdom.APIKeySettings, error) {
	var before tenantdom.APIKeySettings
	loosened := false
	t, err := s.writeSettingsSection(ctx, tenantID, tenantdom.SectionAPIKeys, func(t *tenantdom.Tenant) error {
		before = t.TypedSettings().APIKeys
		if err := ks.Validate(); err != nil {
			return err
		}
		loosened = ks.EffectiveMaxLifetimeDays() > before.EffectiveMaxLifetimeDays()
		if loosened {
			if actx.ActorID == "" {
				return fmt.Errorf("%w: a longer API key lifetime needs a signed-in administrator", shared.ErrValidation)
			}
			if err := s.requireStepUp(ctx, actx.ActorID); err != nil {
				return err
			}
		}
		return t.UpdateAPIKeySettings(ks)
	})
	if err != nil {
		return nil, err
	}
	after := t.TypedSettings().APIKeys
	actx.TenantID = tenantID
	event := auditapp.NewSuccessEvent(audit.ActionTenantAPIKeyPolicyUpdated, audit.ResourceTypeTenant, tenantID).
		WithChanges(auditapp.DiffChanges(
			map[string]any{"max_lifetime_days": before.EffectiveMaxLifetimeDays()},
			map[string]any{"max_lifetime_days": after.EffectiveMaxLifetimeDays()})).
		WithMessage("API key maximum lifetime updated").
		WithMetadata("loosened", loosened)
	if loosened {
		event = event.WithSeverity(audit.SeverityHigh)
		s.notifyPolicyLoosened(ctx, tenantID, actx, "API key lifetime raised",
			fmt.Sprintf("the maximum lifetime of new API keys from %d to %d days",
				before.EffectiveMaxLifetimeDays(), after.EffectiveMaxLifetimeDays()), "/settings/api-keys")
	}
	s.logAudit(ctx, actx, event)
	return &after, nil
}
