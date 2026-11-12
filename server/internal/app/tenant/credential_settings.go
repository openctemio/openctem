package tenant

import (
	"context"
	"fmt"

	auditapp "github.com/openctemio/openctem/server/internal/app/audit"
	"github.com/openctemio/openctem/server/pkg/domain/audit"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/server/pkg/domain/tenant"
)

// GetCredentialSettings returns the organization's leaked-credential policy.
// The zero value means the platform default applies.
func (s *TenantService) GetCredentialSettings(ctx context.Context, tenantID string) (*tenantdom.CredentialSettings, error) {
	parsedID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}
	t, err := s.repo.GetByID(ctx, parsedID)
	if err != nil {
		return nil, err
	}
	cs := t.TypedSettings().Credentials
	return &cs, nil
}

// UpdateCredentialSettings replaces the organization's leaked-credential
// policy and audits the before/after values (high severity: it decides
// whether leaked secret values are kept).
func (s *TenantService) UpdateCredentialSettings(
	ctx context.Context,
	tenantID string,
	cs tenantdom.CredentialSettings,
	actx auditapp.AuditContext,
) (*tenantdom.CredentialSettings, error) {
	var before tenantdom.CredentialSettings
	t, err := s.writeSettingsSection(ctx, tenantID, tenantdom.SectionCredentials, func(t *tenantdom.Tenant) error {
		before = t.TypedSettings().Credentials
		return t.UpdateCredentialSettings(cs)
	})
	if err != nil {
		return nil, err
	}

	actx.TenantID = tenantID
	event := auditapp.NewSuccessEvent(audit.ActionTenantCredentialSettingsUpdated, audit.ResourceTypeTenant, tenantID).
		WithChanges(auditapp.DiffChanges(before, t.TypedSettings().Credentials)).
		WithMessage("Leaked credential settings updated").
		WithMetadata("store_secret_values_before", choiceLabel(before.StoreSecretValues)).
		WithMetadata("store_secret_values_after", choiceLabel(cs.StoreSecretValues))
	s.logAudit(ctx, actx, event)

	out := t.TypedSettings().Credentials
	return &out, nil
}

// choiceLabel renders an optional choice for the audit log.
func choiceLabel(v *bool) string {
	switch {
	case v == nil:
		return "platform_default"
	case *v:
		return "on"
	}
	return "off"
}
