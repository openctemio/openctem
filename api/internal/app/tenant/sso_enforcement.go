package tenant

import (
	"context"
	"errors"
	"fmt"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Preconditions of turning Require SSO on. Both exist so that an organization
// that enforces SSO can always still be entered: the IdP path has been proven
// by an administrator, and an owner can use break-glass (password plus their
// second factor).
var (
	// ErrSSOEnforceNeedsAdminSignIn: no owner or admin has signed in through
	// the organization's identity provider yet.
	ErrSSOEnforceNeedsAdminSignIn = fmt.Errorf("%w: cannot enforce SSO — an owner or admin must sign in through the identity provider once first", shared.ErrValidation)
	// ErrSSOEnforceNeedsOwnerSecondFactor: no owner has two-factor
	// authentication, so owner break-glass would not work.
	ErrSSOEnforceNeedsOwnerSecondFactor = fmt.Errorf("%w: cannot enforce SSO — an owner must turn on two-factor authentication first, so owner break-glass works", shared.ErrValidation)
)

// SetSSOEnforcementStore wires the store behind the Require SSO guard.
func (s *TenantService) SetSSOEnforcementStore(st SSOEnforcementStore) { s.ssoStore = st }

// requireSSOEnforcePreconditions refuses turning Require SSO on until an
// administrator has signed in through the IdP and an owner has a second
// factor. Fail closed: an unwired store or a lookup error refuses.
func (s *TenantService) requireSSOEnforcePreconditions(ctx context.Context, tenantID shared.ID) error {
	if s.ssoStore == nil {
		return ErrSSOEnforceNeedsAdminSignIn
	}
	signedIn, err := s.ssoStore.HasAdminSSOSignIn(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("failed to check administrator SSO sign-in: %w", err)
	}
	if !signedIn {
		return ErrSSOEnforceNeedsAdminSignIn
	}
	hasFactor, err := s.ssoStore.HasOwnerWithSecondFactor(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("failed to check owner second factor: %w", err)
	}
	if !hasFactor {
		return ErrSSOEnforceNeedsOwnerSecondFactor
	}
	return nil
}

// SSOEnforcementReadiness is what the console shows before Require SSO is
// turned on: the two preconditions and what revoking at enable would end.
type SSOEnforcementReadiness struct {
	AdminSSOSignIn    bool `json:"admin_sso_signin"`
	OwnerSecondFactor bool `json:"owner_second_factor"`
	APIKeys           int  `json:"api_keys"`
	ConnectorGrants   int  `json:"connector_grants"`
}

// SSOEnforcementReadiness reads the state of the Require SSO preconditions.
func (s *TenantService) SSOEnforcementReadiness(ctx context.Context, tenantID shared.ID) (*SSOEnforcementReadiness, error) {
	if s.ssoStore == nil {
		return nil, errors.New("sso enforcement store is not wired")
	}
	var r SSOEnforcementReadiness
	var err error
	if r.AdminSSOSignIn, err = s.ssoStore.HasAdminSSOSignIn(ctx, tenantID); err != nil {
		return nil, fmt.Errorf("failed to check administrator SSO sign-in: %w", err)
	}
	if r.OwnerSecondFactor, err = s.ssoStore.HasOwnerWithSecondFactor(ctx, tenantID); err != nil {
		return nil, fmt.Errorf("failed to check owner second factor: %w", err)
	}
	if r.APIKeys, r.ConnectorGrants, err = s.ssoStore.CountCredentials(ctx, tenantID); err != nil {
		return nil, fmt.Errorf("failed to count credentials: %w", err)
	}
	return &r, nil
}

// revokeCredentialsAtSSOEnforce ends the user API keys and connector grants
// that exist when Require SSO turns on, unless the caller opted out. Keys and
// grants made afterwards, from SSO sessions, keep working. The settings are
// already saved; a failure here is logged loudly and the audit entry says
// what happened, so the administrator can retry from the key list.
func (s *TenantService) revokeCredentialsAtSSOEnforce(ctx context.Context, tenantID shared.ID, actx auditapp.AuditContext, want *bool) {
	if (want != nil && !*want) || s.ssoStore == nil {
		return
	}
	var actor shared.ID
	if id, err := shared.IDFromString(actx.ActorID); err == nil {
		actor = id
	}
	keys, grants, err := s.ssoStore.RevokeCredentials(ctx, tenantID, actor)
	if err != nil {
		s.logger.Error("failed to revoke credentials when SSO became required",
			"tenant_id", tenantID.String(), "error", err)
		return
	}
	actx.TenantID = tenantID.String()
	ev := auditapp.NewSuccessEvent(audit.ActionTenantSettingsUpdated, audit.ResourceTypeTenant, tenantID.String()).
		WithSeverity(audit.SeverityHigh).
		WithMessage(fmt.Sprintf("Required SSO: revoked %d API keys and %d connector grants", keys, grants)).
		WithMetadata("revoked_api_keys", keys).
		WithMetadata("revoked_connector_grants", grants)
	s.logAudit(ctx, actx, ev)
}
