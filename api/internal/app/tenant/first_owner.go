package tenant

// First-owner bootstrap by the platform administrator (RFC-022, owner decision
// 2026-10-02).
//
// The platform administrator belongs to no organization and must not be able
// to put a person of its choosing into one: that would let it read the
// organization's data through an account it controls. So the console may
// create exactly one kind of organization user: the FIRST owner of an
// organization that has no owner. An owner who is suspended still counts: the
// organization and its data are theirs. After that, the owner and its
// administrators add people themselves.
//
// Owner recovery is the one exception: when every owner is suspended (so
// nobody can manage the organization), a super admin may create a new owner
// with an explicit recovery request. It is refused while any owner is active,
// written to the organization's audit log at critical severity (and to the
// platform admin audit log by the route), and its set-password link goes by
// email only: it is never returned, so the administrator cannot take over an
// organization that has data. An organization that cannot send email cannot
// be recovered this way.
//
// The owner's one-time set-password link:
//   - is emailed when the organization can send email (tenant or system
//     SMTP), and is then never returned to the administrator, even when the
//     send fails (the owner recovers with forgot-password);
//   - is returned once to the administrator only when email cannot be sent
//     at all. That is the one case where handing it over is allowed: without
//     SMTP there is no other way to reach the new owner, and the organization
//     has no one else who could invite them. The administrator never knows a
//     password: the account has none until the owner sets it through the link,
//     so the owner's first sign-in is always with a password they chose.

import (
	"context"
	"fmt"
	"strings"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	userdom "github.com/openctemio/openctem/api/pkg/domain/user"
	"github.com/openctemio/openctem/api/pkg/password"
)

// FirstOwnerStore checks for and creates an organization's first owner
// atomically. Implemented by the postgres tenant repository.
type FirstOwnerStore interface {
	OwnerPresence(ctx context.Context, tenantID shared.ID) (tenantdom.OwnerPresence, error)
	// CreateFirstOwnerMembership inserts the owner membership under a lock,
	// returning tenantdom.ErrOrganizationHasOwner when an owner exists (with
	// recovery: when an active owner exists).
	CreateFirstOwnerMembership(ctx context.Context, m *tenantdom.Membership, recovery bool) error
}

// ErrOwnerRecoveryNeedsEmail is returned when an owner recovery is requested
// for an organization that cannot send email: the recovery link is never
// handed to the administrator.
var ErrOwnerRecoveryNeedsEmail = fmt.Errorf("%w: owner recovery sends the set-password link by email only, and this organization cannot send email; configure SMTP first", shared.ErrValidation)

func (s *UserProvisioningService) firstOwnerStore() (FirstOwnerStore, error) {
	store, ok := s.tenants.(FirstOwnerStore)
	if !ok {
		return nil, fmt.Errorf("first-owner bootstrap is not supported by this tenant repository")
	}
	return store, nil
}

// CreateFirstOwner creates a password-less account for email and makes it the
// owner of an organization that has no owner, active or suspended. It returns
// tenantdom.ErrOrganizationHasOwner when the organization already has one,
// ErrAccountExists when the email already has an account, and
// ErrEmailDomainNotAllowed when the organization restricts email domains.
func (s *UserProvisioningService) CreateFirstOwner(ctx context.Context, tenantIDStr, email, name string, actx auditapp.AuditContext) (*ProvisionedUser, error) {
	return s.createOwner(ctx, tenantIDStr, email, name, actx, false)
}

// RecoverOwner creates a new owner for an organization whose owners are all
// suspended. The caller must have checked that the actor is a super admin.
// It returns tenantdom.ErrOrganizationHasOwner while any owner is active, and
// ErrOwnerRecoveryNeedsEmail when the organization cannot send email; the
// set-password link is emailed and never returned.
func (s *UserProvisioningService) RecoverOwner(ctx context.Context, tenantIDStr, email, name string, actx auditapp.AuditContext) (*ProvisionedUser, error) {
	return s.createOwner(ctx, tenantIDStr, email, name, actx, true)
}

func (s *UserProvisioningService) createOwner(ctx context.Context, tenantIDStr, email, name string, actx auditapp.AuditContext, recovery bool) (*ProvisionedUser, error) {
	store, err := s.firstOwnerStore()
	if err != nil {
		return nil, err
	}
	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" || !strings.Contains(email, "@") {
		return nil, fmt.Errorf("%w: a valid email is required", shared.ErrValidation)
	}
	t, err := s.tenants.GetByID(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	// Refuse early, before anything is created, when an owner exists. The
	// insert below checks again under a lock.
	presence, err := store.OwnerPresence(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if presence.BlocksBootstrap(recovery) {
		return nil, tenantdom.ErrOrganizationHasOwner
	}
	if recovery && (s.mailer == nil || !s.mailer.CanDeliverTo(ctx, tenantID.String())) {
		return nil, ErrOwnerRecoveryNeedsEmail
	}
	if !t.TypedSettings().Security.EmailDomainAllowed(email) {
		return nil, ErrEmailDomainNotAllowed
	}

	u, err := s.CreateAccount(ctx, email, name)
	if err != nil {
		return nil, err
	}
	membership, err := tenantdom.NewOwnerMembership(u.ID(), tenantID)
	if err == nil {
		err = store.CreateFirstOwnerMembership(ctx, membership, recovery)
	}
	if err != nil {
		s.discardAccount(ctx, u.ID())
		return nil, err
	}

	var result *ProvisionedUser
	if recovery {
		result, err = s.issueRecoveryOwnerLink(ctx, t, u, actx, presence)
	} else {
		result, err = s.issueFirstOwnerLink(ctx, t, u, actx, "Owner account created for %s by a platform administrator")
	}
	if err != nil {
		return nil, err
	}
	result.Membership = membership
	return result, nil
}

// issueRecoveryOwnerLink emails the recovered owner's set-password link (never
// returning it, even when the send fails: the owner then uses forgot-password)
// and writes the critical tenant audit event.
func (s *UserProvisioningService) issueRecoveryOwnerLink(ctx context.Context, t *tenantdom.Tenant, u *userdom.User, actx auditapp.AuditContext, presence tenantdom.OwnerPresence) (*ProvisionedUser, error) {
	token, err := password.GenerateResetToken()
	if err != nil {
		return nil, fmt.Errorf("generate setup token: %w", err)
	}
	expiresAt := s.now().Add(AccountSetupTTL)
	u.SetPasswordResetToken(crypto.HashToken(token), expiresAt)
	if err := s.users.Update(ctx, u); err != nil {
		return nil, fmt.Errorf("store setup token: %w", err)
	}

	result := &ProvisionedUser{User: u, SetupExpiresAt: expiresAt}
	tenantID := t.ID().String()
	if s.mailer == nil {
		result.EmailFailed = true
	} else if err := s.mailer.SendAccountSetupEmail(ctx, tenantID, u.Email(), u.Name(), t.Name(), token, AccountSetupTTL); err != nil {
		s.logger.Error("owner recovery setup email failed; link not returned (owner can use forgot-password)",
			"tenant_id", tenantID, "user_id", u.ID().String())
		result.EmailFailed = true
	} else {
		result.EmailSent = true
	}

	actx.TenantID = tenantID
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(audit.ActionUserCreated, audit.ResourceTypeUser, u.ID().String()).
		WithResourceName(u.Email()).
		WithMessage(fmt.Sprintf("Owner recovery: owner account created for %s by a platform administrator because every owner of the organization is suspended", u.Email())).
		WithMetadata("role", tenantdom.RoleOwner.String()).
		WithMetadata("owner_recovery", true).
		WithMetadata("suspended_owners_present", presence.AllSuspended()).
		WithMetadata("setup_link_emailed", result.EmailSent).
		WithMetadata("setup_link_returned", false).
		WithSeverity(audit.SeverityCritical))
	return result, nil
}

// IssueFirstOwnerSetupLink issues the set-password link of the owner account
// the platform administrator created together with organization t (POST
// /admin/tenants with a new owner_email), under the same delivery rule as
// CreateFirstOwner. u must be a pending-setup account that owns t.
func (s *UserProvisioningService) IssueFirstOwnerSetupLink(ctx context.Context, t *tenantdom.Tenant, u *userdom.User, actx auditapp.AuditContext) (*ProvisionedUser, error) {
	if !u.IsPendingSetup() {
		return nil, ErrNotPendingSetup
	}
	m, err := s.tenants.GetMembership(ctx, u.ID(), t.ID())
	if err != nil {
		return nil, err
	}
	if !m.IsOwner() {
		return nil, ErrNotPendingSetup
	}
	result, err := s.issueFirstOwnerLink(ctx, t, u, actx, "Owner account created for %s with the organization by a platform administrator")
	if err != nil {
		return nil, err
	}
	result.Membership = m
	return result, nil
}

// issueFirstOwnerLink stores a fresh single-use token (hash only) on the
// account and delivers it by the first-owner rule, then writes the tenant
// audit event (the actor is the platform administrator, see actx).
func (s *UserProvisioningService) issueFirstOwnerLink(ctx context.Context, t *tenantdom.Tenant, u *userdom.User, actx auditapp.AuditContext, message string) (*ProvisionedUser, error) {
	token, err := password.GenerateResetToken()
	if err != nil {
		return nil, fmt.Errorf("generate setup token: %w", err)
	}
	expiresAt := s.now().Add(AccountSetupTTL)
	u.SetPasswordResetToken(crypto.HashToken(token), expiresAt)
	if err := s.users.Update(ctx, u); err != nil {
		return nil, fmt.Errorf("store setup token: %w", err)
	}

	result := &ProvisionedUser{User: u, SetupExpiresAt: expiresAt}
	tenantID := t.ID().String()
	switch {
	case s.mailer != nil && s.mailer.CanDeliverTo(ctx, tenantID):
		if err := s.mailer.SendAccountSetupEmail(ctx, tenantID, u.Email(), u.Name(), t.Name(), token, AccountSetupTTL); err != nil {
			// Never fall back to handing the link to the administrator.
			s.logger.Error("first owner setup email failed; link not returned (owner can use forgot-password)",
				"tenant_id", tenantID, "user_id", u.ID().String())
			result.EmailFailed = true
		} else {
			result.EmailSent = true
		}
	default:
		result.SetupToken = token
	}

	actx.TenantID = tenantID
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(audit.ActionUserCreated, audit.ResourceTypeUser, u.ID().String()).
		WithResourceName(u.Email()).
		WithMessage(fmt.Sprintf(message, u.Email())).
		WithMetadata("role", tenantdom.RoleOwner.String()).
		WithMetadata("bootstrap_owner", true).
		WithMetadata("setup_link_emailed", result.EmailSent).
		WithMetadata("setup_link_returned", result.SetupToken != "").
		WithSeverity(audit.SeverityHigh))
	return result, nil
}
