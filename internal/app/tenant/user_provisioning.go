package tenant

// Administrator-created accounts. See docs/rfcs/RFC-025-user-onboarding.md.
//
// With self-registration off, people get an account in one of three ways: an
// organization owner/admin (or the platform administrator) creates it here, an
// invitation is accepted, or the organization's SSO admits them. An account
// created here has no password: the person sets one through a one-time link
// (hashed at rest, single use, short-lived). The link is emailed when the
// organization can send email; otherwise it is returned once to the creating
// administrator, and never to anyone else.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/api/internal/app/accesscontrol"
	auditapp "github.com/openctemio/api/internal/app/audit"
	"github.com/openctemio/api/pkg/crypto"
	"github.com/openctemio/api/pkg/domain/audit"
	"github.com/openctemio/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/api/pkg/domain/tenant"
	userdom "github.com/openctemio/api/pkg/domain/user"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/password"
)

// AccountSetupTTL is how long a one-time set-password link stays valid.
const AccountSetupTTL = 24 * time.Hour

var (
	// ErrAccountExists is returned when the email already has an account. The
	// administrator invites that person instead: attaching an existing account
	// to an organization needs the account owner's consent.
	ErrAccountExists = fmt.Errorf("%w: an account with this email already exists, invite them instead", shared.ErrConflict)
	// ErrEmailDomainNotAllowed is returned when the organization restricts
	// member email domains (Security.AllowedDomains) and the email is outside it.
	ErrEmailDomainNotAllowed = fmt.Errorf("%w: email domain is not allowed for this organization", shared.ErrValidation)
	// ErrNotPendingSetup is returned when a new set-password link is requested
	// for an account that is already in use, or that also belongs to another
	// organization (only the person can recover it, through forgot-password).
	ErrNotPendingSetup = fmt.Errorf("%w: this account is not awaiting setup", shared.ErrValidation)
)

// AccountSetupMailer delivers the one-time set-password link.
type AccountSetupMailer interface {
	CanDeliverTo(ctx context.Context, tenantID string) bool
	SendAccountSetupEmail(ctx context.Context, tenantID, recipientEmail, recipientName, teamName, token string, expiresIn time.Duration) error
}

// RoleGranter makes a role set the user's complete RBAC role set in a tenant.
type RoleGranter interface {
	GrantExactRoles(ctx context.Context, tenantID, userID string, roleIDs []string, grantedBy string, actx auditapp.AuditContext) error
}

// UserProvisioningService creates accounts on behalf of administrators.
type UserProvisioningService struct {
	tenants tenantdom.Repository
	users   userdom.Repository
	roles   RoleGranter
	mailer  AccountSetupMailer
	audit   *auditapp.AuditService
	logger  *logger.Logger
	now     func() time.Time
}

// NewUserProvisioningService wires the service. mailer and audit may be nil.
func NewUserProvisioningService(tenants tenantdom.Repository, users userdom.Repository, roles RoleGranter, mailer AccountSetupMailer, auditSvc *auditapp.AuditService, log *logger.Logger) *UserProvisioningService {
	return &UserProvisioningService{
		tenants: tenants, users: users, roles: roles, mailer: mailer, audit: auditSvc,
		logger: log.With("service", "user_provisioning"), now: time.Now,
	}
}

// CreateUserInput describes an account an administrator creates in an
// organization.
type CreateUserInput struct {
	TenantID string
	Email    string
	Name     string
	// RoleIDs is the user's complete RBAC role set (system or tenant roles,
	// never the owner role). The caller has already checked the creator may
	// grant them.
	RoleIDs []string
	// CreatedBy is the creating tenant user; zero for the platform administrator.
	CreatedBy shared.ID
}

// ProvisionedUser is the result of creating an account or reissuing its link.
type ProvisionedUser struct {
	User       *userdom.User
	Membership *tenantdom.Membership
	// EmailSent is true when the set-password link was emailed to the user.
	EmailSent bool
	// SetupToken is set only when the link was NOT emailed: it is returned once
	// to the administrator, who hands it over. It is never stored in clear.
	SetupToken     string
	SetupExpiresAt time.Time
}

// CreateUser creates a password-less local account, makes it a member of the
// organization with exactly in.RoleIDs, and issues its one-time set-password
// link. It refuses an email that already has an account and an email outside
// the organization's allowed domains.
func (s *UserProvisioningService) CreateUser(ctx context.Context, in CreateUserInput, actx auditapp.AuditContext) (*ProvisionedUser, error) {
	tenantID, err := shared.IDFromString(in.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	email := strings.ToLower(strings.TrimSpace(in.Email))
	if email == "" || !strings.Contains(email, "@") {
		return nil, fmt.Errorf("%w: a valid email is required", shared.ErrValidation)
	}
	if err := accesscontrol.ValidateGrantableRoleIDs(in.RoleIDs); err != nil {
		return nil, err
	}

	t, err := s.tenants.GetByID(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if !t.TypedSettings().Security.EmailDomainAllowed(email) {
		return nil, ErrEmailDomainNotAllowed
	}

	if _, err := s.users.GetByEmail(ctx, email); err == nil {
		return nil, ErrAccountExists
	} else if !shared.IsNotFound(err) {
		return nil, fmt.Errorf("look up account: %w", err)
	}

	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = email
	}
	u, err := userdom.NewProvisionedLocalUser(email, name)
	if err != nil {
		return nil, err
	}
	if err := s.users.Create(ctx, u); err != nil {
		// Lost a race with another creation of the same email.
		if _, gerr := s.users.GetByEmail(ctx, email); gerr == nil {
			return nil, ErrAccountExists
		}
		return nil, fmt.Errorf("create account: %w", err)
	}

	var invitedBy *shared.ID
	if !in.CreatedBy.IsZero() {
		by := in.CreatedBy
		invitedBy = &by
	}
	membership, err := tenantdom.NewMembership(u.ID(), tenantID, accesscontrol.MembershipRoleForRoleIDs(in.RoleIDs), invitedBy)
	if err == nil {
		err = s.tenants.CreateMembership(ctx, membership)
	}
	if err != nil {
		s.discardAccount(ctx, u.ID())
		return nil, fmt.Errorf("add member: %w", err)
	}

	grantedBy := ""
	if invitedBy != nil {
		grantedBy = invitedBy.String()
	}
	if err := s.roles.GrantExactRoles(ctx, tenantID.String(), u.ID().String(), in.RoleIDs, grantedBy, actx); err != nil {
		if derr := s.tenants.DeleteMembership(ctx, membership.ID()); derr != nil {
			s.logger.Error("rollback membership after role grant failure", "tenant_id", tenantID.String(), "error", derr)
		}
		s.discardAccount(ctx, u.ID())
		if errors.Is(err, shared.ErrValidation) || errors.Is(err, shared.ErrNotFound) {
			return nil, err
		}
		return nil, fmt.Errorf("grant roles: %w", err)
	}

	result, err := s.issueSetupLink(ctx, t, u)
	if err != nil {
		return nil, err
	}
	result.Membership = membership

	actx.TenantID = tenantID.String()
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(audit.ActionUserCreated, audit.ResourceTypeUser, u.ID().String()).
		WithResourceName(email).
		WithMessage(fmt.Sprintf("Account created for %s by an administrator", email)).
		WithMetadata("role_ids_count", len(in.RoleIDs)).
		WithMetadata("setup_link_emailed", result.EmailSent).
		WithSeverity(audit.SeverityHigh))
	return result, nil
}

// CreateAccount creates a password-less account that belongs to no
// organization yet. The platform administrator uses it for the owner of an
// organization being created; the caller then creates the organization with
// this account as owner and issues the set-password link (ReissueSetupLink),
// or calls DiscardAccount if creating the organization fails.
func (s *UserProvisioningService) CreateAccount(ctx context.Context, email, name string) (*userdom.User, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" || !strings.Contains(email, "@") {
		return nil, fmt.Errorf("%w: a valid email is required", shared.ErrValidation)
	}
	if _, err := s.users.GetByEmail(ctx, email); err == nil {
		return nil, ErrAccountExists
	} else if !shared.IsNotFound(err) {
		return nil, fmt.Errorf("look up account: %w", err)
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = email
	}
	u, err := userdom.NewProvisionedLocalUser(email, name)
	if err != nil {
		return nil, err
	}
	if err := s.users.Create(ctx, u); err != nil {
		if _, gerr := s.users.GetByEmail(ctx, email); gerr == nil {
			return nil, ErrAccountExists
		}
		return nil, fmt.Errorf("create account: %w", err)
	}
	return u, nil
}

// DiscardAccount deletes an account created by CreateAccount whose
// organization could not be created.
func (s *UserProvisioningService) DiscardAccount(ctx context.Context, id shared.ID) {
	s.discardAccount(ctx, id)
}

// ReissueSetupLink replaces the one-time set-password link of an account that
// an administrator created and that has never been used. It refuses any
// account that has a password, has signed in, or belongs to another
// organization too: those accounts belong to their owner, and handing a
// set-password link for them to an organization administrator would let that
// administrator take them over.
func (s *UserProvisioningService) ReissueSetupLink(ctx context.Context, tenantIDStr, userIDStr string, actx auditapp.AuditContext) (*ProvisionedUser, error) {
	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	userID, err := shared.IDFromString(userIDStr)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid user id", shared.ErrValidation)
	}
	membership, err := s.tenants.GetMembership(ctx, userID, tenantID)
	if err != nil {
		return nil, err
	}
	if membership.IsSuspended() {
		return nil, ErrNotPendingSetup
	}
	u, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if !u.IsPendingSetup() {
		return nil, ErrNotPendingSetup
	}
	memberships, err := s.tenants.GetUserMembershipsWithStatus(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("list memberships: %w", err)
	}
	for _, m := range append(append([]tenantdom.UserMembership{}, memberships.Active...), memberships.Suspended...) {
		if m.TenantID != tenantID.String() {
			return nil, ErrNotPendingSetup
		}
	}
	t, err := s.tenants.GetByID(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	result, err := s.issueSetupLink(ctx, t, u)
	if err != nil {
		return nil, err
	}
	result.Membership = membership

	actx.TenantID = tenantID.String()
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(audit.ActionUserUpdated, audit.ResourceTypeUser, u.ID().String()).
		WithResourceName(u.Email()).
		WithMessage(fmt.Sprintf("New set-password link issued for %s", u.Email())).
		WithMetadata("setup_link_emailed", result.EmailSent).
		WithSeverity(audit.SeverityHigh))
	return result, nil
}

// issueSetupLink stores a fresh single-use token (hash only) on the account,
// replacing any previous one, then emails it or hands it back.
func (s *UserProvisioningService) issueSetupLink(ctx context.Context, t *tenantdom.Tenant, u *userdom.User) (*ProvisionedUser, error) {
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
	if s.mailer != nil && s.mailer.CanDeliverTo(ctx, tenantID) {
		if err := s.mailer.SendAccountSetupEmail(ctx, tenantID, u.Email(), u.Name(), t.Name(), token, AccountSetupTTL); err == nil {
			result.EmailSent = true
			return result, nil
		}
		// Delivery failed: fall back to handing the link to the administrator
		// so the account is not stranded.
		s.logger.Warn("account setup email failed; returning the link to the administrator",
			"tenant_id", tenantID, "user_id", u.ID().String())
	}
	result.SetupToken = token
	return result, nil
}

func (s *UserProvisioningService) discardAccount(ctx context.Context, id shared.ID) {
	if err := s.users.Delete(ctx, id); err != nil {
		s.logger.Error("rollback: delete created account", "user_id", id.String(), "error", err)
	}
}

func (s *UserProvisioningService) logAudit(ctx context.Context, actx auditapp.AuditContext, event auditapp.AuditEvent) {
	if s.audit == nil {
		return
	}
	if err := s.audit.LogEvent(ctx, actx, event); err != nil {
		s.logger.Error("failed to log audit event", "action", event.Action, "error", err)
	}
}
