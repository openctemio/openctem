package scim

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	userdom "github.com/openctemio/openctem/api/pkg/domain/user"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// UserStore is the narrow user-repository surface SCIM provisioning needs.
type UserStore interface {
	GetByEmail(ctx context.Context, email string) (*userdom.User, error)
	GetByID(ctx context.Context, id shared.ID) (*userdom.User, error)
	Create(ctx context.Context, u *userdom.User) error
	Update(ctx context.Context, u *userdom.User) error
}

// MembershipReader reads tenant memberships (tenant.Repository satisfies it).
type MembershipReader interface {
	GetMembership(ctx context.Context, userID, tenantID shared.ID) (*tenantdom.Membership, error)
	ListMembersByTenant(ctx context.Context, tenantID shared.ID) ([]*tenantdom.Membership, error)
}

// MembershipManager applies membership lifecycle with full side effects
// (session revoke, permission-cache clear, audit). An adapter over
// tenant.TenantService injects the SCIM system audit context.
type MembershipManager interface {
	AddMember(ctx context.Context, tenantID, userID shared.ID, role string) error
	SuspendMember(ctx context.Context, tenantID, membershipID shared.ID) error
	ReactivateMember(ctx context.Context, tenantID, membershipID shared.ID) error
	// OffboardMember is SCIM delete: offboard when the member owns nothing
	// that needs a new owner, otherwise disable and ask an administrator to
	// finish the offboarding (SCIM cannot pick the new owners).
	OffboardMember(ctx context.Context, tenantID, membershipID shared.ID) error
}

// DomainVerifier reports whether an organization has DNS-proven an email domain
// (the domainverify service satisfies it).
type DomainVerifier interface {
	IsVerifiedDomain(ctx context.Context, tenantID, emailDomain string) (bool, error)
}

// ErrExistingAccountNeedsInvite is returned when SCIM asks to provision an email
// that already has an account outside this organization and the organization
// has not DNS-verified its domain. Attaching an existing account needs the
// account owner's consent (an invitation), the same rule as administrator-
// created accounts; otherwise any organization could enroll any person by email.
var ErrExistingAccountNeedsInvite = fmt.Errorf("%w: an account with this email already exists; invite them instead", shared.ErrConflict)

// ScimUser is the renderer-agnostic projection the HTTP layer wraps into SCIM
// JSON. Active reflects the tenant membership (suspended → active:false).
type ScimUser struct {
	ID          string
	UserName    string
	DisplayName string
	Email       string
	Active      bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// ProvisionInput is a normalised SCIM create/replace request.
type ProvisionInput struct {
	UserName    string
	DisplayName string
	Email       string
	Active      bool
}

// ErrUserNotInTenant is returned (wrapping ErrNotFound → SCIM 404) when a SCIM
// id is not a member of the requesting tenant.
var ErrUserNotInTenant = fmt.Errorf("%w: user is not provisioned in this tenant", shared.ErrNotFound)

// ProvisioningService maps SCIM User operations onto OpenCTEM users + tenant
// memberships.
type ProvisioningService struct {
	users       UserStore
	members     MembershipReader
	manager     MembershipManager
	defaultRole string
	domains     DomainVerifier
	logger      *logger.Logger
}

// SetDomainVerifier wires the verified-domain check. Without it an existing
// account is never attached by SCIM (fail-closed); new accounts are unaffected.
func (s *ProvisioningService) SetDomainVerifier(v DomainVerifier) {
	s.domains = v
}

// NewProvisioningService wires the service.
func NewProvisioningService(users UserStore, members MembershipReader, manager MembershipManager, log *logger.Logger) *ProvisioningService {
	return &ProvisioningService{
		users:       users,
		members:     members,
		manager:     manager,
		defaultRole: string(tenantdom.RoleMember),
		logger:      log.With("service", "scim-provisioning"),
	}
}

func normalizeEmail(in ProvisionInput) string {
	e := strings.TrimSpace(in.Email)
	if e == "" {
		e = strings.TrimSpace(in.UserName)
	}
	return strings.ToLower(e)
}

// CreateOrActivate provisions a user into the tenant (idempotent). Returns the
// resource and whether a NEW membership was created (caller maps to 201 vs 200).
func (s *ProvisioningService) CreateOrActivate(ctx context.Context, tenantID shared.ID, in ProvisionInput) (ScimUser, bool, error) {
	email := normalizeEmail(in)
	if email == "" {
		return ScimUser{}, false, fmt.Errorf("%w: userName/email required", shared.ErrValidation)
	}
	name := strings.TrimSpace(in.DisplayName)
	if name == "" {
		name = email
	}

	u, existed, err := s.findOrCreateUser(ctx, email, name)
	if err != nil {
		return ScimUser{}, false, err
	}

	created := false
	m, merr := s.members.GetMembership(ctx, u.ID(), tenantID)
	// An offboarded tombstone is not a membership: provisioning re-adds the
	// person from zero, under the same rules as a newcomer.
	if merr == nil && m != nil && m.IsOffboarded() {
		merr = shared.ErrNotFound
	}
	switch {
	case merr == nil && m != nil:
		if err := s.reconcileExisting(ctx, tenantID, m, in.Active); err != nil {
			return ScimUser{}, false, err
		}
	case errors.Is(merr, shared.ErrNotFound):
		if existed && !s.domainVerified(ctx, tenantID, email) {
			s.logger.Warn("scim provision refused: existing account outside a verified domain",
				"tenant_id", tenantID.String(), "user_id", u.ID().String())
			return ScimUser{}, false, ErrExistingAccountNeedsInvite
		}
		if aerr := s.manager.AddMember(ctx, tenantID, u.ID(), s.defaultRole); aerr != nil {
			return ScimUser{}, false, fmt.Errorf("add member: %w", aerr)
		}
		created = true
		if !in.Active {
			if nm, gerr := s.members.GetMembership(ctx, u.ID(), tenantID); gerr == nil && nm != nil {
				if serr := s.manager.SuspendMember(ctx, tenantID, nm.ID()); serr != nil {
					s.logger.Warn("scim provision-inactive suspend failed", "error", serr)
				}
			}
		}
	default:
		return ScimUser{}, false, fmt.Errorf("lookup membership: %w", merr)
	}

	res, err := s.buildResource(ctx, u.ID(), tenantID)
	if err != nil {
		return ScimUser{}, false, err
	}
	return res, created, nil
}

// reconcileExisting aligns an existing membership's active state with the request.
func (s *ProvisioningService) reconcileExisting(ctx context.Context, tenantID shared.ID, m *tenantdom.Membership, wantActive bool) error {
	switch {
	case wantActive && m.IsSuspended():
		if err := s.manager.ReactivateMember(ctx, tenantID, m.ID()); err != nil {
			return fmt.Errorf("reactivate member: %w", err)
		}
	case !wantActive && !m.IsSuspended():
		if err := s.manager.SuspendMember(ctx, tenantID, m.ID()); err != nil {
			return fmt.Errorf("suspend member: %w", err)
		}
	}
	return nil
}

// domainVerified reports whether tenantID has DNS-proven the domain of email.
// Fail-closed on a missing verifier, a lookup error or an unparseable email.
func (s *ProvisioningService) domainVerified(ctx context.Context, tenantID shared.ID, email string) bool {
	at := strings.LastIndex(email, "@")
	if s.domains == nil || at < 0 || at == len(email)-1 {
		return false
	}
	ok, err := s.domains.IsVerifiedDomain(ctx, tenantID.String(), email[at+1:])
	if err != nil {
		s.logger.Warn("scim verified-domain check failed (fail-closed)", "tenant_id", tenantID.String(), "error", err)
		return false
	}
	return ok
}

// findOrCreateUser returns the account for email, creating a passwordless one
// when none exists. existed reports whether the account was already there.
func (s *ProvisioningService) findOrCreateUser(ctx context.Context, email, name string) (u *userdom.User, existed bool, err error) {
	if u, err := s.users.GetByEmail(ctx, email); err == nil && u != nil {
		return u, true, nil
	}
	// Create as a local user with no password — the same "invited, not yet
	// logged in" state the invitation flow uses, so the user can later be
	// claimed by SSO/SAML/OIDC login (findOrCreateUser upgrades a
	// passwordless local user).
	newU, cerr := userdom.New(email, name)
	if cerr != nil {
		return nil, false, fmt.Errorf("%w: %v", shared.ErrValidation, cerr)
	}
	if cerr := s.users.Create(ctx, newU); cerr != nil {
		// Race: a concurrent request may have created it between lookup and
		// create. Treat it as existing: we cannot tell it was ours.
		if retry, rerr := s.users.GetByEmail(ctx, email); rerr == nil && retry != nil {
			return retry, true, nil
		}
		return nil, false, fmt.Errorf("create user: %w", cerr)
	}
	return newU, false, nil
}

// Get returns a provisioned user scoped to the tenant.
func (s *ProvisioningService) Get(ctx context.Context, tenantID, userID shared.ID) (ScimUser, error) {
	return s.buildResource(ctx, userID, tenantID)
}

// SetActive activates/deactivates a user's tenant membership (deprovision when
// active=false — suspends the membership, which revokes sessions immediately).
func (s *ProvisioningService) SetActive(ctx context.Context, tenantID, userID shared.ID, active bool) (ScimUser, error) {
	m, err := s.members.GetMembership(ctx, userID, tenantID)
	if err != nil || m == nil || m.IsOffboarded() {
		return ScimUser{}, ErrUserNotInTenant
	}
	if err := s.reconcileExisting(ctx, tenantID, m, active); err != nil {
		return ScimUser{}, err
	}
	return s.buildResource(ctx, userID, tenantID)
}

// Deprovision is SCIM DELETE: the member is offboarded (or, when they own
// work that needs a new owner, disabled pending an administrator's
// offboarding). Access is cut either way.
func (s *ProvisioningService) Deprovision(ctx context.Context, tenantID, userID shared.ID) error {
	m, err := s.members.GetMembership(ctx, userID, tenantID)
	if err != nil || m == nil || m.IsOffboarded() {
		return ErrUserNotInTenant
	}
	if err := s.manager.OffboardMember(ctx, tenantID, m.ID()); err != nil {
		return fmt.Errorf("offboard member: %w", err)
	}
	return nil
}

// List returns provisioned users. A non-empty filterEmail returns the matching
// member (or empty); otherwise tenant members are listed with SCIM 1-based
// pagination. Returns (page, totalResults, error).
func (s *ProvisioningService) List(ctx context.Context, tenantID shared.ID, filterEmail string, startIndex, count int) ([]ScimUser, int, error) {
	if filterEmail != "" {
		u, err := s.users.GetByEmail(ctx, strings.ToLower(strings.TrimSpace(filterEmail)))
		if err != nil || u == nil {
			// No such user → empty result, not an error (SCIM filter semantics).
			return []ScimUser{}, 0, nil //nolint:nilerr // lookup miss is an empty page
		}
		res, berr := s.buildResource(ctx, u.ID(), tenantID)
		if berr != nil {
			// User exists globally but is not a member of this tenant → empty.
			return []ScimUser{}, 0, nil //nolint:nilerr // non-member is an empty page
		}
		return []ScimUser{res}, 1, nil
	}

	members, err := s.members.ListMembersByTenant(ctx, tenantID)
	if err != nil {
		return nil, 0, fmt.Errorf("list members: %w", err)
	}
	total := len(members)

	if startIndex < 1 {
		startIndex = 1
	}
	lo := startIndex - 1
	if lo > total {
		lo = total
	}
	// SCIM (RFC-7644 §3.4.2.4): count == 0 means "return no resources" (the
	// client just wants totalResults). count < 0 is treated as "no limit".
	hi := total
	if count >= 0 {
		hi = lo + count
		if hi > total {
			hi = total
		}
	}

	out := make([]ScimUser, 0, hi-lo)
	for _, m := range members[lo:hi] {
		u, uerr := s.users.GetByID(ctx, m.UserID())
		if uerr != nil || u == nil {
			continue
		}
		out = append(out, resourceFrom(u, m))
	}
	return out, total, nil
}

func (s *ProvisioningService) buildResource(ctx context.Context, userID, tenantID shared.ID) (ScimUser, error) {
	m, err := s.members.GetMembership(ctx, userID, tenantID)
	if err != nil || m == nil || m.IsOffboarded() {
		return ScimUser{}, ErrUserNotInTenant
	}
	u, uerr := s.users.GetByID(ctx, userID)
	if uerr != nil || u == nil {
		return ScimUser{}, ErrUserNotInTenant
	}
	return resourceFrom(u, m), nil
}

func resourceFrom(u *userdom.User, m *tenantdom.Membership) ScimUser {
	return ScimUser{
		ID:          u.ID().String(),
		UserName:    u.Email(),
		DisplayName: u.Name(),
		Email:       u.Email(),
		Active:      m.IsActive(),
		CreatedAt:   u.CreatedAt(),
		UpdatedAt:   u.UpdatedAt(),
	}
}
