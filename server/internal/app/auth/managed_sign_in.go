package auth

// An account whose sign-in an organization's single sign-on manages gets no
// password from a self-service path (research/539 PR 0, RFC-123 D11).
//
// Such an account was claimed or created by the organization's identity
// provider and has no password of its own. A password set through
// forgot-password, or through a set-password link still outstanding from
// before the first SSO sign-in, would be a way in that the identity provider
// does not control: disabling the person at the IdP would not cut it, and the
// account's own sign-in would open other organizations too (idp_binding.go).
//
// Every organization sign-on (OIDC and SAML, with or without a stable
// identifier from the IdP) records itself on the account: the first time and
// the organization (users.sso_signed_in_at, users.sso_tenant_id), and in the
// same statement voids an outstanding set-password or reset link of an
// account without a password. The rule below reads only that record.
//
// Break-glass is kept, narrowly. An active owner of the organization whose
// SSO manages the account keeps forgot-password: that organization's owners
// are its way in when its IdP fails (Require SSO admits an owner with
// password plus second factor), and who owns it is that organization's own
// decision. Owning any other organization does not count: an account could
// create one itself. A suspended organization, or one scheduled for
// deletion, does not count either. An active platform administrator keeps
// forgot-password too (the admin console needs a password of its own).
// Break-glass console accounts never sign in through an organization's SSO
// (refuseBreakGlass), so they never become SSO-managed.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/server/pkg/domain/tenant"
	userdom "github.com/openctemio/openctem/server/pkg/domain/user"
)

// OrganizationSignInStore records and reads which organization's single
// sign-on signed an account in (implemented by the postgres user repository).
type OrganizationSignInStore interface {
	// RecordOrganizationSignIn keeps the first time and organization and
	// voids an outstanding password link of an account without a password,
	// in one statement.
	RecordOrganizationSignIn(ctx context.Context, userID, tenantID shared.ID) error
	// OrganizationSignIn returns the first organization sign-on time (nil:
	// never) and the organization (nil: unknown).
	OrganizationSignIn(ctx context.Context, userID shared.ID) (*time.Time, *shared.ID, error)
}

// PlatformAdminLookup reports whether an account is linked to an active
// platform administrator (admin console).
type PlatformAdminLookup interface {
	IsPlatformAdmin(ctx context.Context, userID shared.ID) (bool, error)
}

// SetManagedSignIn wires the rule that an SSO-managed account gets no
// password through a self-service path. Without store, a password-less
// account that has signed in is refused a password by email (fail closed);
// admins exempts
// active platform administrators (nil: none exempt).
func (s *AuthService) SetManagedSignIn(store OrganizationSignInStore, admins PlatformAdminLookup) {
	s.orgSignIns = store
	s.platformAdmins = admins
}

// errManagedLookup wraps a failed or impossible lookup of the managed rule.
var errManagedLookup = errors.New("managed sign-in lookup failed")

// passwordManagedBySSO reports whether u is a password-less account an
// organization's single sign-on signed in, and so must not get a password
// through forgot-password or a set-password link. An error means the answer
// is unknown; callers refuse (fail closed).
func (s *AuthService) passwordManagedBySSO(ctx context.Context, u *userdom.User) (bool, error) {
	if u == nil || u.AuthProvider() != userdom.AuthProviderLocal || u.PasswordHash() != nil {
		return false, nil
	}
	if s.orgSignIns == nil {
		// Unknown without the record. An account that never signed in at
		// all (awaiting its setup link) cannot have been signed in by an
		// organization's SSO; any other answer refuses (fail closed).
		if u.LastLoginAt() == nil {
			return false, nil
		}
		return false, fmt.Errorf("%w: organization sign-in store not configured", errManagedLookup)
	}
	at, tenantID, err := s.orgSignIns.OrganizationSignIn(ctx, u.ID())
	if err != nil {
		return false, fmt.Errorf("%w: %w", errManagedLookup, err)
	}
	if at == nil {
		return false, nil
	}
	exempt, err := s.breakGlassHolder(ctx, u.ID(), tenantID)
	if err != nil {
		return false, err
	}
	return !exempt, nil
}

// breakGlassHolder reports whether the account is an active platform
// administrator, or an active owner of managedBy (the organization whose
// SSO manages it) while that organization is active and not scheduled for
// deletion. Unknown managedBy, or no tenant store: not exempt.
func (s *AuthService) breakGlassHolder(ctx context.Context, userID shared.ID, managedBy *shared.ID) (bool, error) {
	if s.platformAdmins != nil {
		admin, err := s.platformAdmins.IsPlatformAdmin(ctx, userID)
		if err != nil {
			return false, fmt.Errorf("%w: platform administrator: %w", errManagedLookup, err)
		}
		if admin {
			return true, nil
		}
	}
	if managedBy == nil || s.tenantRepo == nil {
		return false, nil
	}
	memberships, err := s.tenantRepo.GetUserMembershipsWithStatus(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("%w: memberships: %w", errManagedLookup, err)
	}
	if memberships == nil {
		return false, nil
	}
	// Active lists only active memberships of active organizations.
	for _, m := range memberships.Active {
		if m.TenantID == managedBy.String() && m.Role == tenantdom.RoleOwner.String() &&
			!m.OrganizationSuspended && m.DeletionDueAt == nil {
			return true, nil
		}
	}
	return false, nil
}

// SetOrganizationSignInStore wires the record every organization sign-on
// leaves on the account (managed_sign_in.go).
func (s *SSOService) SetOrganizationSignInStore(store OrganizationSignInStore) { s.orgSignIns = store }

// recordOrganizationSignIn records that t's SSO signed u in, before a session
// is issued. A failure refuses the sign-in: an unrecorded account could still
// get a password by email. It also voids an outstanding password link of a
// password-less account, in the same statement.
func (s *SSOService) recordOrganizationSignIn(ctx context.Context, u *userdom.User, t *tenantdom.Tenant) error {
	if s.orgSignIns == nil || u == nil || t == nil {
		return nil
	}
	if err := s.orgSignIns.RecordOrganizationSignIn(ctx, u.ID(), t.ID()); err != nil {
		return fmt.Errorf("record organization sign-in: %w", err)
	}
	if u.PasswordHash() == nil {
		u.ClearPasswordResetToken()
	}
	return nil
}

// voidPasswordLinkOnSSO clears an outstanding set-password or reset link of
// an account without a password on the entity an SSO sign-in is about to
// save, so the save does not write it back. The database clears it too
// (RecordOrganizationSignIn). A password account keeps its link: it linked
// SSO itself and its password stays its own.
func voidPasswordLinkOnSSO(u *userdom.User) bool {
	if u == nil || u.PasswordHash() != nil || u.PasswordResetToken() == nil {
		return false
	}
	u.ClearPasswordResetToken()
	return true
}
