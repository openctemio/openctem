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
// Break-glass is kept. An active organization owner and a platform
// administrator keep forgot-password even when their account is SSO-managed:
// owners are the organization's way in when its IdP fails (Require SSO admits
// an owner with password plus second factor), and a platform administrator
// needs a password of its own for the admin console. Break-glass console
// accounts never sign in through an organization's SSO (refuseBreakGlass), so
// they never become SSO-managed.

import (
	"context"
	"errors"
	"fmt"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/server/pkg/domain/tenant"
	userdom "github.com/openctemio/openctem/server/pkg/domain/user"
	"github.com/openctemio/openctem/server/pkg/domain/useridentity"
)

// PlatformAdminLookup reports whether an account is linked to a platform
// administrator (admin console).
type PlatformAdminLookup interface {
	IsPlatformAdmin(ctx context.Context, userID shared.ID) (bool, error)
}

// SetManagedSignIn wires the rule that an SSO-managed account gets no
// password through a self-service path. identities finds the account's SSO
// identities; admins exempts platform administrators (nil: none exempt).
func (s *AuthService) SetManagedSignIn(identities useridentity.Repository, admins PlatformAdminLookup) {
	s.identities = identities
	s.platformAdmins = admins
}

// errManagedLookup wraps a failed lookup of the managed-account rule.
var errManagedLookup = errors.New("managed sign-in lookup failed")

// passwordManagedBySSO reports whether u is an account whose sign-in an
// organization's single sign-on manages, so that it must not get a password
// through forgot-password or a set-password link. An error means the answer
// is unknown; callers refuse (fail closed).
//
// Managed: a local account with no password that either holds an identity
// an organization's SSO asserted (useridentity.SourceSSO), or has signed in
// although it has no password and no bound identity at all (an SSO sign-in
// whose IdP sends no stable identifier, such as a SAML assertion with an
// email NameID, binds nothing). Exempt: an active owner of an organization
// and a platform administrator (break-glass).
func (s *AuthService) passwordManagedBySSO(ctx context.Context, u *userdom.User) (bool, error) {
	if u == nil || u.AuthProvider() != userdom.AuthProviderLocal || u.PasswordHash() != nil {
		return false, nil
	}
	if s.identities == nil {
		return false, nil
	}
	idents, err := s.identities.ListByUser(ctx, u.ID())
	if err != nil {
		return false, fmt.Errorf("%w: identities: %w", errManagedLookup, err)
	}
	managed := false
	for _, ident := range idents {
		if ident.ManagedBySSO() {
			managed = true
			break
		}
	}
	if !managed && len(idents) == 0 && u.LastLoginAt() != nil {
		managed = true
	}
	if !managed {
		return false, nil
	}
	exempt, err := s.breakGlassHolder(ctx, u.ID())
	if err != nil {
		return false, err
	}
	return !exempt, nil
}

// breakGlassHolder reports whether the account is an active owner of an
// organization or a platform administrator.
func (s *AuthService) breakGlassHolder(ctx context.Context, userID shared.ID) (bool, error) {
	if s.platformAdmins != nil {
		admin, err := s.platformAdmins.IsPlatformAdmin(ctx, userID)
		if err != nil {
			return false, fmt.Errorf("%w: platform administrator: %w", errManagedLookup, err)
		}
		if admin {
			return true, nil
		}
	}
	if s.tenantRepo == nil {
		return false, nil
	}
	memberships, err := s.tenantRepo.GetUserMemberships(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("%w: memberships: %w", errManagedLookup, err)
	}
	for _, m := range memberships {
		if m.Role == tenantdom.RoleOwner.String() {
			return true, nil
		}
	}
	return false, nil
}

// voidPasswordLinkOnSSO clears an outstanding set-password or reset link of
// an account without a password when an organization's SSO signs it in: from
// then on the IdP is its way in, and a link issued before (an administrator's
// 24-hour setup link, a reset requested earlier) would be a second one. The
// caller saves u. A password account keeps its link: it linked SSO itself
// and its password stays its own.
func voidPasswordLinkOnSSO(u *userdom.User) bool {
	if u == nil || u.PasswordHash() != nil || u.PasswordResetToken() == nil {
		return false
	}
	u.ClearPasswordResetToken()
	return true
}
