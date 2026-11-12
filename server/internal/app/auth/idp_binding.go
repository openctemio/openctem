package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/mfa"
	sessiondom "github.com/openctemio/openctem/api/pkg/domain/session"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	userdom "github.com/openctemio/openctem/api/pkg/domain/user"
)

// An organization's identity provider vouches for a person in THAT
// organization only.
//
// An organization trusts its own IdP: a sign-in through it skips the
// account's own password and second factor there. The session is global,
// though, and the same person may belong to other organizations. Without this
// gate, the administrator of organization A's IdP could sign in as a shared
// member and open organization B, which never chose that IdP, with neither
// the account's password nor its second factor.
//
// So a session issued by organization A's IdP opens another organization B
// only when one of these holds:
//   - B trusts A as the member's home organization (RFC-058 home sign-in);
//   - the account has no sign-in of its own (no password, no second factor,
//     not a social account): the IdP is the only way this account has ever
//     signed in, and B admitted the account as such.
//
// Otherwise the person signs in with their own account (password, and the
// second factor when they have one) or through B's own IdP.

// ErrOwnSignInRequired refuses a token for an organization other than the one
// whose identity provider issued the session, when the account has its own
// sign-in that the provider skipped.
var ErrOwnSignInRequired = errors.New("this organization needs a sign-in with your own account")

// CodeOwnSignInRequired is the API error code of ErrOwnSignInRequired.
const CodeOwnSignInRequired apierror.Code = "OWN_SIGN_IN_REQUIRED"

// enforceIdPBindingPolicy is the gate described above. It runs at every token
// mint and per request (CheckEntry), next to the other entry requirements.
func (s *AuthService) enforceIdPBindingPolicy(ctx context.Context, sess *sessiondom.Session, userID shared.ID, tenantID string) error {
	if !sess.AuthMethod().IsFederated() || sess.IDPTenantID().IsZero() || sess.FederatedFor(tenantID) {
		// A password session, a social sign-in (the account's own linked
		// provider, behind its own second factor), or this organization's IdP.
		return nil
	}
	if fed, _ := s.assuranceAt(ctx, sess, userID, tenantID); fed {
		return nil // a trusted home organization's IdP, accepted by this organization
	}
	own, err := s.hasOwnSignIn(ctx, userID)
	if err != nil {
		// Fail closed: an unreadable account never opens another organization.
		return err
	}
	if !own {
		return nil
	}
	tid, _ := shared.IDFromString(tenantID)
	s.logger.Warn("blocked another organization's identity provider session from an organization that did not choose it",
		"tenant_id", tid.String(), "user_id", userID.String(), "idp_tenant_id", sess.IDPTenantID().String())
	return ErrOwnSignInRequired
}

// hasOwnSignIn reports whether the account can sign in by itself, without an
// organization's IdP: a password, an enabled second factor, or a social
// account (its own provider).
func (s *AuthService) hasOwnSignIn(ctx context.Context, userID shared.ID) (bool, error) {
	u, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("failed to load account for the identity provider binding: %w", err)
	}
	if u.PasswordHash() != nil {
		return true, nil
	}
	switch u.AuthProvider() {
	case userdom.AuthProviderGoogle, userdom.AuthProviderGitHub, userdom.AuthProviderMicrosoft:
		return true, nil
	}
	if s.mfaRepo == nil {
		return false, nil
	}
	f, err := s.mfaRepo.GetFactor(ctx, userID)
	if err != nil && !errors.Is(err, mfa.ErrFactorNotFound) {
		return false, fmt.Errorf("failed to load mfa factor: %w", err)
	}
	return f != nil && f.Enabled, nil
}

// OwnSignInRequired reports whether an action on the account itself (not on
// one organization) must be refused for this session: the session was issued
// by an organization's identity provider and the account has a sign-in of its
// own. Deleting the account or signing it out everywhere reaches every
// organization the person belongs to, so no single organization's IdP may do
// it in the account's name; the person signs in with their own account. An
// account the IdP created (no sign-in of its own) is not refused.
func (s *AuthService) OwnSignInRequired(ctx context.Context, userID, sessionID string) (bool, error) {
	uid, err := shared.IDFromString(userID)
	if err != nil {
		return false, fmt.Errorf("%w: invalid user id", shared.ErrValidation)
	}
	sid, err := shared.IDFromString(sessionID)
	if err != nil {
		return false, fmt.Errorf("%w: invalid session id", shared.ErrValidation)
	}
	sess, err := s.sessionRepo.GetByID(ctx, sid)
	if err != nil {
		return false, fmt.Errorf("failed to load session: %w", err)
	}
	if sess.UserID() != uid {
		return false, fmt.Errorf("%w: session of another user", shared.ErrValidation)
	}
	if !sess.AuthMethod().IsFederated() || sess.IDPTenantID().IsZero() {
		return false, nil
	}
	return s.hasOwnSignIn(ctx, uid)
}
