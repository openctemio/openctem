package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/mfa"
	sessiondom "github.com/openctemio/openctem/api/pkg/domain/session"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// Personal accounts and SSO exceptions at token mint (RFC-058).

// ErrPersonalAccountsBlocked refuses a token for a personal account in an
// organization that blocks personal accounts.
var ErrPersonalAccountsBlocked = errors.New("this organization does not accept personal email accounts")

// secondFactorProven reports whether the session went through a second factor
// that the organization tenantID accepts: a password session of a user with
// 2FA on (the login verified it), or a federated session whose provider proved
// one, when that provider is the organization's own or the trusted home
// organization of an external member. A second factor proven by another
// organization's provider counts for that organization only: its
// administrators could otherwise satisfy this organization's rule.
func (s *AuthService) secondFactorProven(ctx context.Context, sess *sessiondom.Session, userID shared.ID, tenantID string) (bool, error) {
	if sess.AuthMethod().IsFederated() {
		if sess.FederatedFor(tenantID) {
			return sess.MFAEvidence(), nil
		}
		fed, mfaOK := s.assuranceAt(ctx, sess, userID, tenantID)
		return fed && mfaOK, nil
	}
	return s.ownSecondFactorProven(ctx, sess, userID)
}

// ownSecondFactorProven reports whether a password session went through the
// account's own second factor. A federated session never did: no identity
// provider's word stands in for the account's own factor.
func (s *AuthService) ownSecondFactorProven(ctx context.Context, sess *sessiondom.Session, userID shared.ID) (bool, error) {
	if sess.AuthMethod().IsFederated() || s.mfaRepo == nil {
		return false, nil
	}
	f, err := s.mfaRepo.GetFactor(ctx, userID)
	if err != nil && !errors.Is(err, mfa.ErrFactorNotFound) {
		return false, fmt.Errorf("failed to load mfa factor: %w", err)
	}
	return f != nil && f.Enabled, nil
}

// enforcePersonalPolicy applies the organization's personal-account policy to
// a member with a personal address: blocked refuses the token;
// allowed_with_mfa requires a proven second factor.
func (s *AuthService) enforcePersonalPolicy(ctx context.Context, sess *sessiondom.Session, userID shared.ID, tenantID string) error {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	m, err := s.tenantRepo.GetMembership(ctx, userID, tid)
	if err != nil || !tenantdom.IsPersonalMember(m) {
		return nil //nolint:nilerr // no membership is refused elsewhere; not personal: nothing to apply
	}
	t, err := s.tenantRepo.GetByID(ctx, tid)
	if err != nil {
		return fmt.Errorf("failed to load tenant for the personal account policy: %w", err)
	}
	sec, err := t.SecuritySettingsStrict()
	if err != nil {
		return fmt.Errorf("failed to read the personal account policy: %w", err)
	}
	switch sec.PersonalAccounts.Effective() {
	case tenantdom.PersonalAccountsBlocked:
		return ErrPersonalAccountsBlocked
	case tenantdom.PersonalAccountsAllowedWithMFA:
		ok, err := s.secondFactorProven(ctx, sess, userID, tenantID)
		if err != nil {
			return err
		}
		if !ok {
			s.logger.Warn("blocked personal account without a second factor",
				"tenant_id", tid.String(), "user_id", userID.String())
			return ErrMFAEnrollmentRequired
		}
	}
	return nil
}

// ssoExceptionAllows reports whether an SSO-enforced organization lets this
// session in through a named exception: the member is on the list, the
// exception has not expired, and the session proved the account's own second
// factor (password and factor; another organization's provider does not count).
func (s *AuthService) ssoExceptionAllows(ctx context.Context, sess *sessiondom.Session, sec tenantdom.SecuritySettings) bool {
	if !sec.HasSSOException(sess.UserID().String(), time.Now().UTC()) {
		return false
	}
	ok, err := s.ownSecondFactorProven(ctx, sess, sess.UserID())
	return err == nil && ok
}
