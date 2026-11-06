package auth

// Two-factor reset by the platform console (Console > Users). A person who
// lost their device and recovery codes, and who has no organization
// administrator above them (a sole owner, or an account in no organization),
// cannot be reset from an organization. The console route that calls this
// takes a super admin, a fresh step-up, a reason and the approval of a second
// super admin; this method does the account work.

import (
	"context"
	"errors"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/mfa"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ResetUserMFAByConsole turns off the second factor of the local account id
// and signs it out everywhere. The next sign-in is a password sign-in, and
// enrolls again where an organization requires it. ErrMFANotEnabled when the
// account has no active factor.
func (s *AuthService) ResetUserMFAByConsole(ctx context.Context, id shared.ID, ip string) error {
	if !s.mfaEnabled() {
		return ErrMFAUnavailable
	}
	u, err := s.userRepo.GetByID(ctx, id)
	if err != nil {
		return err
	}
	if !isPasswordAccount(u) {
		return ErrMFANotSupported
	}
	f, err := s.mfaRepo.GetFactor(ctx, u.ID())
	if errors.Is(err, mfa.ErrFactorNotFound) || (err == nil && !f.Enabled) {
		return ErrMFANotEnabled
	}
	if err != nil {
		return err
	}
	if err := s.mfaRepo.Disable(ctx, u.ID()); err != nil {
		return fmt.Errorf("disable two-factor: %w", err)
	}
	s.revokeUserSessions(ctx, u.ID(), shared.ID{})
	if s.securityNotifier != nil {
		s.securityNotifier.NotifyMFADisabled(ctx, u.Email(), u.Name(), ip)
	}
	return nil
}
