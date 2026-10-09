package auth

import (
	"context"
	"errors"

	"github.com/openctemio/openctem/api/pkg/domain/mfa"
)

// Fresh authenticator code errors.
var (
	// ErrTOTPNotEnrolled: the account has no authenticator app (or the
	// platform has two-factor authentication turned off).
	ErrTOTPNotEnrolled = errors.New("no authenticator app is enrolled for this account")
)

// VerifyFreshTOTP checks a code from userID's authenticator app for an
// action that needs proof of presence with the second factor itself, not
// only a recent sign-in (an owner approving their own scope entry). A
// password does not do; a code is accepted once (the factor's step
// advances), and a wrong code counts towards the account lockout. It answers
// ErrTOTPNotEnrolled, ErrAccountLocked or ErrStepUpFailed.
func (s *AuthService) VerifyFreshTOTP(ctx context.Context, userID, code string) error {
	if !s.mfaEnabled() {
		return ErrTOTPNotEnrolled
	}
	u, err := s.mfaUser(ctx, userID)
	if err != nil {
		return ErrStepUpFailed
	}
	if u.IsLocked() {
		return ErrAccountLocked
	}
	f, err := s.mfaRepo.GetFactor(ctx, u.ID())
	if errors.Is(err, mfa.ErrFactorNotFound) || (err == nil && !f.Enabled) {
		return ErrTOTPNotEnrolled
	}
	if err != nil {
		return err
	}
	ok, err := s.checkTOTP(ctx, f, code)
	if err != nil {
		return err
	}
	if !ok {
		s.recordPasswordFailure(ctx, u)
		return ErrStepUpFailed
	}
	return nil
}
