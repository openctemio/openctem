package auth

// Step-up re-authentication for tenant users (RFC-052 D-2): an action that
// binds a credential to the organization (approving a sensor pairing) asks
// the signed-in user to prove again that they are who the session says.
//
// What counts as proof, strongest first:
//  1. the user has TOTP enabled: a current code (never a recovery code, and a
//     code from an already used time step is refused);
//  2. a local account without TOTP: the password;
//  3. an SSO-only account without TOTP: a session younger than
//     StepUpFreshSession (sign in again to approve).
//
// Failures count towards the account lockout exactly like a failed sign-in,
// so step-up cannot be used to guess a password without the lockout.

import (
	"context"
	"errors"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/mfa"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// StepUpFreshSession is how recent a sign-in must be for an SSO-only account
// without TOTP to pass step-up.
const StepUpFreshSession = 10 * time.Minute

// StepUpProof is what the user typed.
type StepUpProof struct {
	TOTP     string `json:"totp,omitempty"`
	Password string `json:"password,omitempty"`
}

// StepUpMethod names what the account must present.
type StepUpMethod string

const (
	StepUpTOTP          StepUpMethod = "totp"
	StepUpPassword      StepUpMethod = "password"
	StepUpFreshSignIn   StepUpMethod = "fresh_sign_in"
	stepUpNothingNeeded StepUpMethod = ""
)

// Step-up errors. ErrStepUpRequired carries no detail on purpose: the caller
// answers with the method the account needs (StepUpMethodFor).
var (
	ErrStepUpRequired = errors.New("step-up re-authentication required")
	ErrStepUpFailed   = errors.New("step-up re-authentication failed")
)

// StepUpMethodFor returns what userID must present.
func (s *AuthService) StepUpMethodFor(ctx context.Context, userID string) (StepUpMethod, error) {
	u, err := s.mfaUser(ctx, userID)
	if err != nil {
		return stepUpNothingNeeded, err
	}
	if s.mfaEnabled() {
		if f, err := s.mfaRepo.GetFactor(ctx, u.ID()); err == nil && f.Enabled {
			return StepUpTOTP, nil
		} else if err != nil && !errors.Is(err, mfa.ErrFactorNotFound) {
			return stepUpNothingNeeded, err
		}
	}
	if isPasswordAccount(u) {
		return StepUpPassword, nil
	}
	return StepUpFreshSignIn, nil
}

// VerifyStepUp checks proof for userID signed in with sessionID. It returns
// nil on success, ErrStepUpRequired when nothing usable was given (or the
// SSO session is too old) and ErrStepUpFailed for a wrong code or password,
// which also counts towards the lockout.
func (s *AuthService) VerifyStepUp(ctx context.Context, userID, sessionID string, proof StepUpProof) error {
	method, err := s.StepUpMethodFor(ctx, userID)
	if err != nil {
		return ErrStepUpRequired
	}
	u, err := s.mfaUser(ctx, userID)
	if err != nil {
		return ErrStepUpRequired
	}
	if u.IsLocked() {
		return ErrAccountLocked
	}
	switch method {
	case StepUpTOTP:
		if proof.TOTP == "" {
			return ErrStepUpRequired
		}
		f, err := s.mfaRepo.GetFactor(ctx, u.ID())
		if err != nil {
			return ErrStepUpRequired
		}
		ok, err := s.checkTOTP(ctx, f, proof.TOTP)
		if err != nil || !ok {
			s.recordPasswordFailure(ctx, u)
			return ErrStepUpFailed
		}
		return nil
	case StepUpPassword:
		if proof.Password == "" {
			return ErrStepUpRequired
		}
		if err := s.passwordHasher.Verify(proof.Password, *u.PasswordHash()); err != nil {
			s.recordPasswordFailure(ctx, u)
			return ErrStepUpFailed
		}
		return nil
	default:
		sid, err := shared.IDFromString(sessionID)
		if err != nil || s.sessionRepo == nil {
			return ErrStepUpRequired
		}
		sess, err := s.sessionRepo.GetByID(ctx, sid)
		if err != nil || sess == nil || sess.UserID() != u.ID() || !sess.IsActive() {
			return ErrStepUpRequired
		}
		if time.Since(sess.CreatedAt()) > StepUpFreshSession {
			return ErrStepUpRequired
		}
		return nil
	}
}
