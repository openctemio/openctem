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
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/mfa"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
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
	// ErrStepUpCodeReused is an authenticator code from a time step that was
	// already used (it signed the person in, or confirmed an earlier action).
	// It is an ErrStepUpFailed, so every caller that refuses a wrong code
	// refuses it the same way; the step-up endpoint tells the person to wait
	// for the next code instead of calling it wrong.
	ErrStepUpCodeReused = fmt.Errorf("%w: code already used", ErrStepUpFailed)
	// ErrStepUpNoFactor: the account was asked for a code but its
	// authenticator was removed meanwhile. Ask again (ErrStepUpRequired).
	ErrStepUpNoFactor = fmt.Errorf("%w: no authenticator", ErrStepUpRequired)
	// ErrStepUpSecretUnreadable: the stored authenticator secret could not be
	// decrypted. A server fault, never reported as a wrong code and not
	// counted towards the lockout.
	ErrStepUpSecretUnreadable = errors.New("step-up re-authentication unavailable: authenticator secret unreadable")
)

// Reasons recorded in the metadata of a failed step-up audit event
// (auth.step_up_failed, key "reason"). The code itself is never recorded.
const (
	StepUpReasonInvalidCode     = "invalid_code"
	StepUpReasonReplayedCode    = "replayed_code"
	StepUpReasonInvalidPassword = "invalid_password"
	StepUpReasonAccountLocked   = "account_locked"
	StepUpReasonNoTOTPFactor    = "no_totp_factor"
	StepUpReasonDecryptError    = "decrypt_error"
	StepUpReasonRateLimited     = "rate_limited"
)

// StepUpFailureReason names a VerifyStepUp error for the audit trail, or ""
// for an error that is not a refused proof (nothing given, an SSO session,
// an infrastructure error).
func StepUpFailureReason(err error, method StepUpMethod) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrStepUpCodeReused):
		return StepUpReasonReplayedCode
	case errors.Is(err, ErrStepUpFailed):
		if method == StepUpPassword {
			return StepUpReasonInvalidPassword
		}
		return StepUpReasonInvalidCode
	case errors.Is(err, ErrAccountLocked):
		return StepUpReasonAccountLocked
	case errors.Is(err, ErrStepUpNoFactor):
		return StepUpReasonNoTOTPFactor
	case errors.Is(err, ErrStepUpSecretUnreadable):
		return StepUpReasonDecryptError
	}
	return ""
}

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
// which also counts towards the lockout (ErrStepUpCodeReused, an
// ErrStepUpFailed, for a code from a step already used).
// ErrStepUpSecretUnreadable is a server fault and counts for nothing.
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
			if errors.Is(err, mfa.ErrFactorNotFound) {
				return ErrStepUpNoFactor
			}
			return err
		}
		if !f.Enabled || f.SecretEncrypted == "" {
			return ErrStepUpNoFactor
		}
		out, err := s.verifyTOTP(ctx, f, proof.TOTP)
		switch {
		case errors.Is(err, errTOTPDecrypt):
			s.logger.Error("step-up: authenticator secret could not be decrypted", "error", logger.SanitizeError(err))
			return ErrStepUpSecretUnreadable
		case err != nil:
			return err
		case out == totpReplayed:
			s.recordPasswordFailure(ctx, u)
			return ErrStepUpCodeReused
		case out != totpAccepted:
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
