package auth

// Proof for changing an account's sign-in methods
// (docs/architecture/social-login-linking.md, "Proof at the moment of the
// change").
//
// Linking a social provider (the start of an explicit link, or confirming a
// pending link) and unlinking one each need a proof typed into the confirm
// dialog for that one request:
//
//   - the account has TOTP: a current authenticator code. Never a recovery
//     code, and a code from an already used time step is refused, so a code
//     that just signed the person in cannot be replayed here;
//   - otherwise a password account: its password.
//
// A recent sign-in or an open step-up window does not count, and an account
// with neither TOTP nor a password (signs in only through a provider) cannot
// change its sign-in methods until it turns on two-factor authentication.
// Passkeys are only for platform administrators (the admin console), so a
// tenant account never presents one here.
//
// A wrong code or password counts towards the account lockout exactly like a
// failed sign-in (VerifyStepUp). The proof authorizes only the request that
// carries it: unlike POST /auth/step-up it does not open a window on the
// session. Each attempt is audited (auth.step_up / auth.step_up_failed) with
// the factor and what it was for.

import (
	"context"
	"errors"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	sessiondom "github.com/openctemio/openctem/api/pkg/domain/session"
)

// Purposes of a sign-in method change, recorded in the audit event.
const (
	LinkProofLinkStart   = "link_start"
	LinkProofPendingLink = "pending_link"
	LinkProofUnlink      = "unlink"
)

// Proof errors.
var (
	// ErrLinkProofRequired: the request carried no proof of the kind the
	// account needs (a password for an account with TOTP is not one).
	ErrLinkProofRequired = errors.New("confirm with your authenticator code or password to change sign-in methods")
	// ErrLinkProofFailed: the code or password was wrong, reused, or a
	// recovery code. Counts towards the lockout.
	ErrLinkProofFailed = errors.New("the code or password is not correct")
	// ErrLinkProofUnavailable: the account has neither TOTP nor a password
	// (or the session is not usable), so nothing can prove it here.
	ErrLinkProofUnavailable = errors.New("turn on two-factor authentication to change sign-in methods")
)

// LinkProofVerifier checks the proof for a sign-in method change
// (implemented by AuthService).
type LinkProofVerifier interface {
	// LinkProofMethod is what the account must present: StepUpTOTP,
	// StepUpPassword, or "" when it has neither.
	LinkProofMethod(ctx context.Context, userID string) (StepUpMethod, error)
	// VerifyLinkProof checks proof for userID in sessionID and returns the
	// factor that was verified.
	VerifyLinkProof(ctx context.Context, actx auditapp.AuditContext, userID, sessionID string, proof StepUpProof, purpose string) (StepUpMethod, error)
}

var _ LinkProofVerifier = (*AuthService)(nil)

// LinkProofMethod returns StepUpTOTP or StepUpPassword, or "" for an account
// that has neither.
func (s *AuthService) LinkProofMethod(ctx context.Context, userID string) (StepUpMethod, error) {
	m, err := s.StepUpMethodFor(ctx, userID)
	if err != nil {
		return stepUpNothingNeeded, err
	}
	if m != StepUpTOTP && m != StepUpPassword {
		return stepUpNothingNeeded, nil
	}
	return m, nil
}

// VerifyLinkProof checks the proof typed for one sign-in method change. It
// never stamps the session: the next change needs a new proof.
func (s *AuthService) VerifyLinkProof(ctx context.Context, actx auditapp.AuditContext, userID, sessionID string, proof StepUpProof, purpose string) (StepUpMethod, error) {
	st := s.stepUpStore()
	uid, sid, ok := parseStepUpIDs(userID, sessionID)
	if st == nil || !ok {
		return stepUpNothingNeeded, ErrLinkProofUnavailable
	}
	// Only a live session of this user may spend a code or a password.
	if _, err := st.RecentAuthAt(ctx, sid, uid); err != nil {
		if errors.Is(err, sessiondom.ErrSessionNotFound) {
			return stepUpNothingNeeded, ErrLinkProofUnavailable
		}
		return stepUpNothingNeeded, err
	}
	method, err := s.LinkProofMethod(ctx, userID)
	if err != nil {
		return stepUpNothingNeeded, err
	}
	if method == stepUpNothingNeeded {
		return stepUpNothingNeeded, ErrLinkProofUnavailable
	}
	if (method == StepUpTOTP && proof.TOTP == "") || (method == StepUpPassword && proof.Password == "") {
		return method, ErrLinkProofRequired
	}
	err = s.VerifyStepUp(ctx, userID, sessionID, proof)
	switch {
	case err == nil:
		s.audit(ctx, actx, auditapp.NewSuccessEvent(auditdom.ActionAuthStepUp, auditdom.ResourceTypeUser, userID).
			WithMessage("Identity confirmed to change sign-in methods").
			WithMetadata("method", string(method)).
			WithMetadata("purpose", purpose))
		return method, nil
	case errors.Is(err, ErrStepUpFailed), errors.Is(err, ErrAccountLocked):
		s.audit(ctx, actx, auditapp.NewFailureEvent(auditdom.ActionAuthStepUpFailed, auditdom.ResourceTypeUser, userID, err).
			WithMessage("Identity confirmation to change sign-in methods failed").
			WithMetadata("method", string(method)).
			WithMetadata("purpose", purpose))
		if errors.Is(err, ErrAccountLocked) {
			return method, ErrAccountLocked
		}
		return method, ErrLinkProofFailed
	case errors.Is(err, ErrStepUpRequired):
		return method, ErrLinkProofRequired
	default:
		return method, err
	}
}
