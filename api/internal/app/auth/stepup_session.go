package auth

// Session-bound step-up window (docs/architecture/step-up-reauth.md).
//
// POST /api/v1/auth/step-up verifies the user's proof (VerifyStepUp: TOTP when
// enrolled, else the password) and stamps sessions.step_up_at on the session
// that made the request. RequireRecentAuth then admits a sensitive request
// while the later of the session's sign-in and that stamp is younger than
// StepUpWindow. The stamp is server-side state of one session: it is not a
// client-held flag, cannot be replayed from another session, and is moved
// forward only by a new successful verification (reading it never extends it).

import (
	"context"
	"errors"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	sessiondom "github.com/openctemio/openctem/api/pkg/domain/session"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// StepUpWindow is how long a sign-in or a step-up unlocks sensitive actions
// in the same session (owner decision B7: 10 minutes, fixed, not sliding).
const StepUpWindow = 10 * time.Minute

// ErrStepUpUnavailable means this session cannot step up here: the account
// has neither TOTP nor a password (SSO-only: sign in again instead), or the
// session is not an active session of the user.
var ErrStepUpUnavailable = errors.New("step-up re-authentication unavailable for this session")

// StepUpSessionStore is the session state step-up needs. The PostgreSQL
// session repository implements it.
type StepUpSessionStore interface {
	MarkStepUp(ctx context.Context, sessionID, userID shared.ID, at time.Time) (bool, error)
	RecentAuthAt(ctx context.Context, sessionID, userID shared.ID) (time.Time, error)
}

// StepUpState tells the client what to ask for and whether the session is
// already inside the window.
type StepUpState struct {
	Method StepUpMethod `json:"method"`
	// ValidUntil is when the current window closes; nil when it is closed.
	ValidUntil *time.Time `json:"valid_until,omitempty"`
	// WindowSeconds is the length of a window opened by a step-up.
	WindowSeconds int `json:"window_seconds"`
}

func (s *AuthService) stepUpStore() StepUpSessionStore {
	st, _ := s.sessionRepo.(StepUpSessionStore)
	return st
}

func parseStepUpIDs(userID, sessionID string) (shared.ID, shared.ID, bool) {
	uid, err := shared.IDFromString(userID)
	if err != nil {
		return shared.ID{}, shared.ID{}, false
	}
	sid, err := shared.IDFromString(sessionID)
	if err != nil {
		return shared.ID{}, shared.ID{}, false
	}
	return uid, sid, true
}

// RecentAuthAt returns when userID last authenticated in sessionID (sign-in
// or step-up). ErrStepUpUnavailable when the session cannot be used.
func (s *AuthService) RecentAuthAt(ctx context.Context, userID, sessionID string) (time.Time, error) {
	st := s.stepUpStore()
	uid, sid, ok := parseStepUpIDs(userID, sessionID)
	if st == nil || !ok {
		return time.Time{}, ErrStepUpUnavailable
	}
	at, err := st.RecentAuthAt(ctx, sid, uid)
	if errors.Is(err, sessiondom.ErrSessionNotFound) {
		return time.Time{}, ErrStepUpUnavailable
	}
	return at, err
}

// GetStepUpState reports the method the account needs and the open window.
func (s *AuthService) GetStepUpState(ctx context.Context, userID, sessionID string) (*StepUpState, error) {
	method, err := s.StepUpMethodFor(ctx, userID)
	if err != nil {
		return nil, err
	}
	state := &StepUpState{Method: method, WindowSeconds: int(StepUpWindow.Seconds())}
	at, err := s.RecentAuthAt(ctx, userID, sessionID)
	if err != nil {
		if errors.Is(err, ErrStepUpUnavailable) {
			return state, nil
		}
		return nil, err
	}
	if until := at.Add(StepUpWindow); time.Now().Before(until) {
		state.ValidUntil = &until
	}
	return state, nil
}

// StepUp verifies proof for the signed-in user and opens a new window on the
// session that made the request. It returns when the window closes.
//
// An SSO-only account without TOTP has nothing to verify here: it gets
// ErrStepUpUnavailable and must sign in again (a fresh session is inside the
// window). That path never stamps the session, so a session cannot extend its
// own window without a new proof.
func (s *AuthService) StepUp(ctx context.Context, actx auditapp.AuditContext, userID, sessionID string, proof StepUpProof) (time.Time, error) {
	st := s.stepUpStore()
	uid, sid, ok := parseStepUpIDs(userID, sessionID)
	if st == nil || !ok {
		return time.Time{}, ErrStepUpUnavailable
	}
	// The session must be a live session of this user before a code or
	// password is spent on it.
	if _, err := st.RecentAuthAt(ctx, sid, uid); err != nil {
		if errors.Is(err, sessiondom.ErrSessionNotFound) {
			return time.Time{}, ErrStepUpUnavailable
		}
		return time.Time{}, err
	}
	method, err := s.StepUpMethodFor(ctx, userID)
	if err != nil {
		return time.Time{}, err
	}
	if method != StepUpTOTP && method != StepUpPassword {
		return time.Time{}, ErrStepUpUnavailable
	}

	if err := s.VerifyStepUp(ctx, userID, sessionID, proof); err != nil {
		if errors.Is(err, ErrStepUpFailed) || errors.Is(err, ErrAccountLocked) {
			s.audit(ctx, actx, auditapp.NewFailureEvent(auditdom.ActionAuthStepUpFailed, auditdom.ResourceTypeUser, userID, err).
				WithMessage("Step-up re-authentication failed").
				WithMetadata("method", string(method)))
		}
		return time.Time{}, err
	}

	now := time.Now()
	marked, err := st.MarkStepUp(ctx, sid, uid, now)
	if err != nil {
		return time.Time{}, err
	}
	if !marked {
		return time.Time{}, ErrStepUpUnavailable
	}
	until := now.Add(StepUpWindow)
	s.audit(ctx, actx, auditapp.NewSuccessEvent(auditdom.ActionAuthStepUp, auditdom.ResourceTypeUser, userID).
		WithMessage("Step-up re-authentication").
		WithMetadata("method", string(method)).
		WithMetadata("valid_until", until.UTC().Format(time.RFC3339)))
	return until, nil
}
