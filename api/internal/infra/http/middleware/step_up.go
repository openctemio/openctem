package middleware

// RequireRecentAuth: step-up re-authentication for sensitive routes
// (docs/architecture/step-up-reauth.md). RecentAuthGate: the same check for an
// action that needs it only in some cases, decided by a service.

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Step-up error codes. The web client answers STEP_UP_REQUIRED with its
// re-authentication dialog and retries the request once.
const (
	// CodeStepUpRequired: the session has not authenticated within the window.
	CodeStepUpRequired apierror.Code = "STEP_UP_REQUIRED"
	// CodeStepUpUnavailable: this credential cannot step up (no user session,
	// e.g. an API key, or step-up is not wired).
	CodeStepUpUnavailable apierror.Code = "STEP_UP_UNAVAILABLE"
)

// ErrNoRecentAuth is what a RecentAuthChecker returns when the session cannot
// be used for step-up (unknown, revoked, expired, or another user's).
var ErrNoRecentAuth = errors.New("no usable session for step-up")

// RecentAuthChecker returns when userID last authenticated (signed in or
// stepped up) in sessionID.
type RecentAuthChecker interface {
	RecentAuthAt(ctx context.Context, userID, sessionID string) (time.Time, error)
}

type stepUpVerdict int

const (
	stepUpOK stepUpVerdict = iota
	stepUpRequired
	stepUpUnavailable
	stepUpProviderUnavailable
)

// recentAuthVerdict decides whether the request's caller authenticated within
// window. A token from the external OIDC provider has no platform session:
// its recent authentication is the provider's own, the signature-verified
// auth_time claim, and the client steps up by signing in at the provider
// again (prompt=login, max_age=0) and sending the new token. Any other
// caller needs a user session (not an API key) whose sign-in or step-up is
// recent. A lookup error is returned and refuses the request.
func recentAuthVerdict(ctx context.Context, checker RecentAuthChecker, window time.Duration) (stepUpVerdict, error) {
	if GetAuthProvider(ctx) == AuthProviderOIDC {
		claims := GetClaims(ctx)
		if claims == nil || claims.AuthTime == nil {
			return stepUpProviderUnavailable, nil
		}
		if !recentEnough(claims.AuthTime.Time, window) {
			return stepUpRequired, nil
		}
		return stepUpOK, nil
	}
	userID, sessionID := GetUserID(ctx), GetSessionID(ctx)
	if checker == nil || IsAPIKeyAuthenticated(ctx) || userID == "" || sessionID == "" {
		return stepUpUnavailable, nil
	}
	at, err := checker.RecentAuthAt(ctx, userID, sessionID)
	switch {
	case errors.Is(err, ErrNoRecentAuth):
		return stepUpRequired, nil
	case err != nil:
		return stepUpUnavailable, err
	case !recentEnough(at, window):
		return stepUpRequired, nil
	}
	return stepUpOK, nil
}

// RequireRecentAuth admits a request only when the caller's session
// authenticated within window. Otherwise it answers 403 STEP_UP_REQUIRED;
// requests without a user session (API keys) and a nil checker answer 403
// STEP_UP_UNAVAILABLE. It fails closed: a lookup error refuses the request.
//
// Mount it after authentication and the route's permission check, so a caller
// without the permission is told so before being asked to re-authenticate.
func RequireRecentAuth(checker RecentAuthChecker, window time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			verdict, err := recentAuthVerdict(r.Context(), checker, window)
			if err != nil {
				if l := logger.FromContext(r.Context()); l != nil {
					l.Error("step-up check failed", "error", logger.SanitizeError(err))
				}
				apierror.InternalServerError("could not check re-authentication").WriteJSON(w)
				return
			}
			if verdict != stepUpOK {
				WriteStepUpError(w, stepUpErrorFor(verdict, window))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RecentAuthGate is RequireRecentAuth for an action that needs step-up only
// in some cases (granting an administrator role, renaming the organization):
// the service decides and calls RequireRecentAuth, and the handler writes the
// returned *shared.StepUpError with WriteStepUpError.
type RecentAuthGate struct {
	Checker RecentAuthChecker
	Window  time.Duration
}

var _ shared.RecentAuthGate = RecentAuthGate{}

// RequireRecentAuth returns nil when actorID is not the user making this
// request (a system path, or a grant authorized earlier, such as an
// invitation accepted by the invitee) or when that user authenticated within
// the window; otherwise a *shared.StepUpError, or the lookup error.
func (g RecentAuthGate) RequireRecentAuth(ctx context.Context, actorID string) error {
	if actorID == "" || GetUserID(ctx) != actorID {
		return nil
	}
	verdict, err := recentAuthVerdict(ctx, g.Checker, g.Window)
	if err != nil {
		return err
	}
	if verdict == stepUpOK {
		return nil
	}
	return stepUpErrorFor(verdict, g.Window)
}

func stepUpErrorFor(v stepUpVerdict, window time.Duration) *shared.StepUpError {
	switch v {
	case stepUpUnavailable:
		return &shared.StepUpError{Unavailable: true, Window: window,
			Message: "This action needs a signed-in user session that can re-authenticate"}
	case stepUpProviderUnavailable:
		return &shared.StepUpError{Unavailable: true, Window: window,
			Message: "This token does not say when you signed in; sign in again at your identity provider"}
	default:
		return &shared.StepUpError{Window: window, Message: "Confirm your identity to continue"}
	}
}

// WriteStepUpError writes a step-up refusal: 403 STEP_UP_REQUIRED with
// details.window_seconds, or 403 STEP_UP_UNAVAILABLE.
func WriteStepUpError(w http.ResponseWriter, e *shared.StepUpError) {
	if e.Unavailable {
		apierror.New(http.StatusForbidden, CodeStepUpUnavailable, e.Message).WriteJSON(w)
		return
	}
	apierror.New(http.StatusForbidden, CodeStepUpRequired, e.Message).
		WithDetails(map[string]int{"window_seconds": int(e.Window.Seconds())}).WriteJSON(w)
}

// recentEnough reports whether at lies within window before now (and not
// more than a minute of clock skew ahead).
func recentEnough(at time.Time, window time.Duration) bool {
	now := time.Now()
	return !at.IsZero() && !at.After(now.Add(time.Minute)) && now.Sub(at) <= window
}
