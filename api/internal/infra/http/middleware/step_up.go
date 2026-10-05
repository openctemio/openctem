package middleware

// RequireRecentAuth: step-up re-authentication for sensitive routes
// (docs/architecture/step-up-reauth.md).

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/openctemio/openctem/api/pkg/apierror"
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
			ctx := r.Context()
			userID, sessionID := GetUserID(ctx), GetSessionID(ctx)
			if checker == nil || IsAPIKeyAuthenticated(ctx) || userID == "" || sessionID == "" {
				apierror.New(http.StatusForbidden, CodeStepUpUnavailable,
					"This action needs a signed-in user session that can re-authenticate").WriteJSON(w)
				return
			}
			at, err := checker.RecentAuthAt(ctx, userID, sessionID)
			if err != nil && !errors.Is(err, ErrNoRecentAuth) {
				if l := logger.FromContext(ctx); l != nil {
					l.Error("step-up check failed", "error", logger.SanitizeError(err))
				}
				apierror.InternalServerError("could not check re-authentication").WriteJSON(w)
				return
			}
			now := time.Now()
			if err != nil || at.IsZero() || at.After(now.Add(time.Minute)) || now.Sub(at) > window {
				apierror.New(http.StatusForbidden, CodeStepUpRequired,
					"Confirm your identity to continue").
					WithDetails(map[string]int{"window_seconds": int(window.Seconds())}).WriteJSON(w)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
