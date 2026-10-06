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
			// A token from the external OIDC provider has no platform
			// session: its recent authentication is the provider's own,
			// the signature-verified auth_time claim. The client steps up
			// by signing in at the provider again (prompt=login, max_age=0)
			// and sending the new token.
			if GetAuthProvider(ctx) == AuthProviderOIDC {
				requireRecentProviderAuth(w, r, next, window)
				return
			}
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
			if err != nil || !recentEnough(at, window) {
				writeStepUpRequired(w, window)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func requireRecentProviderAuth(w http.ResponseWriter, r *http.Request, next http.Handler, window time.Duration) {
	claims := GetClaims(r.Context())
	if claims == nil || claims.AuthTime == nil {
		apierror.New(http.StatusForbidden, CodeStepUpUnavailable,
			"This token does not say when you signed in; sign in again at your identity provider").WriteJSON(w)
		return
	}
	if !recentEnough(claims.AuthTime.Time, window) {
		writeStepUpRequired(w, window)
		return
	}
	next.ServeHTTP(w, r)
}

// recentEnough reports whether at lies within window before now (and not
// more than a minute of clock skew ahead).
func recentEnough(at time.Time, window time.Duration) bool {
	now := time.Now()
	return !at.IsZero() && !at.After(now.Add(time.Minute)) && now.Sub(at) <= window
}

func writeStepUpRequired(w http.ResponseWriter, window time.Duration) {
	apierror.New(http.StatusForbidden, CodeStepUpRequired,
		"Confirm your identity to continue").
		WithDetails(map[string]int{"window_seconds": int(window.Seconds())}).WriteJSON(w)
}
