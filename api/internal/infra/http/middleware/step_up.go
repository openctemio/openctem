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

// Errors CheckRecentAuth returns for a caller that has not re-authenticated
// recently (ErrStepUpRequired) or cannot (ErrStepUpUnavailable).
var (
	ErrStepUpRequired    = errors.New("step-up re-authentication required")
	ErrStepUpUnavailable = errors.New("step-up re-authentication unavailable for this credential")
)

// CheckRecentAuth is the RequireRecentAuth decision for code that only knows
// inside a service whether an action is sensitive (a grant change that widens).
// It fails closed: any other error means the check itself failed.
//
// A token from the external OIDC provider has no platform session: its recent
// authentication is the provider's own, the signature-verified auth_time
// claim. The client steps up by signing in at the provider again
// (prompt=login, max_age=0) and sending the new token; a token without
// auth_time cannot step up.
func CheckRecentAuth(ctx context.Context, checker RecentAuthChecker, window time.Duration) error {
	if GetAuthProvider(ctx) == AuthProviderOIDC {
		claims := GetClaims(ctx)
		if claims == nil || claims.AuthTime == nil {
			return ErrStepUpUnavailable
		}
		if !recentEnough(claims.AuthTime.Time, window) {
			return ErrStepUpRequired
		}
		return nil
	}
	userID, sessionID := GetUserID(ctx), GetSessionID(ctx)
	if checker == nil || IsAPIKeyAuthenticated(ctx) || userID == "" || sessionID == "" {
		return ErrStepUpUnavailable
	}
	at, err := checker.RecentAuthAt(ctx, userID, sessionID)
	if err != nil && !errors.Is(err, ErrNoRecentAuth) {
		return err
	}
	if err != nil || !recentEnough(at, window) {
		return ErrStepUpRequired
	}
	return nil
}

// recentEnough reports whether at lies within window before now (and not
// more than a minute of clock skew ahead).
func recentEnough(at time.Time, window time.Duration) bool {
	now := time.Now()
	return !at.IsZero() && !at.After(now.Add(time.Minute)) && now.Sub(at) <= window
}

// WriteStepUpError answers ErrStepUpRequired / ErrStepUpUnavailable the way
// RequireRecentAuth does, so the web client's re-authentication dialog
// handles both paths. It reports false for any other error.
func WriteStepUpError(w http.ResponseWriter, err error, window time.Duration) bool {
	switch {
	case errors.Is(err, ErrStepUpRequired):
		apierror.New(http.StatusForbidden, CodeStepUpRequired, "Confirm your identity to continue").
			WithDetails(map[string]int{"window_seconds": int(window.Seconds())}).WriteJSON(w)
	case errors.Is(err, ErrStepUpUnavailable):
		apierror.New(http.StatusForbidden, CodeStepUpUnavailable,
			"This action needs a signed-in user session that can re-authenticate").WriteJSON(w)
	default:
		return false
	}
	return true
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
			if err := CheckRecentAuth(ctx, checker, window); err != nil {
				if WriteStepUpError(w, err, window) {
					return
				}
				if l := logger.FromContext(ctx); l != nil {
					l.Error("step-up check failed", "error", logger.SanitizeError(err))
				}
				apierror.InternalServerError("could not check re-authentication").WriteJSON(w)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
