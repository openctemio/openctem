package middleware

import (
	"context"
	"net/http"

	"github.com/openctemio/openctem/server/pkg/apierror"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// CodeOwnSignInRequired answers an action on the account itself from a
// session that an organization's identity provider issued
// (docs/architecture/organization-settings.md#identity-provider-binding).
const CodeOwnSignInRequired apierror.Code = "OWN_SIGN_IN_REQUIRED"

// OwnSignInChecker decides whether the session must be the account's own
// sign-in (AuthService.OwnSignInRequired).
type OwnSignInChecker interface {
	OwnSignInRequired(ctx context.Context, userID, sessionID string) (bool, error)
}

// RequireOwnSignIn guards a route that acts on the whole account (deleting
// it, signing it out everywhere): such an action reaches every organization
// the person belongs to, so one organization's identity provider may not take
// it in the account's name. A nil checker lets requests through: only the
// local sign-in mode has organization IdP sessions, and it always wires one.
// A request without a user session (API key) is refused; a failure to decide
// refuses too.
func RequireOwnSignIn(checker OwnSignInChecker) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if checker == nil {
				next.ServeHTTP(w, r)
				return
			}
			ctx := r.Context()
			userID, sessionID := GetUserID(ctx), GetSessionID(ctx)
			if IsAPIKeyAuthenticated(ctx) || userID == "" || sessionID == "" {
				apierror.New(http.StatusForbidden, CodeStepUpUnavailable,
					"This action needs a signed-in user session").WriteJSON(w)
				return
			}
			required, err := checker.OwnSignInRequired(ctx, userID, sessionID)
			if err != nil {
				if l := logger.FromContext(ctx); l != nil {
					l.Error("own sign-in check failed", "error", logger.SanitizeError(err))
				}
				apierror.InternalServerError("could not check the sign-in").WriteJSON(w)
				return
			}
			if required {
				apierror.New(http.StatusForbidden, CodeOwnSignInRequired,
					"Your session comes from an organization's identity provider. Sign in with your own account to change the account itself.").WriteJSON(w)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
