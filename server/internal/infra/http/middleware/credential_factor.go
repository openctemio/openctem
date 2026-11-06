package middleware

// RequireCredentialFactor: creating a credential (API key, sensor
// enrolment, integration secret) needs a second factor when the organization
// or the platform's two-factor floor covers the caller, even while the
// caller's grace period for sign-in has not ended. Design: research 308,
// decision D16; docs/architecture/two-factor-floor.md.

import (
	"context"
	"errors"
	"net/http"

	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Errors a CredentialFactorChecker returns for a caller without the factor
// (ErrCredentialFactorRequired) or whose organization needs its identity
// provider to prove one (ErrCredentialProofRequired).
var (
	ErrCredentialFactorRequired = errors.New("two-factor authentication must be set up before creating credentials")
	ErrCredentialProofRequired  = errors.New("the identity provider must prove a second factor before creating credentials")
)

// CredentialFactorChecker decides for a signed-in user (auth.AuthService).
// It returns nil, ErrCredentialFactorRequired or ErrCredentialProofRequired;
// any other error means the check itself failed.
type CredentialFactorChecker interface {
	CheckCredentialFactor(ctx context.Context, userID, tenantID, sessionID string) error
}

// RequireCredentialFactor admits a request only when the caller holds the
// factor the policy asks for. Otherwise it answers 403 MFA_ENROLLMENT_REQUIRED
// (the web client opens its two-factor setup). A caller that is not a user
// session (an API key, which cannot create credentials here anyway) and a nil
// checker pass; a failed check refuses (fail closed). Mount it after
// authentication, the route's permission check and the step-up.
func RequireCredentialFactor(c CredentialFactorChecker) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			if c == nil || IsAPIKeyAuthenticated(ctx) {
				next.ServeHTTP(w, r)
				return
			}
			err := c.CheckCredentialFactor(ctx, GetUserID(ctx), GetTenantID(ctx), GetSessionID(ctx))
			switch {
			case err == nil:
				next.ServeHTTP(w, r)
			case errors.Is(err, ErrCredentialFactorRequired):
				apierror.New(http.StatusForbidden, apierror.CodeMFAEnrollmentRequired,
					"Set up two-factor authentication before creating credentials.").WriteJSON(w)
			case errors.Is(err, ErrCredentialProofRequired):
				apierror.New(http.StatusForbidden, apierror.CodeMFAEnrollmentRequired,
					"This organization requires your identity provider to confirm a second factor. Sign in again through your identity provider with multi-factor authentication.").WriteJSON(w)
			default:
				if l := logger.FromContext(ctx); l != nil {
					l.Error("credential factor check failed", "error", logger.SanitizeError(err))
				}
				apierror.InternalServerError("could not check two-factor authentication").WriteJSON(w)
			}
		})
	}
}
