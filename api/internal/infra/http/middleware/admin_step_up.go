package middleware

// Route-level step-up for protected console actions (RFC-022, research on the
// admin plane): every identity, privilege and platform-trust change asks for a
// fresh authenticator code, or rides the step-up window of the same console
// session. The rule is declared in the route table, not in each handler, so a
// new protected route cannot forget it (see the admin route inventory test).

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// AdminStepUpHeader carries the fresh authenticator code of a protected
// console action. A header, not the body, so one middleware serves every
// route whatever its body looks like.
const AdminStepUpHeader = "X-Admin-Step-Up"

// Codes of the route-level step-up refusals. ADMIN_STEP_UP_REQUIRED tells the
// console to ask for a code and retry with AdminStepUpHeader.
const (
	CodeAdminStepUpRequired    apierror.Code = "ADMIN_STEP_UP_REQUIRED"
	CodeAdminStepUpUnavailable apierror.Code = "STEP_UP_UNAVAILABLE"
	// CodeAdminStepUpWebAuthn: the console requires security keys; confirm
	// through the WebAuthn step-up and retry inside its window.
	CodeAdminStepUpWebAuthn apierror.Code = "WEBAUTHN_REQUIRED"
)

// adminSteppedUpKey marks a request whose route-level step-up passed.
const adminSteppedUpKey logger.ContextKey = "admin_stepped_up"

// AdminSteppedUp reports whether this request passed RequireAdminStepUp, so a
// handler that also checks a code does not ask for a second one.
func AdminSteppedUp(ctx context.Context) bool {
	v, _ := ctx.Value(adminSteppedUpKey).(bool)
	return v
}

// AdminStepUpConfirmer checks a protected action (adminconsole.Service).
type AdminStepUpConfirmer interface {
	ConfirmProtected(ctx context.Context, a *admin.AdminUser, sess *admin.Session, code, purpose string, client AdminStepUpClient) error
}

// AdminStepUpClient is who asked, for the audit row.
type AdminStepUpClient struct {
	IP        string
	UserAgent string
}

// AdminStepUpFunc adapts a function to AdminStepUpConfirmer.
type AdminStepUpFunc func(ctx context.Context, a *admin.AdminUser, sess *admin.Session, code, purpose string, client AdminStepUpClient) error

// ConfirmProtected implements AdminStepUpConfirmer.
func (f AdminStepUpFunc) ConfirmProtected(ctx context.Context, a *admin.AdminUser, sess *admin.Session, code, purpose string, client AdminStepUpClient) error {
	return f(ctx, a, sess, code, purpose, client)
}

// RequireAdminStepUp gates a protected console action. It runs after
// Authenticate and the role guard. A nil confirmer refuses every request: a
// protected action never runs unconfirmed.
func RequireAdminStepUp(c AdminStepUpConfirmer, purpose string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			actor := GetAdminUser(r.Context())
			if actor == nil {
				apierror.Unauthorized("administrator session required").WriteJSON(w)
				return
			}
			if c == nil {
				apierror.ServiceUnavailable("This action is not available").WriteJSON(w)
				return
			}
			code := strings.TrimSpace(r.Header.Get(AdminStepUpHeader))
			client := AdminStepUpClient{IP: ClientIP(r), UserAgent: r.UserAgent()}
			err := c.ConfirmProtected(r.Context(), actor, GetAdminSession(r.Context()), code, purpose, client)
			switch {
			case err == nil:
				next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), adminSteppedUpKey, true)))
			case errors.Is(err, admin.ErrStepUpRequired):
				apierror.New(http.StatusUnauthorized, CodeAdminStepUpRequired,
					"Confirm this action with a fresh code from your authenticator").WriteJSON(w)
			case errors.Is(err, admin.ErrStepUpUnavailable):
				apierror.New(http.StatusForbidden, CodeAdminStepUpUnavailable,
					"Enroll the console authenticator (sign in with your password and TOTP) to confirm this action").WriteJSON(w)
			case errors.Is(err, admin.ErrWebAuthnRequired):
				apierror.New(http.StatusForbidden, CodeAdminStepUpWebAuthn,
					"Confirm this action with your security key or passkey").WriteJSON(w)
			case errors.Is(err, admin.ErrInvalidMFACode):
				apierror.New(http.StatusUnauthorized, CodeAdminStepUpRequired,
					"Invalid or already used code; wait for your authenticator to show a new one").WriteJSON(w)
			default:
				// The confirmer logs the cause; the caller learns nothing more.
				apierror.InternalServerError("could not verify the code").WriteJSON(w)
			}
		})
	}
}
