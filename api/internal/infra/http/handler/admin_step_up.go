package handler

import (
	"errors"
	"net/http"
	"strings"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// confirmAdminStepUp checks a fresh console authenticator code for one
// sensitive console action (purpose names it in the audit trail). It writes
// the refusal and returns false when the code is missing, wrong, replayed or
// cannot be checked. A nil verifier refuses: the action never runs
// unconfirmed.
func confirmAdminStepUp(w http.ResponseWriter, r *http.Request, v StepUpVerifier, code, purpose string, log *logger.Logger) bool {
	actor := middleware.GetAdminUser(r.Context())
	if actor == nil {
		apierror.Unauthorized("administrator session required").WriteJSON(w)
		return false
	}
	if v == nil {
		apierror.ServiceUnavailable("This action is not available").WriteJSON(w)
		return false
	}
	code = strings.TrimSpace(code)
	if code == "" {
		apierror.New(http.StatusUnauthorized, codeStepUpRequired, "Enter a code from your authenticator to confirm").WriteJSON(w)
		return false
	}
	if err := v.StepUp(r.Context(), actor, code, purpose, clientInfo(r)); err != nil {
		switch {
		case errors.Is(err, admin.ErrStepUpUnavailable):
			apierror.New(http.StatusForbidden, codeStepUpUnavailable,
				"Enroll the console authenticator (sign in with your password and TOTP) to confirm this action").WriteJSON(w)
		case errors.Is(err, admin.ErrInvalidMFACode):
			apierror.Unauthorized("Invalid or already used code; wait for your authenticator to show a new one").WriteJSON(w)
		default:
			log.Error("console step-up", "purpose", purpose, "error", err)
			apierror.InternalServerError("could not verify the code").WriteJSON(w)
		}
		return false
	}
	return true
}
