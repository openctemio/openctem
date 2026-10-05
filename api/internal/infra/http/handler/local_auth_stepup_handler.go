package handler

// Step-up re-authentication endpoints (docs/architecture/step-up-reauth.md).

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/openctemio/openctem/api/internal/app"
	authapp "github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// StepUpRequest is the proof for POST /auth/step-up: totp when the account
// has an authenticator, otherwise password.
type StepUpRequest struct {
	TOTP     string `json:"totp" validate:"omitempty,max=16"`
	Password string `json:"password" validate:"omitempty,max=128"`
}

// StepUpResponse reports the window a successful step-up opened.
type StepUpResponse struct {
	ValidUntil    time.Time `json:"valid_until"`
	WindowSeconds int       `json:"window_seconds"`
}

// GetStepUp reports what the signed-in user must present and whether the
// current session is inside its re-authentication window.
// @Summary      Step-up re-authentication state
// @Description  method is totp (an authenticator code), password, or fresh_sign_in (an SSO account without an authenticator: sign in again). valid_until is set while the session is inside its window.
// @Tags         Authentication
// @Produce      json
// @Success      200  {object}  authapp.StepUpState
// @Failure      401  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /auth/step-up [get]
func (h *LocalAuthHandler) GetStepUp(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	if userID == "" {
		apierror.Unauthorized("User not authenticated").WriteJSON(w)
		return
	}
	state, err := h.authService.GetStepUpState(r.Context(), userID, middleware.GetSessionID(r.Context()))
	if err != nil {
		h.logger.Error("step-up state", "error", logger.SanitizeError(err))
		apierror.InternalServerError("could not read re-authentication state").WriteJSON(w)
		return
	}
	writeNoStoreJSON(w, http.StatusOK, state)
}

// StepUp re-authenticates the signed-in user and opens a short window on this
// session in which sensitive actions are accepted.
// @Summary      Step-up re-authentication
// @Description  Verifies a current authenticator code (accounts with two-factor authentication; recovery codes are not accepted) or the password (other local accounts) and lets this session perform sensitive actions for 10 minutes. The window belongs to this session only and is extended only by another successful step-up. Failures count towards the account lockout. SSO accounts without an authenticator get STEP_UP_UNAVAILABLE and sign in again instead.
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        request  body      StepUpRequest  true  "Authenticator code or password"
// @Success      200  {object}  StepUpResponse
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      429  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /auth/step-up [post]
func (h *LocalAuthHandler) StepUp(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	if userID == "" {
		apierror.Unauthorized("User not authenticated").WriteJSON(w)
		return
	}
	var req StepUpRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	if err := h.validator.Validate(req); err != nil {
		apierror.ValidationFailed("Validation failed", err).WriteJSON(w)
		return
	}
	actx := selfAuditContext(r)
	actx.TenantID = middleware.GetTenantID(r.Context())
	until, err := h.authService.StepUp(r.Context(), actx, userID, middleware.GetSessionID(r.Context()),
		authapp.StepUpProof{TOTP: req.TOTP, Password: req.Password})
	switch {
	case err == nil:
		writeNoStoreJSON(w, http.StatusOK, StepUpResponse{ValidUntil: until, WindowSeconds: int(authapp.StepUpWindow.Seconds())})
	case errors.Is(err, authapp.ErrStepUpRequired):
		apierror.BadRequest("Enter your authenticator code or password").WriteJSON(w)
	case errors.Is(err, authapp.ErrStepUpFailed):
		apierror.New(http.StatusForbidden, "STEP_UP_FAILED", "Re-authentication failed").WriteJSON(w)
	case errors.Is(err, app.ErrAccountLocked):
		apierror.Forbidden("Account is locked due to too many failed attempts").WriteJSON(w)
	case errors.Is(err, authapp.ErrStepUpUnavailable):
		apierror.New(http.StatusForbidden, middleware.CodeStepUpUnavailable,
			"Sign in again to confirm your identity").WriteJSON(w)
	default:
		h.logger.Error("step-up", "error", logger.SanitizeError(err))
		apierror.InternalServerError("re-authentication failed").WriteJSON(w)
	}
}

// RecentAuthChecker is what middleware.RequireRecentAuth asks: when the
// caller last signed in or stepped up in their session.
func (h *LocalAuthHandler) RecentAuthChecker() middleware.RecentAuthChecker {
	return recentAuthChecker{svc: h.authService}
}

type recentAuthChecker struct{ svc *app.AuthService }

func (c recentAuthChecker) RecentAuthAt(ctx context.Context, userID, sessionID string) (time.Time, error) {
	at, err := c.svc.RecentAuthAt(ctx, userID, sessionID)
	if errors.Is(err, authapp.ErrStepUpUnavailable) {
		return time.Time{}, middleware.ErrNoRecentAuth
	}
	return at, err
}
