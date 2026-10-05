package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/app"
	"github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Two-factor authentication endpoints: the second login step under
// /auth/mfa/* (public, authorized by the login challenge token) and the
// signed-in user's own 2FA management under /users/me/2fa.

// MFAChallengeResponse is returned by POST /auth/login instead of a session
// when the password was correct but a second factor is needed. mfa_purpose is
// "verify" (enter a code) or "enroll" (the organization requires 2FA and the
// user must set it up first). mfa_token is not an access token.
type MFAChallengeResponse struct {
	MFARequired bool   `json:"mfa_required"`
	MFAToken    string `json:"mfa_token"`
	MFAPurpose  string `json:"mfa_purpose"`
	ExpiresIn   int64  `json:"expires_in"`
}

func writeMFAChallenge(w http.ResponseWriter, c *app.MFAChallengeInfo) {
	expires := int64(time.Until(c.ExpiresAt).Seconds())
	if expires < 0 {
		expires = 0
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(MFAChallengeResponse{
		MFARequired: true,
		MFAToken:    c.Token,
		MFAPurpose:  string(c.Purpose),
		ExpiresIn:   expires,
	})
}

// selfAuditContext builds the audit context for a user acting on their own
// account.
func selfAuditContext(r *http.Request) audit.AuditContext {
	return audit.AuditContext{
		ActorID:    middleware.GetUserID(r.Context()),
		ActorEmail: middleware.GetEmail(r.Context()),
		ActorIP:    getClientIP(r),
		UserAgent:  r.UserAgent(),
		SessionID:  middleware.GetSessionID(r.Context()),
	}
}

// VerifyMFARequest is the second login step. Send either code (6 digits from
// the authenticator app) or recovery_code.
type VerifyMFARequest struct {
	MFAToken     string `json:"mfa_token" validate:"required,max=128"`
	Code         string `json:"code" validate:"omitempty,max=16"`
	RecoveryCode string `json:"recovery_code" validate:"omitempty,max=32"`
}

// VerifyMFA completes a login that needs a second factor.
// @Summary      Verify second factor
// @Description  Completes a password login with a TOTP code or a recovery code. Returns the same response as a password login without 2FA.
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        request  body      VerifyMFARequest  true  "Challenge token and code"
// @Success      200  {object}  LoginResponse
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      403  {object}  map[string]string
// @Router       /auth/mfa/verify [post]
func (h *LocalAuthHandler) VerifyMFA(w http.ResponseWriter, r *http.Request) {
	var req VerifyMFARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	if err := h.validator.Validate(req); err != nil {
		apierror.ValidationFailed("Validation failed", err).WriteJSON(w)
		return
	}
	if req.Code == "" && req.RecoveryCode == "" {
		apierror.BadRequest("code or recovery_code is required").WriteJSON(w)
		return
	}
	result, err := h.authService.VerifyMFALogin(r.Context(), app.VerifyMFAInput{
		Token:        req.MFAToken,
		Code:         req.Code,
		RecoveryCode: req.RecoveryCode,
		IPAddress:    getClientIP(r),
		UserAgent:    r.UserAgent(),
	})
	if err != nil {
		h.handleAuthError(w, err)
		return
	}
	h.writeLoginSuccess(w, r, result, nil)
}

// MFAEnrollmentStartRequest starts enrollment from a login enrollment challenge.
type MFAEnrollmentStartRequest struct {
	MFAToken string `json:"mfa_token" validate:"required,max=128"`
}

// MFASetupResponse carries a new authenticator secret. The client renders
// otpauth_uri as a QR code; secret is for manual entry.
type MFASetupResponse struct {
	Secret     string `json:"secret"`
	OTPAuthURI string `json:"otpauth_uri"`
}

// StartMFAEnrollment issues a secret to a user whose organization requires 2FA.
// @Summary      Start required 2FA enrollment
// @Description  For a login that returned mfa_purpose=enroll: returns a new TOTP secret to add to an authenticator app.
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        request  body      MFAEnrollmentStartRequest  true  "Challenge token"
// @Success      200  {object}  MFASetupResponse
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Router       /auth/mfa/enroll/start [post]
func (h *LocalAuthHandler) StartMFAEnrollment(w http.ResponseWriter, r *http.Request) {
	var req MFAEnrollmentStartRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	if err := h.validator.Validate(req); err != nil {
		apierror.ValidationFailed("Validation failed", err).WriteJSON(w)
		return
	}
	setup, err := h.authService.BeginMFAEnrollmentFromChallenge(r.Context(), req.MFAToken)
	if err != nil {
		h.handleAuthError(w, err)
		return
	}
	writeNoStoreJSON(w, http.StatusOK, MFASetupResponse{Secret: setup.Secret, OTPAuthURI: setup.OTPAuthURI})
}

// MFAEnrollmentConfirmRequest confirms a required enrollment with a code.
type MFAEnrollmentConfirmRequest struct {
	MFAToken string `json:"mfa_token" validate:"required,max=128"`
	Code     string `json:"code" validate:"required,max=16"`
}

// ConfirmMFAEnrollment turns 2FA on and signs the user in.
// @Summary      Confirm required 2FA enrollment
// @Description  Confirms the authenticator with a code, turns 2FA on and completes the login. The response is a login response plus recovery_codes, shown once.
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        request  body      MFAEnrollmentConfirmRequest  true  "Challenge token and code"
// @Success      200  {object}  LoginResponse
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Router       /auth/mfa/enroll/confirm [post]
func (h *LocalAuthHandler) ConfirmMFAEnrollment(w http.ResponseWriter, r *http.Request) {
	var req MFAEnrollmentConfirmRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	if err := h.validator.Validate(req); err != nil {
		apierror.ValidationFailed("Validation failed", err).WriteJSON(w)
		return
	}
	result, codes, err := h.authService.CompleteMFAEnrollmentFromChallenge(r.Context(), app.CompleteMFAEnrollmentInput{
		Token:     req.MFAToken,
		Code:      req.Code,
		IPAddress: getClientIP(r),
		UserAgent: r.UserAgent(),
	})
	if err != nil {
		h.handleAuthError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	h.writeLoginSuccess(w, r, result, codes)
}

// ---------------------------------------------------------------------------
// /users/me/2fa
// ---------------------------------------------------------------------------

// MFACodeRequest carries a 6-digit authenticator code.
type MFACodeRequest struct {
	Code string `json:"code" validate:"required,max=16"`
}

// MFAEnableRequest confirms 2FA setup. The current password is required:
// a stolen session alone must not be able to bind an authenticator.
type MFAEnableRequest struct {
	Password string `json:"password" validate:"required,max=128"`
	Code     string `json:"code" validate:"required,max=16"`
}

// MFADisableRequest turns 2FA off. code may be an authenticator code or an
// unused recovery code.
type MFADisableRequest struct {
	Password string `json:"password" validate:"required,max=128"`
	Code     string `json:"code" validate:"required,max=32"`
}

// MFARecoveryCodesResponse carries recovery codes, shown once.
type MFARecoveryCodesResponse struct {
	RecoveryCodes []string `json:"recovery_codes"`
}

// GetMFAStatus returns the signed-in user's 2FA status.
// @Summary      Get my 2FA status
// @Tags         Users
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  app.MFAStatus
// @Failure      401  {object}  map[string]string
// @Router       /users/me/2fa [get]
func (h *LocalAuthHandler) GetMFAStatus(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	if userID == "" {
		apierror.Unauthorized("User not authenticated").WriteJSON(w)
		return
	}
	st, err := h.authService.GetMFAStatus(r.Context(), userID)
	if err != nil {
		h.handleSelfServiceMFAError(w, err)
		return
	}
	writeNoStoreJSON(w, http.StatusOK, st)
}

// SetupMFA starts (or restarts) enrollment for the signed-in user.
// @Summary      Start 2FA setup
// @Description  Generates a new TOTP secret. Nothing changes until it is confirmed with POST /users/me/2fa/enable.
// @Tags         Users
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  MFASetupResponse
// @Failure      400  {object}  map[string]string
// @Failure      409  {object}  map[string]string
// @Router       /users/me/2fa/setup [post]
func (h *LocalAuthHandler) SetupMFA(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	if userID == "" {
		apierror.Unauthorized("User not authenticated").WriteJSON(w)
		return
	}
	setup, err := h.authService.BeginMFASetup(r.Context(), userID)
	if err != nil {
		h.handleSelfServiceMFAError(w, err)
		return
	}
	writeNoStoreJSON(w, http.StatusOK, MFASetupResponse{Secret: setup.Secret, OTPAuthURI: setup.OTPAuthURI})
}

// EnableMFA confirms setup with a code and turns 2FA on.
// @Summary      Enable 2FA
// @Description  Confirms the authenticator with a code and turns 2FA on. Needs the current password. Signs out every other session. Returns recovery codes, shown once.
// @Tags         Users
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        request  body      MFAEnableRequest  true  "Current password and authenticator code"
// @Success      200  {object}  MFARecoveryCodesResponse
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Router       /users/me/2fa/enable [post]
func (h *LocalAuthHandler) EnableMFA(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	if userID == "" {
		apierror.Unauthorized("User not authenticated").WriteJSON(w)
		return
	}
	var req MFAEnableRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	if err := h.validator.Validate(req); err != nil {
		apierror.ValidationFailed("Validation failed", err).WriteJSON(w)
		return
	}
	codes, err := h.authService.EnableMFA(r.Context(), selfAuditContext(r), userID, req.Password, req.Code)
	if err != nil {
		h.handleSelfServiceMFAError(w, err)
		return
	}
	writeNoStoreJSON(w, http.StatusOK, MFARecoveryCodesResponse{RecoveryCodes: codes})
}

// DisableMFA turns 2FA off for the signed-in user.
// @Summary      Disable 2FA
// @Description  Turns 2FA off. Requires the current password and an authenticator code or unused recovery code.
// @Tags         Users
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        request  body      MFADisableRequest  true  "Password and code"
// @Success      200  {object}  map[string]string
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Router       /users/me/2fa/disable [post]
func (h *LocalAuthHandler) DisableMFA(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	if userID == "" {
		apierror.Unauthorized("User not authenticated").WriteJSON(w)
		return
	}
	var req MFADisableRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	if err := h.validator.Validate(req); err != nil {
		apierror.ValidationFailed("Validation failed", err).WriteJSON(w)
		return
	}
	if err := h.authService.DisableMFA(r.Context(), selfAuditContext(r), userID, req.Password, req.Code); err != nil {
		h.handleSelfServiceMFAError(w, err)
		return
	}
	writeNoStoreJSON(w, http.StatusOK, map[string]string{"message": "Two-factor authentication disabled"})
}

// RegenerateRecoveryCodes replaces the signed-in user's recovery codes.
// @Summary      Regenerate 2FA recovery codes
// @Description  Replaces every recovery code. Requires a current authenticator code. Returns the new codes, shown once.
// @Tags         Users
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        request  body      MFACodeRequest  true  "Authenticator code"
// @Success      200  {object}  MFARecoveryCodesResponse
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Router       /users/me/2fa/recovery-codes [post]
func (h *LocalAuthHandler) RegenerateRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	if userID == "" {
		apierror.Unauthorized("User not authenticated").WriteJSON(w)
		return
	}
	var req MFACodeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	if err := h.validator.Validate(req); err != nil {
		apierror.ValidationFailed("Validation failed", err).WriteJSON(w)
		return
	}
	codes, err := h.authService.RegenerateRecoveryCodes(r.Context(), selfAuditContext(r), userID, req.Code)
	if err != nil {
		h.handleSelfServiceMFAError(w, err)
		return
	}
	writeNoStoreJSON(w, http.StatusOK, MFARecoveryCodesResponse{RecoveryCodes: codes})
}

// handleSelfServiceMFAError maps errors of the signed-in /users/me/2fa calls.
// A wrong code there is a 400: the caller is authenticated, and clients treat
// a 401 as an expired session (they sign the user out). The public login step
// keeps 401 for a wrong code (handleAuthError).
func (h *LocalAuthHandler) handleSelfServiceMFAError(w http.ResponseWriter, err error) {
	if errors.Is(err, app.ErrMFACodeInvalid) {
		apierror.BadRequest("Invalid verification code").WriteJSON(w)
		return
	}
	h.handleAuthError(w, err)
}

// writeNoStoreJSON writes a JSON body that must never be cached (secrets,
// recovery codes).
func writeNoStoreJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// ResetMemberMFA turns off a member's two-factor authentication.
// @Summary      Reset a member's two-factor authentication
// @Description  An owner or administrator turns off the second factor of a member of their organization who lost their authenticator and recovery codes. The member is signed out everywhere and e-mailed. An owner or administrator target needs the owner; a member who also belongs to another organization needs the same authority there; nobody resets their own factor here.
// @Tags         Tenants
// @Produce      json
// @Param        member_id  path  string  true  "Membership ID"
// @Success      200  {object}  map[string]string
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /organization/members/{member_id}/mfa [delete]
func (h *LocalAuthHandler) ResetMemberMFA(w http.ResponseWriter, r *http.Request) {
	membershipID := chi.URLParam(r, "member_id")
	tenantID := middleware.GetTenantID(r.Context())
	if membershipID == "" || tenantID == "" {
		apierror.BadRequest("Member ID is required").WriteJSON(w)
		return
	}
	actx := audit.AuditContext{
		ActorIP:   getClientIP(r),
		UserAgent: r.UserAgent(),
		RequestID: r.Header.Get("X-Request-ID"),
		TenantID:  tenantID,
	}
	if u := middleware.GetLocalUser(r.Context()); u != nil {
		actx.ActorID = u.ID().String()
		actx.ActorEmail = u.Email()
	}
	if actx.ActorID == "" {
		apierror.Unauthorized("Authentication required").WriteJSON(w)
		return
	}
	if err := h.authService.ResetMemberMFA(r.Context(), actx, tenantID, membershipID); err != nil {
		switch {
		case errors.Is(err, shared.ErrNotFound):
			apierror.NotFound("Member").WriteJSON(w)
		case errors.Is(err, shared.ErrForbidden), errors.Is(err, shared.ErrValidation):
			msg := err.Error()
			if i := strings.Index(msg, ": "); i != -1 {
				msg = msg[i+2:]
			}
			if errors.Is(err, shared.ErrForbidden) {
				apierror.Forbidden(msg).WriteJSON(w)
			} else {
				apierror.BadRequest(msg).WriteJSON(w)
			}
		default:
			h.handleAuthError(w, err)
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"message": "Two-factor authentication reset"})
}
