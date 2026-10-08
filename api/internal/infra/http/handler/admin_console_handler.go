package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/app/adminconsole"
	"github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/password"
)

// Cookie paths: the pending-MFA cookie only reaches the auth endpoints, the
// session cookie only the admin API, the CSRF cookie must be readable by the
// console page so it is site-wide (it is not a credential on its own).
const (
	adminAuthPath = "/api/v1/admin/auth"
	adminAPIPath  = "/api/v1/admin"
)

// AdminConsoleHandler serves platform admin console login (RFC-022).
type AdminConsoleHandler struct {
	svc                *adminconsole.Service
	cookieSecure       bool
	refreshTokenCookie string
	logger             *logger.Logger
}

// NewAdminConsoleHandler creates the handler. cookieSecure mirrors
// AUTH_COOKIE_SECURE (true in production, behind HTTPS).
// refreshTokenCookie is the name of the normal sign-in refresh-token cookie
// (AUTH_REFRESH_TOKEN_COOKIE_NAME): the console session starts from it.
func NewAdminConsoleHandler(svc *adminconsole.Service, cookieSecure bool, refreshTokenCookie string, log *logger.Logger) *AdminConsoleHandler {
	if refreshTokenCookie == "" {
		refreshTokenCookie = "refresh_token"
	}
	return &AdminConsoleHandler{
		svc: svc, cookieSecure: cookieSecure, refreshTokenCookie: refreshTokenCookie,
		logger: log.With("handler", "admin_console"),
	}
}

// AdminLoginResponse tells the client which second step follows.
type AdminLoginResponse struct {
	Status     string `json:"status"`
	OTPAuthURI string `json:"otpauth_uri,omitempty"`
	Secret     string `json:"secret,omitempty"`
}

// AdminMFARequest is the TOTP step.
type AdminMFARequest struct {
	Code string `json:"code"`
}

// AdminProvisionRequest makes someone a platform administrator.
type AdminProvisionRequest struct {
	Email string `json:"email"`
	Name  string `json:"name"`
	Role  string `json:"role"`
	// BreakGlass makes a local emergency-access administrator (super_admin only).
	BreakGlass bool `json:"break_glass"`
}

// AdminChangePasswordRequest changes the signed-in administrator's password.
type AdminChangePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// AdminProvisionResponse returns the new administrator; temporary_password is
// set only when a user account had to be created, and is shown once.
type AdminProvisionResponse struct {
	Admin             ValidateResponse `json:"admin"`
	TemporaryPassword string           `json:"temporary_password,omitempty"`
}

func clientInfo(r *http.Request) adminconsole.ClientInfo {
	return adminconsole.ClientInfo{IP: middleware.ClientIP(r), UserAgent: r.UserAgent()}
}

// setCookie writes an admin console cookie. admin_session and admin_mfa are
// HttpOnly (admin_session is forced so a caller can never weaken it);
// admin_csrf is deliberately JS-readable because it is the double-submit CSRF
// token the console echoes in a header, a nonce rather than a credential.
// Secure follows AUTH_COOKIE_SECURE (required in production) and SameSite is
// always Strict: the console never needs its cookies on cross-site requests.
func (h *AdminConsoleHandler) setCookie(w http.ResponseWriter, name, value, path string, maxAge int, httpOnly bool) {
	effectiveHTTPOnly := httpOnly
	if name == middleware.AdminSessionCookie {
		effectiveHTTPOnly = true
	}

	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     path,
		MaxAge:   maxAge,
		HttpOnly: effectiveHTTPOnly,
		Secure:   h.cookieSecure,
		SameSite: http.SameSiteStrictMode,
	})
}

func (h *AdminConsoleHandler) clearCookie(w http.ResponseWriter, name, path string, httpOnly bool) {
	h.setCookie(w, name, "", path, -1, httpOnly)
}

// StartSession handles POST /api/v1/admin/auth/session. The caller has
// already signed in on the normal /login page; their refresh-token cookie
// identifies them. It answers which TOTP step follows and sets the pending
// admin_mfa cookie.
// @Summary Open the platform admin console (after /login)
// @Description Starts a console session for the user signed in on the normal /login page (refresh-token cookie). Only a password sign-in by a user linked to an active platform administrator qualifies; the response says whether to enter a TOTP code or enroll an authenticator first.
// @Tags Admin Auth
// @Produce json
// @Success 200 {object} AdminLoginResponse
// @Failure 401 {object} apierror.Error "Not signed in"
// @Failure 403 {object} apierror.Error "Not a platform administrator, or not a password sign-in"
// @Router /admin/auth/session [post]
func (h *AdminConsoleHandler) StartSession(w http.ResponseWriter, r *http.Request) {
	refresh := ""
	if c, err := r.Cookie(h.refreshTokenCookie); err == nil {
		refresh = c.Value
	}
	res, err := h.svc.Start(r.Context(), refresh, clientInfo(r))
	if err != nil {
		switch {
		case errors.Is(err, admin.ErrNotSignedIn):
			apierror.Unauthorized("Sign in first").WriteJSON(w)
		case errors.Is(err, admin.ErrPasswordSignInRequired):
			apierror.Forbidden("Platform administrators sign in with their password, not single sign-on").WriteJSON(w)
		case errors.Is(err, admin.ErrIdPSignInRequired):
			apierror.New(http.StatusForbidden, codeIdPSignInRequired,
				"Sign in to the admin console with the identity provider").WriteJSON(w)
		case errors.Is(err, admin.ErrNotPlatformAdmin):
			apierror.Forbidden("This account is not a platform administrator").WriteJSON(w)
		default:
			h.logger.Error("admin console start", "error", err)
			apierror.InternalError(err).WriteJSON(w)
		}
		return
	}
	h.setCookie(w, middleware.AdminMFACookie, res.PendingToken, adminAuthPath, int(admin.PendingMFATTL.Seconds()), true)
	writeJSON(w, http.StatusOK, AdminLoginResponse{Status: string(res.Status), OTPAuthURI: res.OTPAuthURI, Secret: res.Secret})
}

// Provision handles POST /api/v1/admin/administrators (super admin).
// @Summary Make someone a platform administrator
// @Description Links the user account with this email (it must not belong to any organization), or creates a local account and returns its temporary password once. The administrator signs in on the normal /login page.
// @Tags Admin Users
// @Accept json
// @Produce json
// @Param request body AdminProvisionRequest true "Administrator"
// @Success 201 {object} AdminProvisionResponse
// @Failure 400 {object} apierror.Error "Bad Request"
// @Failure 409 {object} apierror.Error "Already an administrator, or the account belongs to an organization"
// @Security BearerAuth
// @Router /admin/administrators [post]
func (h *AdminConsoleHandler) Provision(w http.ResponseWriter, r *http.Request) {
	actor := middleware.MustGetAdminUser(r.Context())
	var req AdminProvisionRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	role := admin.AdminRole(req.Role)
	if req.Role == "" {
		role = admin.AdminRoleReadonly
	}
	if !role.IsValid() {
		apierror.BadRequest("role must be super_admin, ops_admin or readonly").WriteJSON(w)
		return
	}
	a, temp, err := h.svc.Provision(r.Context(), actor, adminconsole.ProvisionInput{
		Email: req.Email, Name: req.Name, Role: role, BreakGlass: req.BreakGlass,
	}, clientInfo(r))
	if err != nil {
		switch {
		case errors.Is(err, admin.ErrAdminAlreadyExists), errors.Is(err, admin.ErrUserAlreadyAdmin):
			apierror.Conflict("This person is already a platform administrator").WriteJSON(w)
		case errors.Is(err, admin.ErrEmailHasAccount):
			apierror.Conflict("An account with this email already exists. Platform administrators get a new, dedicated account: use another email.").WriteJSON(w)
		case errors.Is(err, admin.ErrUserHasMemberships):
			apierror.Conflict("This account belongs to an organization. Platform administrators cannot; use a separate account.").WriteJSON(w)
		case shared.IsValidation(err):
			apierror.BadRequest(sanitizeLogField(err.Error())).WriteJSON(w)
		default:
			h.logger.Error("provision administrator", "error", sanitizeLogField(err.Error()))
			apierror.InternalError(err).WriteJSON(w)
		}
		return
	}
	writeJSON(w, http.StatusCreated, AdminProvisionResponse{
		Admin: ValidateResponse{
			ID: a.ID().String(), Email: a.Email(), Name: a.Name(), Role: string(a.Role()),
			IsBreakGlass: a.IsBreakGlass(), PasswordChangeRequired: a.PasswordChangeRequired(),
		},
		TemporaryPassword: temp,
	})
}

// ChangePassword handles POST /api/v1/admin/auth/password.
// @Summary Change your own password
// @Description Changes the signed-in administrator's password (their sign-in account's). Every /login and console session of the account ends, so the administrator signs in again.
// @Tags Admin Auth
// @Accept json
// @Param request body AdminChangePasswordRequest true "Current and new password"
// @Success 204 "No Content"
// @Failure 400 {object} apierror.Error "Wrong current password, or the new one does not meet the policy"
// @Failure 401 {object} apierror.Error "No console session"
// @Router /admin/auth/password [post]
func (h *AdminConsoleHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	a := middleware.MustGetAdminUser(r.Context())
	var req AdminChangePasswordRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil ||
		req.CurrentPassword == "" || req.NewPassword == "" {
		apierror.BadRequest("current_password and new_password are required").WriteJSON(w)
		return
	}
	if err := h.svc.ChangePassword(r.Context(), a, req.CurrentPassword, req.NewPassword, clientInfo(r)); err != nil {
		switch {
		case errors.Is(err, auth.ErrPasswordMismatch):
			apierror.BadRequest("Current password is incorrect").WriteJSON(w)
		case errors.Is(err, password.ErrPasswordTooShort), errors.Is(err, password.ErrPasswordNoUppercase),
			errors.Is(err, password.ErrPasswordNoLowercase), errors.Is(err, password.ErrPasswordNoNumber),
			errors.Is(err, password.ErrPasswordNoSpecial), errors.Is(err, password.ErrPasswordCommon):
			apierror.BadRequest("The new password does not meet the password policy: " + sanitizeLogField(errors.Unwrap(err).Error())).WriteJSON(w)
		default:
			h.logger.Error("admin change password", "error", sanitizeLogField(err.Error()))
			apierror.InternalError(err).WriteJSON(w)
		}
		return
	}
	h.clearCookie(w, middleware.AdminSessionCookie, adminAPIPath, true)
	h.clearCookie(w, middleware.AdminCSRFCookie, "/", false)
	w.WriteHeader(http.StatusNoContent)
}

// VerifyMFA handles POST /api/v1/admin/auth/mfa (TOTP step). On success it
// issues the session and CSRF cookies and returns the admin's profile.
// @Summary Admin console login (TOTP step)
// @Description Verifies the TOTP code for the pending login (admin_mfa cookie) and issues the admin_session and admin_csrf cookies. On first login this also completes authenticator enrollment.
// @Tags Admin Auth
// @Accept json
// @Produce json
// @Param request body AdminMFARequest true "TOTP code"
// @Success 200 {object} ValidateResponse
// @Failure 400 {object} apierror.Error "Bad Request"
// @Failure 401 {object} apierror.Error "Invalid or expired verification code"
// @Router /admin/auth/mfa [post]
func (h *AdminConsoleHandler) VerifyMFA(w http.ResponseWriter, r *http.Request) {
	var req AdminMFARequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&req); err != nil || req.Code == "" {
		apierror.BadRequest("code is required").WriteJSON(w)
		return
	}
	pending := ""
	if c, err := r.Cookie(middleware.AdminMFACookie); err == nil {
		pending = c.Value
	}
	token, a, err := h.svc.VerifyMFA(r.Context(), pending, req.Code, clientInfo(r))
	if err != nil {
		if errors.Is(err, admin.ErrInvalidMFACode) {
			apierror.Unauthorized("Invalid or expired verification code").WriteJSON(w)
			return
		}
		if errors.Is(err, admin.ErrIdPSignInRequired) {
			apierror.New(http.StatusForbidden, codeIdPSignInRequired,
				"Sign in to the admin console with the identity provider").WriteJSON(w)
			return
		}
		h.logger.Error("admin console mfa", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}
	if err := h.issueSessionCookies(w, token); err != nil {
		apierror.InternalError(err).WriteJSON(w)
		return
	}
	writeJSON(w, http.StatusOK, ValidateResponse{
		ID: a.ID().String(), Email: a.Email(), Name: a.Name(), Role: string(a.Role()),
	})
}

// Logout handles POST /api/v1/admin/auth/logout.
// @Summary Admin console logout
// @Description Ends the caller's console session and the /login session it was opened from (refresh-token cookie), and clears the admin cookies.
// @Tags Admin Auth
// @Success 204 "No Content"
// @Router /admin/auth/logout [post]
func (h *AdminConsoleHandler) Logout(w http.ResponseWriter, r *http.Request) {
	session, refresh := "", ""
	if c, err := r.Cookie(middleware.AdminSessionCookie); err == nil {
		session = c.Value
	}
	if c, err := r.Cookie(h.refreshTokenCookie); err == nil {
		refresh = c.Value
	}
	if err := h.svc.Logout(r.Context(), session, refresh, clientInfo(r)); err != nil {
		h.logger.Warn("admin console logout", "error", err)
	}
	h.clearCookie(w, middleware.AdminSessionCookie, adminAPIPath, true)
	h.clearCookie(w, middleware.AdminCSRFCookie, "/", false)
	h.clearCookie(w, middleware.AdminMFACookie, adminAuthPath, true)
	w.WriteHeader(http.StatusNoContent)
}

// ResetCredentials handles POST /api/v1/admin/users/{id}/reset-credentials
// (super admin): removes another administrator's second factor and ends their
// console sessions, for a lost authenticator.
// @Summary Reset another administrator's two-step verification
// @Description Super admin only. Removes the target administrator's TOTP second factor and ends their console sessions (lost authenticator); they enroll again the next time they open the console.
// @Tags Admin Users
// @Param id path string true "Admin user ID"
// @Success 204 "No Content"
// @Failure 400 {object} apierror.Error "Bad Request"
// @Failure 403 {object} apierror.Error "Forbidden"
// @Failure 404 {object} apierror.Error "Not Found"
// @Security BearerAuth
// @Router /admin/users/{id}/reset-credentials [post]
func (h *AdminConsoleHandler) ResetCredentials(w http.ResponseWriter, r *http.Request) {
	actor := middleware.MustGetAdminUser(r.Context())
	id, err := shared.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		apierror.BadRequest("invalid admin id").WriteJSON(w)
		return
	}
	if id == actor.ID() {
		apierror.BadRequest("use the password endpoint to change your own credentials").WriteJSON(w)
		return
	}
	if err := h.svc.ResetCredentials(r.Context(), actor, id, clientInfo(r)); err != nil {
		if admin.IsAdminNotFound(err) {
			apierror.NotFound("admin user").WriteJSON(w)
			return
		}
		h.logger.Error("admin console reset credentials", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// issueSessionCookies sets the verified console session and CSRF cookies and
// clears the pending-MFA cookie.
func (h *AdminConsoleHandler) issueSessionCookies(w http.ResponseWriter, token string) error {
	csrf, err := middleware.GenerateCSRFToken()
	if err != nil {
		return err
	}
	maxAge := int(admin.SessionTTL.Seconds())
	h.clearCookie(w, middleware.AdminMFACookie, adminAuthPath, true)
	h.setCookie(w, middleware.AdminSessionCookie, token, adminAPIPath, maxAge, true)
	h.setCookie(w, middleware.AdminCSRFCookie, csrf, "/", maxAge, false)
	return nil
}
