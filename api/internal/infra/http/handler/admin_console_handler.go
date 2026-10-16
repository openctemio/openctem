package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

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
	// adminPagePath scopes the readable CSRF copy to the console's pages.
	adminPagePath = "/admin"
)

// AdminConsoleHandler serves platform admin console login (RFC-022).
type AdminConsoleHandler struct {
	svc          *adminconsole.Service
	cookieSecure bool
	logger       *logger.Logger

	// captcha and loginFailures add the same CAPTCHA after repeated failed
	// sign-ins as the tenant /login (counted per client address, under a
	// console-only key).
	captcha       Captcha
	loginFailures LoginFailureCounter
}

// SetLoginGuard wires the CAPTCHA and the failed-sign-in counter on the
// console's /login.
func (h *AdminConsoleHandler) SetLoginGuard(c Captcha, f LoginFailureCounter) {
	h.captcha, h.loginFailures = c, f
}

func consoleFailureKey(ip string) string {
	if ip == "" {
		return ""
	}
	return "console:" + ip
}

// NewAdminConsoleHandler creates the handler. cookieSecure mirrors
// AUTH_COOKIE_SECURE (true in production, behind HTTPS).
func NewAdminConsoleHandler(svc *adminconsole.Service, cookieSecure bool, log *logger.Logger) *AdminConsoleHandler {
	return &AdminConsoleHandler{svc: svc, cookieSecure: cookieSecure, logger: log.With("handler", "admin_console")}
}

// AdminConsoleLoginRequest is the console's own first factor: the account's
// email and password.
type AdminConsoleLoginRequest struct {
	Email        string `json:"email"`
	Password     string `json:"password"`
	CaptchaToken string `json:"captcha_token,omitempty"`
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

// setCookie writes an admin console cookie. admin_session, admin_mfa and
// admin_csrf are HttpOnly (admin_session is forced so a caller can never weaken
// it) and scoped to the console API. The console's pages echo the CSRF token
// in a header, so they read a copy, admin_csrf_ui, scoped to /admin: a
// tenant page's script does not find it in document.cookie. Paths are not a
// boundary inside one origin (a same-origin frame of a console page can read
// it); the console's own origin removes that.
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

// Login handles POST /api/v1/admin/auth/login: the console's own sign-in,
// on the console's origin. It answers which TOTP step follows and sets the
// pending admin_mfa cookie.
// @Summary Sign in to the platform admin console
// @Description The administrator's account email and password (the same account and password policy as everywhere, checked with the same lockout), then the console's own second factor. Independent of any tenant sign-in. A wrong password and an unknown email answer the same 401.
// @Tags Admin Auth
// @Accept json
// @Produce json
// @Param request body AdminConsoleLoginRequest true "Email and password"
// @Success 200 {object} AdminLoginResponse
// @Failure 401 {object} apierror.Error "Wrong email or password, or not an active unlocked platform administrator (one answer)"
// @Failure 403 {object} apierror.Error "CAPTCHA required, or the identity provider sign-in is required"
// @Router /admin/auth/login [post]
func (h *AdminConsoleHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req AdminConsoleLoginRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	ip := getClientIP(r)
	key := consoleFailureKey(ip)
	if captchaNeeded(r.Context(), h.captcha, h.loginFailures, key, h.logger) {
		ok, cerr := h.captcha.Verify(r.Context(), strings.TrimSpace(req.CaptchaToken), ip)
		if cerr != nil || !ok {
			apierror.New(http.StatusForbidden, CodeCaptchaRequired,
				"Complete the security check and try again.").WriteJSON(w)
			return
		}
	}
	res, err := h.svc.Start(r.Context(), req.Email, req.Password, clientInfo(r))
	if err != nil {
		switch {
		// A wrong password, an unknown email, a tenant account that is not an
		// administrator and an inactive or locked one all answer the same, so
		// the sign-in is not an oracle for a tenant password.
		case errors.Is(err, admin.ErrInvalidCredentials), errors.Is(err, admin.ErrNotPlatformAdmin), errors.Is(err, admin.ErrAccountLocked):
			if h.loginFailures != nil && key != "" {
				if rerr := h.loginFailures.Record(r.Context(), key); rerr != nil {
					h.logger.Warn("record failed console sign-in", "error", rerr)
				}
			}
			apierror.Unauthorized("Wrong email or password").WriteJSON(w)
		case errors.Is(err, admin.ErrIdPSignInRequired):
			apierror.New(http.StatusForbidden, codeIdPSignInRequired,
				"Sign in to the admin console with the identity provider").WriteJSON(w)
		default:
			h.logger.Error("admin console sign-in", "error", err)
			apierror.InternalError(err).WriteJSON(w)
		}
		return
	}
	// The failure counter is not cleared on success: a success must not reset
	// the count an attacker is building against the address (the entries decay
	// with LoginFailureWindow).
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
			errors.Is(err, password.ErrPasswordNoSpecial), errors.Is(err, password.ErrPasswordCommon),
			errors.Is(err, password.ErrPasswordTooLong):
			apierror.BadRequest("The new password does not meet the password policy: " + sanitizeLogField(errors.Unwrap(err).Error())).WriteJSON(w)
		default:
			h.logger.Error("admin change password", "error", sanitizeLogField(err.Error()))
			apierror.InternalError(err).WriteJSON(w)
		}
		return
	}
	h.clearCookie(w, middleware.AdminSessionCookie, adminAPIPath, true)
	h.clearCSRFCookies(w)
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
// @Description Ends the caller's console session and clears the admin cookies. No other session is touched.
// @Tags Admin Auth
// @Success 204 "No Content"
// @Router /admin/auth/logout [post]
func (h *AdminConsoleHandler) Logout(w http.ResponseWriter, r *http.Request) {
	session := ""
	if c, err := r.Cookie(middleware.AdminSessionCookie); err == nil {
		session = c.Value
	}
	if err := h.svc.Logout(r.Context(), session, clientInfo(r)); err != nil {
		h.logger.Warn("admin console logout", "error", err)
	}
	h.clearCookie(w, middleware.AdminSessionCookie, adminAPIPath, true)
	h.clearCSRFCookies(w)
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
	h.setCookie(w, middleware.AdminCSRFCookie, csrf, adminAPIPath, maxAge, true)
	h.setCookie(w, middleware.AdminCSRFPageCookie, csrf, adminPagePath, maxAge, false)
	// The older readable copy at "/", from before the console's cookies were
	// scoped: never left behind for tenant pages to read.
	h.clearCookie(w, middleware.AdminCSRFCookie, "/", false)
	return nil
}

// clearCSRFCookies removes both copies of the console's CSRF token, and the
// older one at "/".
func (h *AdminConsoleHandler) clearCSRFCookies(w http.ResponseWriter) {
	h.clearCookie(w, middleware.AdminCSRFCookie, adminAPIPath, true)
	h.clearCookie(w, middleware.AdminCSRFPageCookie, adminPagePath, false)
	h.clearCookie(w, middleware.AdminCSRFCookie, "/", false)
}
