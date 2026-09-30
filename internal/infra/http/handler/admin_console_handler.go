package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/api/internal/app/adminconsole"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/admin"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
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
	svc          *adminconsole.Service
	cookieSecure bool
	logger       *logger.Logger
}

// NewAdminConsoleHandler creates the handler. cookieSecure mirrors
// AUTH_COOKIE_SECURE (true in production, behind HTTPS).
func NewAdminConsoleHandler(svc *adminconsole.Service, cookieSecure bool, log *logger.Logger) *AdminConsoleHandler {
	return &AdminConsoleHandler{svc: svc, cookieSecure: cookieSecure, logger: log.With("handler", "admin_console")}
}

// AdminLoginRequest is the password step.
type AdminLoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
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

// AdminPasswordRequest sets or changes the caller's own console password.
type AdminPasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

func clientInfo(r *http.Request) adminconsole.ClientInfo {
	return adminconsole.ClientInfo{IP: middleware.ClientIP(r), UserAgent: r.UserAgent()}
}

func (h *AdminConsoleHandler) setCookie(w http.ResponseWriter, name, value, path string, maxAge int, httpOnly bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     path,
		MaxAge:   maxAge,
		HttpOnly: httpOnly,
		Secure:   h.cookieSecure,
		SameSite: http.SameSiteStrictMode,
	})
}

func (h *AdminConsoleHandler) clearCookie(w http.ResponseWriter, name, path string, httpOnly bool) {
	h.setCookie(w, name, "", path, -1, httpOnly)
}

// Login handles POST /api/v1/admin/auth/login (password step).
// @Summary Admin console login (password step)
// @Description First step of platform admin console login (RFC-022). Sets a short-lived admin_mfa cookie; the response says whether to enter a TOTP code or enroll an authenticator first. Every failure is the same generic 401.
// @Tags Admin Auth
// @Accept json
// @Produce json
// @Param request body AdminLoginRequest true "Credentials"
// @Success 200 {object} AdminLoginResponse
// @Failure 400 {object} apierror.Error "Bad Request"
// @Failure 401 {object} apierror.Error "Invalid email or password"
// @Router /admin/auth/login [post]
func (h *AdminConsoleHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req AdminLoginRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil || req.Email == "" || req.Password == "" {
		apierror.BadRequest("email and password are required").WriteJSON(w)
		return
	}
	res, err := h.svc.Login(r.Context(), req.Email, req.Password, clientInfo(r))
	if err != nil {
		if errors.Is(err, admin.ErrInvalidCredentials) {
			apierror.Unauthorized("Invalid email or password").WriteJSON(w)
			return
		}
		h.logger.Error("admin console login", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}
	h.setCookie(w, middleware.AdminMFACookie, res.PendingToken, adminAuthPath, int(admin.PendingMFATTL.Seconds()), true)
	writeJSON(w, http.StatusOK, AdminLoginResponse{Status: string(res.Status), OTPAuthURI: res.OTPAuthURI, Secret: res.Secret})
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
		h.logger.Error("admin console mfa", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}
	csrf, err := middleware.GenerateCSRFToken()
	if err != nil {
		apierror.InternalError(err).WriteJSON(w)
		return
	}
	maxAge := int(admin.SessionTTL.Seconds())
	h.clearCookie(w, middleware.AdminMFACookie, adminAuthPath, true)
	h.setCookie(w, middleware.AdminSessionCookie, token, adminAPIPath, maxAge, true)
	h.setCookie(w, middleware.AdminCSRFCookie, csrf, "/", maxAge, false)
	writeJSON(w, http.StatusOK, ValidateResponse{
		ID: a.ID().String(), Email: a.Email(), Name: a.Name(), Role: string(a.Role()),
	})
}

// Logout handles POST /api/v1/admin/auth/logout.
// @Summary Admin console logout
// @Description Ends the caller's console session and clears the admin cookies.
// @Tags Admin Auth
// @Success 204 "No Content"
// @Router /admin/auth/logout [post]
func (h *AdminConsoleHandler) Logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(middleware.AdminSessionCookie); err == nil {
		if err := h.svc.Logout(r.Context(), c.Value, clientInfo(r)); err != nil {
			h.logger.Warn("admin console logout", "error", err)
		}
	}
	h.clearCookie(w, middleware.AdminSessionCookie, adminAPIPath, true)
	h.clearCookie(w, middleware.AdminCSRFCookie, "/", false)
	h.clearCookie(w, middleware.AdminMFACookie, adminAuthPath, true)
	w.WriteHeader(http.StatusNoContent)
}

// SetPassword handles POST /api/v1/admin/auth/password for the caller's own
// password. With an API key the current password is not required (bootstrap
// path); with a console session it is.
// @Summary Set own admin console password
// @Description Sets or changes the caller's console password. With an API key the current password is not required (bootstrap path); with a console session it is, and every session of the admin is ended.
// @Tags Admin Auth
// @Accept json
// @Param request body AdminPasswordRequest true "Passwords"
// @Success 204 "No Content"
// @Failure 400 {object} apierror.Error "Bad Request"
// @Failure 401 {object} apierror.Error "Unauthorized"
// @Security BearerAuth
// @Router /admin/auth/password [post]
func (h *AdminConsoleHandler) SetPassword(w http.ResponseWriter, r *http.Request) {
	a := middleware.MustGetAdminUser(r.Context())
	var req AdminPasswordRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	requireCurrent := middleware.GetAdminAuthMethod(r.Context()) != middleware.AdminAuthMethodAPIKey
	err := h.svc.SetPassword(r.Context(), a, req.CurrentPassword, req.NewPassword, requireCurrent, clientInfo(r))
	switch {
	case err == nil:
		if requireCurrent {
			// The password change ended every session, including this one.
			h.clearCookie(w, middleware.AdminSessionCookie, adminAPIPath, true)
			h.clearCookie(w, middleware.AdminCSRFCookie, "/", false)
		}
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, admin.ErrWeakPassword):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	case errors.Is(err, admin.ErrCurrentPassword):
		apierror.Unauthorized("Current password is incorrect").WriteJSON(w)
	default:
		h.logger.Error("admin console set password", "error", err)
		apierror.InternalError(err).WriteJSON(w)
	}
}

// ResetCredentials handles POST /api/v1/admin/users/{id}/reset-credentials
// (super admin): removes another admin's password and MFA and ends their
// sessions, for a lost authenticator.
// @Summary Reset another admin's console credentials
// @Description Super admin only. Removes the target admin's password and MFA and ends their sessions (lost authenticator). The target sets a new password with their API key and re-enrolls on next login.
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
