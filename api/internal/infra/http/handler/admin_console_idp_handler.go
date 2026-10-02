package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/app/adminconsole"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Platform identity provider sign-in and configuration, and break-glass
// management (RFC-022 revision 4).

// AdminIdPCookie carries the state of an in-flight IdP sign-in. HttpOnly and
// scoped to the console auth endpoints; the callback must present the same
// state, so a sign-in cannot be completed from another browser.
const AdminIdPCookie = "admin_idp"

const codeIdPSignInRequired apierror.Code = "IDP_SIGN_IN_REQUIRED"

// AdminIdPInfoResponse is what the console sign-in page may know.
type AdminIdPInfoResponse struct {
	Enabled     bool   `json:"enabled"`
	DisplayName string `json:"display_name,omitempty"`
}

// AdminIdPStartResponse sends the browser to the IdP.
type AdminIdPStartResponse struct {
	AuthorizationURL string `json:"authorization_url"`
}

// AdminIdPCallbackRequest is what the IdP redirected back with.
type AdminIdPCallbackRequest struct {
	Code  string `json:"code"`
	State string `json:"state"`
}

// AdminIdPCallbackResponse: status signed_in (session cookies set), or
// mfa_required / mfa_enrollment_required (continue with POST /auth/mfa).
type AdminIdPCallbackResponse struct {
	Status     string            `json:"status"`
	OTPAuthURI string            `json:"otpauth_uri,omitempty"`
	Secret     string            `json:"secret,omitempty"`
	Admin      *ValidateResponse `json:"admin,omitempty"`
}

// PlatformIdPRequest configures the administrators' identity provider. An
// empty client_secret on update keeps the stored one.
type PlatformIdPRequest struct {
	Enabled          bool     `json:"enabled"`
	DisplayName      string   `json:"display_name"`
	Issuer           string   `json:"issuer"`
	ClientID         string   `json:"client_id"`
	ClientSecret     string   `json:"client_secret,omitempty"`
	RedirectURI      string   `json:"redirect_uri"`
	Scopes           []string `json:"scopes,omitempty"`
	RequireIdP       bool     `json:"require_idp"`
	TrustedACRValues []string `json:"trusted_acr_values,omitempty"`
	TrustedAMRValues []string `json:"trusted_amr_values,omitempty"`
}

// PlatformIdPResponse is the configuration without the secret.
type PlatformIdPResponse struct {
	Configured              bool     `json:"configured"`
	Enabled                 bool     `json:"enabled"`
	DisplayName             string   `json:"display_name,omitempty"`
	Issuer                  string   `json:"issuer,omitempty"`
	ClientID                string   `json:"client_id,omitempty"`
	HasClientSecret         bool     `json:"has_client_secret"`
	RedirectURI             string   `json:"redirect_uri,omitempty"`
	Scopes                  []string `json:"scopes,omitempty"`
	RequireIdP              bool     `json:"require_idp"`
	TrustedACRValues        []string `json:"trusted_acr_values"`
	TrustedAMRValues        []string `json:"trusted_amr_values"`
	AuthorizationEndpoint   string   `json:"authorization_endpoint,omitempty"`
	TokenEndpoint           string   `json:"token_endpoint,omitempty"`
	JWKSURI                 string   `json:"jwks_uri,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	UpdatedAt               string   `json:"updated_at,omitempty"`
}

func toPlatformIdPResponse(p *admin.PlatformIdP) PlatformIdPResponse {
	return PlatformIdPResponse{
		Configured:              true,
		Enabled:                 p.Enabled,
		DisplayName:             p.DisplayName,
		Issuer:                  p.Issuer,
		ClientID:                p.ClientID,
		HasClientSecret:         p.ClientSecretEncrypted != "",
		RedirectURI:             p.RedirectURI,
		Scopes:                  p.Scopes,
		RequireIdP:              p.RequireIdP,
		TrustedACRValues:        nonNil(p.TrustedACRValues),
		TrustedAMRValues:        nonNil(p.TrustedAMRValues),
		AuthorizationEndpoint:   p.AuthorizationEndpoint,
		TokenEndpoint:           p.TokenEndpoint,
		JWKSURI:                 p.JWKSURI,
		TokenEndpointAuthMethod: p.TokenEndpointAuthMethod,
		UpdatedAt:               p.UpdatedAt.UTC().Format(time.RFC3339),
	}
}

func nonNil(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

// IdPInfo handles GET /api/v1/admin/auth/idp (public).
// @Summary Administrators' identity provider (sign-in page)
// @Description Whether the console sign-in page offers the platform identity provider, and its display name. Nothing else about the configuration is public.
// @Tags Admin Auth
// @Produce json
// @Success 200 {object} AdminIdPInfoResponse
// @Router /admin/auth/idp [get]
func (h *AdminConsoleHandler) IdPInfo(w http.ResponseWriter, r *http.Request) {
	info := h.svc.PublicIdP(r.Context())
	writeJSON(w, http.StatusOK, AdminIdPInfoResponse{Enabled: info.Enabled, DisplayName: info.DisplayName})
}

// IdPStart handles POST /api/v1/admin/auth/idp/start.
// @Summary Start an identity-provider sign-in to the admin console
// @Description Begins an OIDC authorization-code sign-in with PKCE and a nonce. Returns the URL to send the browser to and sets the HttpOnly admin_idp cookie that the callback must present.
// @Tags Admin Auth
// @Produce json
// @Success 200 {object} AdminIdPStartResponse
// @Failure 404 {object} apierror.Error "No identity provider is enabled for administrators"
// @Router /admin/auth/idp/start [post]
func (h *AdminConsoleHandler) IdPStart(w http.ResponseWriter, r *http.Request) {
	st, err := h.svc.StartIdPLogin(r.Context())
	if err != nil {
		if errors.Is(err, admin.ErrPlatformIdPNotConfigured) {
			apierror.NotFound("identity provider").WriteJSON(w)
			return
		}
		h.logger.Error("admin idp start", "error", sanitizeLogField(err.Error()))
		apierror.InternalServerError("single sign-on is unavailable").WriteJSON(w)
		return
	}
	h.setCookie(w, AdminIdPCookie, st.State, adminAuthPath, int(admin.IdPLoginStateTTL.Seconds()), true)
	writeJSON(w, http.StatusOK, AdminIdPStartResponse{AuthorizationURL: st.AuthorizationURL})
}

// IdPCallback handles POST /api/v1/admin/auth/idp/callback.
// @Summary Finish an identity-provider sign-in to the admin console
// @Description Exchanges the authorization code, verifies the id_token and matches it to an existing administrator (no administrator is created). Unless the IdP's MFA is trusted by configuration, the console TOTP step follows (POST /admin/auth/mfa). Any failure returns the same generic error; the reason is in the admin audit log.
// @Tags Admin Auth
// @Accept json
// @Produce json
// @Param request body AdminIdPCallbackRequest true "Code and state from the IdP redirect"
// @Success 200 {object} AdminIdPCallbackResponse
// @Failure 400 {object} apierror.Error "Bad Request"
// @Failure 401 {object} apierror.Error "Single sign-on failed"
// @Router /admin/auth/idp/callback [post]
func (h *AdminConsoleHandler) IdPCallback(w http.ResponseWriter, r *http.Request) {
	var req AdminIdPCallbackRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	cookieState := ""
	if c, err := r.Cookie(AdminIdPCookie); err == nil {
		cookieState = c.Value
	}
	// The state is single use whatever the outcome.
	h.clearCookie(w, AdminIdPCookie, adminAuthPath, true)

	res, err := h.svc.CompleteIdPLogin(r.Context(), cookieState, req.State, req.Code, clientInfo(r))
	if err != nil {
		if !errors.Is(err, admin.ErrIdPSignInFailed) {
			h.logger.Error("admin idp callback", "error", sanitizeLogField(err.Error()))
		}
		apierror.Unauthorized("Single sign-on failed").WriteJSON(w)
		return
	}
	a := res.Admin
	who := &ValidateResponse{
		ID: a.ID().String(), Email: a.Email(), Name: a.Name(), Role: string(a.Role()),
		AuthMethod: admin.AuthMethodIdP, IsBreakGlass: a.IsBreakGlass(),
	}
	if res.Status == adminconsole.StatusSignedIn {
		if err := h.issueSessionCookies(w, res.SessionToken); err != nil {
			apierror.InternalError(err).WriteJSON(w)
			return
		}
		writeJSON(w, http.StatusOK, AdminIdPCallbackResponse{Status: string(res.Status), Admin: who})
		return
	}
	h.setCookie(w, middleware.AdminMFACookie, res.Second.PendingToken, adminAuthPath, int(admin.PendingMFATTL.Seconds()), true)
	writeJSON(w, http.StatusOK, AdminIdPCallbackResponse{
		Status: string(res.Status), OTPAuthURI: res.Second.OTPAuthURI, Secret: res.Second.Secret,
	})
}

// GetPlatformIdP handles GET /api/v1/admin/platform-idp (super admin).
// @Summary Get the administrators' identity provider
// @Description The platform-level OIDC provider administrators may sign in with. The client secret is never returned (has_client_secret only).
// @Tags Admin Platform IdP
// @Produce json
// @Success 200 {object} PlatformIdPResponse
// @Security BearerAuth
// @Router /admin/platform-idp [get]
func (h *AdminConsoleHandler) GetPlatformIdP(w http.ResponseWriter, r *http.Request) {
	p, err := h.svc.GetPlatformIdP(r.Context())
	if err != nil {
		if errors.Is(err, admin.ErrPlatformIdPNotConfigured) {
			writeJSON(w, http.StatusOK, PlatformIdPResponse{TrustedACRValues: []string{}, TrustedAMRValues: []string{}})
			return
		}
		h.logger.Error("get platform idp", "error", sanitizeLogField(err.Error()))
		apierror.InternalError(err).WriteJSON(w)
		return
	}
	writeJSON(w, http.StatusOK, toPlatformIdPResponse(p))
}

// PutPlatformIdP handles PUT /api/v1/admin/platform-idp (super admin).
// @Summary Configure the administrators' identity provider
// @Description Creates or updates the platform-level OIDC provider. The issuer's discovery document is fetched (https only, SSRF-guarded) and must report the same issuer. The client secret is stored encrypted; leave it empty to keep the stored one. Changing the issuer removes every administrator's IdP binding. require_idp needs an active break-glass super admin. Audited.
// @Tags Admin Platform IdP
// @Accept json
// @Produce json
// @Param request body PlatformIdPRequest true "Configuration"
// @Success 200 {object} PlatformIdPResponse
// @Failure 400 {object} apierror.Error "Invalid configuration or discovery failed"
// @Failure 409 {object} apierror.Error "require_idp without a break-glass super admin"
// @Security BearerAuth
// @Router /admin/platform-idp [put]
func (h *AdminConsoleHandler) PutPlatformIdP(w http.ResponseWriter, r *http.Request) {
	actor := middleware.MustGetAdminUser(r.Context())
	var req PlatformIdPRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384)).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	p, err := h.svc.SavePlatformIdP(r.Context(), actor, adminconsole.PlatformIdPInput{
		Enabled: req.Enabled, DisplayName: req.DisplayName, Issuer: req.Issuer, ClientID: req.ClientID,
		ClientSecret: req.ClientSecret, RedirectURI: req.RedirectURI, Scopes: req.Scopes,
		RequireIdP: req.RequireIdP, TrustedACRValues: req.TrustedACRValues, TrustedAMRValues: req.TrustedAMRValues,
	}, clientInfo(r))
	if err != nil {
		switch {
		case shared.IsValidation(err):
			apierror.BadRequest(sanitizeLogField(validationMessage(err))).WriteJSON(w)
		case errors.Is(err, admin.ErrLastLocalAdmin):
			apierror.Conflict("Requiring the identity provider needs at least one active break-glass super admin, so the console stays reachable when the IdP is down.").WriteJSON(w)
		default:
			h.logger.Error("save platform idp", "error", sanitizeLogField(err.Error()))
			apierror.InternalError(err).WriteJSON(w)
		}
		return
	}
	writeJSON(w, http.StatusOK, toPlatformIdPResponse(p))
}

// DeletePlatformIdP handles DELETE /api/v1/admin/platform-idp (super admin).
// @Summary Remove the administrators' identity provider
// @Description Removes the configuration (and "require IdP" with it). Administrators sign in with their password again. Audited.
// @Tags Admin Platform IdP
// @Success 204 "No Content"
// @Failure 404 {object} apierror.Error "Not configured"
// @Security BearerAuth
// @Router /admin/platform-idp [delete]
func (h *AdminConsoleHandler) DeletePlatformIdP(w http.ResponseWriter, r *http.Request) {
	if err := h.svc.DeletePlatformIdP(r.Context(), middleware.MustGetAdminUser(r.Context()), clientInfo(r)); err != nil {
		if errors.Is(err, admin.ErrPlatformIdPNotConfigured) {
			apierror.NotFound("identity provider").WriteJSON(w)
			return
		}
		h.logger.Error("delete platform idp", "error", sanitizeLogField(err.Error()))
		apierror.InternalError(err).WriteJSON(w)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ConfirmBreakGlassTest handles POST /api/v1/admin/users/{id}/break-glass-test.
// @Summary Confirm a break-glass sign-in was a test
// @Description Super admin only, and not the break-glass account itself: records the account's last sign-in as its periodic test.
// @Tags Admin Users
// @Produce json
// @Param id path string true "Admin user ID"
// @Success 200 {object} AdminResponse
// @Failure 400 {object} apierror.Error "Not break-glass, never signed in, or your own account"
// @Failure 404 {object} apierror.Error "Not Found"
// @Security BearerAuth
// @Router /admin/users/{id}/break-glass-test [post]
func (h *AdminConsoleHandler) ConfirmBreakGlassTest(w http.ResponseWriter, r *http.Request) {
	id, err := shared.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		apierror.BadRequest("invalid admin id").WriteJSON(w)
		return
	}
	a, err := h.svc.ConfirmBreakGlassTest(r.Context(), middleware.MustGetAdminUser(r.Context()), id, clientInfo(r))
	if err != nil {
		switch {
		case admin.IsAdminNotFound(err):
			apierror.NotFound("Admin").WriteJSON(w)
		case shared.IsValidation(err):
			apierror.BadRequest(sanitizeLogField(validationMessage(err))).WriteJSON(w)
		default:
			h.logger.Error("confirm break-glass test", "error", sanitizeLogField(err.Error()))
			apierror.InternalError(err).WriteJSON(w)
		}
		return
	}
	writeJSON(w, http.StatusOK, toAdminResponse(a))
}

// UnbindIdP handles DELETE /api/v1/admin/users/{id}/idp-binding.
// @Summary Remove an administrator's identity-provider binding
// @Description Super admin only. The administrator is bound again, by verified email, on their next IdP sign-in. Ends their console sessions. Audited.
// @Tags Admin Users
// @Param id path string true "Admin user ID"
// @Success 204 "No Content"
// @Failure 404 {object} apierror.Error "Not Found"
// @Security BearerAuth
// @Router /admin/users/{id}/idp-binding [delete]
func (h *AdminConsoleHandler) UnbindIdP(w http.ResponseWriter, r *http.Request) {
	id, err := shared.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		apierror.BadRequest("invalid admin id").WriteJSON(w)
		return
	}
	if err := h.svc.UnbindIdP(r.Context(), middleware.MustGetAdminUser(r.Context()), id, clientInfo(r)); err != nil {
		if admin.IsAdminNotFound(err) {
			apierror.NotFound("Admin").WriteJSON(w)
			return
		}
		h.logger.Error("unbind admin idp", "error", sanitizeLogField(err.Error()))
		apierror.InternalError(err).WriteJSON(w)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// validationMessage returns the domain error's own message (without the
// wrapped sentinel prefix) for a 400 response.
func validationMessage(err error) string {
	var de *shared.DomainError
	if errors.As(err, &de) {
		return de.Message
	}
	return err.Error()
}
