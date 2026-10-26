package handler

// Platform console: Settings > Social login. Google, GitHub and Microsoft
// sign-in (client ID, client secret, scopes, on/off) per provider, replacing
// OAUTH_<PROVIDER>_* and a restart. Any administrator reads; the secret is
// never returned. A change needs super_admin, a fresh confirmation and a
// reason; the service writes the critical admin audit row (never the
// secret) and tells every administrator.

import (
	"errors"
	"net/http"

	"github.com/openctemio/openctem/api/internal/app/platformsociallogin"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	signupdom "github.com/openctemio/openctem/api/pkg/domain/signup"
)

// SocialProviderResponse is one provider without its secret.
type SocialProviderResponse struct {
	Provider string `json:"provider"`
	// Enabled: the provider is offered on the sign-in page.
	Enabled bool `json:"enabled"`
	// RedirectURI is the exact callback address to register at the provider.
	RedirectURI   string   `json:"redirect_uri"`
	ClientID      string   `json:"client_id"`
	SecretSet     bool     `json:"secret_set"`
	Scopes        []string `json:"scopes"`
	DefaultScopes []string `json:"default_scopes"`
	// Source: none, console or environment.
	Source              string `json:"source"`
	LockedByEnvironment bool   `json:"locked_by_environment"`
	// EnvVar names the variable that locks the provider.
	EnvVar string `json:"env_var"`
	// Active: sign-in with the provider is offered right now.
	Active bool `json:"active"`
	// Undecryptable: the stored secret does not decrypt; the provider is off
	// until the secret is replaced.
	Undecryptable bool `json:"undecryptable"`
}

// SocialLoginSettingsResponse is the Social login page.
type SocialLoginSettingsResponse struct {
	Providers []SocialProviderResponse `json:"providers"`
	// MasterEnabled is OAUTH_ENABLED on the server; false switches every
	// provider off.
	MasterEnabled bool `json:"master_enabled"`
	// JavaScriptOrigin is the authorized JavaScript origin to register.
	JavaScriptOrigin string `json:"javascript_origin"`
	// SignupAccounts is who may create an account by public sign-up (closed,
	// domain or open): who a social sign-in can admit besides existing
	// accounts and invited people.
	SignupAccounts string `json:"signup_accounts"`
	Version        int    `json:"version"`
	SettingChange
}

// UpdateSocialLoginRequest changes one provider.
type UpdateSocialLoginRequest struct {
	Enabled  bool   `json:"enabled"`
	ClientID string `json:"client_id"`
	// Secret: omit to keep the stored one, "" to remove it.
	Secret *string `json:"secret,omitempty"`
	// Scopes: empty uses the provider's defaults.
	Scopes  []string `json:"scopes"`
	Reason  string   `json:"reason"`
	Version int      `json:"version"`
}

// SocialLoginCheckRequest checks a client before or after saving it.
type SocialLoginCheckRequest struct {
	// ClientID and Secret to check; empty uses the ones in force.
	ClientID string `json:"client_id,omitempty"`
	Secret   string `json:"secret,omitempty"`
}

// SocialLoginCheckResponse is the outcome of a check.
type SocialLoginCheckResponse struct {
	// Result: valid, invalid, redirect_mismatch, unreachable or unknown.
	Result string `json:"result"`
}

func (h *AdminPlatformSettingsHandler) socialLoginResponse(r *http.Request, s platformsociallogin.Settings) SocialLoginSettingsResponse {
	out := SocialLoginSettingsResponse{
		Providers: make([]SocialProviderResponse, 0, len(s.Providers)), MasterEnabled: s.MasterEnabled,
		JavaScriptOrigin: s.JavaScriptOrigin, Version: s.Version,
		SignupAccounts: string(signupdom.AccountsClosed),
		SettingChange:  h.change(r.Context(), s.UpdatedAt, s.UpdatedBy),
	}
	if h.Signup != nil {
		out.SignupAccounts = string(h.Signup.Current(r.Context()).AccountSignup())
	}
	for _, p := range s.Providers {
		scopes := p.Scopes
		if scopes == nil {
			scopes = []string{}
		}
		out.Providers = append(out.Providers, SocialProviderResponse{
			Provider: p.Provider, Enabled: p.Enabled, RedirectURI: p.RedirectURI, ClientID: p.ClientID, SecretSet: p.SecretSet, Scopes: scopes,
			DefaultScopes: p.DefaultScopes, Source: p.Source, LockedByEnvironment: p.LockedByEnvironment,
			EnvVar: p.EnvVar, Active: p.Active, Undecryptable: p.Undecryptable,
		})
	}
	return out
}

// GetSocialLogin returns the social login providers without any secret.
// @Summary      Get the social login providers
// @Description  Per provider (Google, GitHub, Microsoft): on or off, client ID, whether a client secret is set (never the secret), scopes, where the values come from, the redirect URI and JavaScript origin to register at the provider, and who last changed them. Any administrator.
// @Tags         Admin System
// @Produce      json
// @Success      200  {object}  SocialLoginSettingsResponse
// @Security     AdminAuth
// @Router       /admin/settings/social-login [get]
func (h *AdminPlatformSettingsHandler) GetSocialLogin(w http.ResponseWriter, r *http.Request) {
	s, err := h.SocialLogin.Get(r.Context())
	if err != nil {
		h.writeSettingError(w, "social login", err)
		return
	}
	writeJSON(w, http.StatusOK, h.socialLoginResponse(r, s))
}

// UpdateSocialLogin changes one provider.
// @Summary      Change a social login provider
// @Description  Super admin with a fresh confirmation and a reason. The client secret is encrypted at rest and never returned; a provider is turned on only with a client ID and a client secret. Refused (409 SETTING_LOCKED_BY_ENVIRONMENT) while OAUTH_<PROVIDER>_CLIENT_SECRET is set on the server. Applies without a restart; audited critical, every administrator is told.
// @Tags         Admin System
// @Accept       json
// @Produce      json
// @Param        provider path      string                    true  "google, github or microsoft"
// @Param        request  body      UpdateSocialLoginRequest  true  "Provider"
// @Success      200  {object}  SocialLoginSettingsResponse
// @Failure      400  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Security     AdminAuth
// @Router       /admin/settings/social-login/{provider} [put]
func (h *AdminPlatformSettingsHandler) UpdateSocialLogin(w http.ResponseWriter, r *http.Request) {
	actor := requireActor(w, r)
	if actor == nil {
		return
	}
	var req UpdateSocialLoginRequest
	if !decodeSetting(w, r, &req) {
		return
	}
	s, err := h.SocialLogin.Update(r.Context(), actor, r.PathValue("provider"), platformsociallogin.Input{
		Enabled: req.Enabled, ClientID: req.ClientID, Secret: req.Secret, Scopes: req.Scopes, Reason: req.Reason,
	}, req.Version, middleware.ClientIP(r), r.UserAgent())
	if err != nil {
		h.writeSettingError(w, "social login", err)
		return
	}
	writeJSON(w, http.StatusOK, h.socialLoginResponse(r, s))
}

// CheckSocialLogin asks the provider whether it accepts the client.
// @Summary      Check a social login client
// @Description  Asks the provider's token endpoint (a fixed address, through the SSRF-safe client) whether it accepts the client ID and secret given, or the ones in force, with a code that cannot be valid. Nothing is stored or logged and the secret is never returned. Super admin.
// @Tags         Admin System
// @Accept       json
// @Produce      json
// @Param        provider path      string                   true  "google, github or microsoft"
// @Param        request  body      SocialLoginCheckRequest  true  "Client"
// @Success      200  {object}  SocialLoginCheckResponse
// @Failure      409  {object}  apierror.Error
// @Security     AdminAuth
// @Router       /admin/settings/social-login/{provider}/test [post]
func (h *AdminPlatformSettingsHandler) CheckSocialLogin(w http.ResponseWriter, r *http.Request) {
	var req SocialLoginCheckRequest
	if !decodeSetting(w, r, &req) {
		return
	}
	res, err := h.SocialLogin.Check(r.Context(), r.PathValue("provider"), req.ClientID, req.Secret)
	if errors.Is(err, platformsociallogin.ErrNoSecret) {
		apierror.New(http.StatusConflict, CodeSettingNotConfigured, "No client ID and secret are set; enter them to check them").WriteJSON(w)
		return
	}
	if err != nil {
		h.writeSettingError(w, "social login", err)
		return
	}
	writeJSON(w, http.StatusOK, SocialLoginCheckResponse{Result: string(res)})
}
