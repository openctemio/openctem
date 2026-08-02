package handler

import (
	"encoding/json"
	"net/http"

	"github.com/openctemio/api/internal/config"
	"github.com/openctemio/api/pkg/logger"
)

// AuthProvidersHandler exposes a public, tenant-agnostic snapshot of which
// social-login providers (and the platform-wide Entra SSO env fallback) are
// actually configured on this server. The login page uses it to avoid
// rendering dead buttons for providers that would 404 on click.
//
// Social OAuth providers are global (env-configured), so this endpoint needs
// no auth and no tenant context. It reports booleans only — never client IDs,
// secrets, or any other credential material.
type AuthProvidersHandler struct {
	oauthConfig config.OAuthConfig
	entraSSO    config.EntraSSOConfig
	// oauthRoutesLive reports whether /auth/oauth/{provider}/authorize and
	// /auth/oauth/{provider}/callback are actually registered on this server.
	// Credentials alone are not enough — if the OAuth handler is not wired into
	// the composition root those routes 404, and advertising a provider anyway
	// makes the login page render a button that dead-ends. Callers MUST pass
	// the same condition the router uses to gate those routes.
	oauthRoutesLive bool
	logger          *logger.Logger
}

// NewAuthProvidersHandler creates a new AuthProvidersHandler.
//
// oauthRoutesLive must be the same condition that gates registration of the
// /auth/oauth/* routes, so this endpoint can never advertise a provider whose
// routes do not exist.
func NewAuthProvidersHandler(
	oauthConfig config.OAuthConfig,
	entraSSO config.EntraSSOConfig,
	oauthRoutesLive bool,
	log *logger.Logger,
) *AuthProvidersHandler {
	return &AuthProvidersHandler{
		oauthConfig:     oauthConfig,
		entraSSO:        entraSSO,
		oauthRoutesLive: oauthRoutesLive,
		logger:          log.With("handler", "auth_providers"),
	}
}

// SocialProviders reports which social OAuth buttons should be shown on the
// login page. A field is true only when that provider's OAUTH_<PROVIDER>_*
// credentials (enabled + client_id + secret) are configured AND the
// /auth/oauth/* routes are live on this server.
type SocialProviders struct {
	Microsoft bool `json:"microsoft"`
	Google    bool `json:"google"`
	GitHub    bool `json:"github"`
}

// AuthProvidersResponse is the public login-capability snapshot.
type AuthProvidersResponse struct {
	Social SocialProviders `json:"social"`
	// SSOEnvEntraEnabled reports whether the platform-wide (env-based)
	// Microsoft Entra ID SSO fallback is usable (SSO_ENTRA_* configured).
	SSOEnvEntraEnabled bool `json:"sso_env_entra_enabled"`
}

// GetProviders returns which login providers are configured on this server.
// @Summary      Public login-provider capability snapshot
// @Description  Reports which social OAuth providers (and the Entra SSO env fallback) are configured, so the UI can hide dead login buttons. Booleans only — no secrets.
// @Tags         OAuth
// @Produce      json
// @Success      200  {object}  AuthProvidersResponse
// @Router       /auth/providers [get]
func (h *AuthProvidersHandler) GetProviders(w http.ResponseWriter, _ *http.Request) {
	resp := AuthProvidersResponse{
		Social: SocialProviders{
			Microsoft: h.oauthRoutesLive && h.oauthConfig.Microsoft.IsConfigured(),
			Google:    h.oauthRoutesLive && h.oauthConfig.Google.IsConfigured(),
			GitHub:    h.oauthRoutesLive && h.oauthConfig.GitHub.IsConfigured(),
		},
		SSOEnvEntraEnabled: h.entraSSO.IsConfigured(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		h.logger.Error("failed to encode auth providers response", "error", err)
	}
}
