package handler

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/openctemio/api/internal/config"
	"github.com/openctemio/api/pkg/logger"
)

// AuthHandler handles authentication requests.
type AuthHandler struct {
	keycloakCfg *config.KeycloakConfig
	logger      *logger.Logger
}

// NewAuthHandler creates a new AuthHandler.
func NewAuthHandler(keycloakCfg *config.KeycloakConfig, log *logger.Logger) *AuthHandler {
	return &AuthHandler{
		keycloakCfg: keycloakCfg,
		logger:      log,
	}
}

// KeycloakInfoResponse is the response body for Keycloak info.
type KeycloakInfoResponse struct {
	AuthURL     string `json:"auth_url"`
	TokenURL    string `json:"token_url"`
	UserInfoURL string `json:"userinfo_url"`
	LogoutURL   string `json:"logout_url"`
	JWKSURL     string `json:"jwks_url"`
	Realm       string `json:"realm"`
	Issuer      string `json:"issuer"`
}

// Info returns Keycloak configuration info.
//
// Served at GET /auth/info, but only in the OIDC branch of registerAuthRoutes
// (routes/auth.go) — LocalAuthHandler.Info serves the same path in the local
// branch and the two are mutually exclusive at runtime. Since the spec is
// generated, both handlers cannot annotate the one path: LocalAuthHandler
// carries the @Router and this one deliberately does not. The annotation this
// replaces claimed /auth/keycloak/info, which no router has ever served.
func (h *AuthHandler) Info(w http.ResponseWriter, r *http.Request) {
	baseURL := h.keycloakCfg.BaseURL
	realm := h.keycloakCfg.Realm
	oidcBase := fmt.Sprintf("%s/realms/%s/protocol/openid-connect", baseURL, realm)

	resp := KeycloakInfoResponse{
		AuthURL:     fmt.Sprintf("%s/auth", oidcBase),
		TokenURL:    fmt.Sprintf("%s/token", oidcBase),
		UserInfoURL: fmt.Sprintf("%s/userinfo", oidcBase),
		LogoutURL:   fmt.Sprintf("%s/logout", oidcBase),
		JWKSURL:     fmt.Sprintf("%s/certs", oidcBase),
		Realm:       realm,
		Issuer:      h.keycloakCfg.IssuerURL(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// GenerateToken is deprecated - tokens are now issued by Keycloak.
//
// Served at POST /auth/token in the OIDC branch only; LocalAuthHandler.Login
// serves the same path in the local branch and carries the @Router. See Info
// above. The annotation this replaces claimed /auth/keycloak/token, which no
// router has ever served.
func (h *AuthHandler) GenerateToken(w http.ResponseWriter, r *http.Request) {
	baseURL := h.keycloakCfg.BaseURL
	realm := h.keycloakCfg.Realm
	authURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/auth", baseURL, realm)

	resp := struct {
		Message string `json:"message"`
		AuthURL string `json:"auth_url"`
	}{
		Message: "Token generation is now handled by Keycloak. Please use the OAuth2 authorization flow.",
		AuthURL: authURL,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}
