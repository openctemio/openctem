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
// @Summary      Get Keycloak info
// @Description  Returns Keycloak server configuration URLs and realm info
// @Tags         Authentication
// @Produce      json
// @Success      200  {object}  KeycloakInfoResponse
// @Router       /auth/keycloak/info [get]
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
// @Summary      Generate token (deprecated)
// @Description  Deprecated endpoint - returns redirect instruction to Keycloak OAuth flow
// @Tags         Authentication
// @Produce      json
// @Success      200  {object}  map[string]string
// @Router       /auth/keycloak/token [post]
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
