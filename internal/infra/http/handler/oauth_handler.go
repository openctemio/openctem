package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/config"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/logger"
)

// OAuthHandler handles OAuth authentication requests.
type OAuthHandler struct {
	oauthService *app.OAuthService
	oauthConfig  config.OAuthConfig
	authConfig   config.AuthConfig
	logger       *logger.Logger
}

// NewOAuthHandler creates a new OAuthHandler.
func NewOAuthHandler(
	oauthService *app.OAuthService,
	oauthConfig config.OAuthConfig,
	authConfig config.AuthConfig,
	log *logger.Logger,
) *OAuthHandler {
	return &OAuthHandler{
		oauthService: oauthService,
		oauthConfig:  oauthConfig,
		authConfig:   authConfig,
		logger:       log.With("handler", "oauth"),
	}
}

// AuthorizeRequest is the request for getting authorization URL.
type AuthorizeRequest struct {
	RedirectURI   string `json:"redirect_uri"`
	FinalRedirect string `json:"final_redirect"`
}

// AuthorizeResponse is the response containing the authorization URL.
type AuthorizeResponse struct {
	AuthorizationURL string `json:"authorization_url"`
	State            string `json:"state"`
}

// Authorize returns the OAuth authorization URL for a provider.
// @Summary      Get OAuth authorization URL
// @Description  Returns authorization URL for OAuth login with the specified provider
// @Tags         OAuth
// @Produce      json
// @Param        provider       path      string  true   "OAuth provider (google, github, gitlab)"
// @Param        redirect_uri   query     string  false  "Callback URL after authorization"
// @Param        final_redirect query     string  false  "Final redirect URL after login"
// @Success      200  {object}  AuthorizeResponse
// @Failure      400  {object}  map[string]string
// @Router       /auth/oauth/{provider}/authorize [get]
func (h *OAuthHandler) Authorize(w http.ResponseWriter, r *http.Request) {
	provider := r.PathValue("provider")
	if provider == "" {
		apierror.BadRequest("Provider is required").WriteJSON(w)
		return
	}

	oauthProvider := app.OAuthProvider(provider)
	if !oauthProvider.IsValid() {
		apierror.BadRequest("Invalid OAuth provider").WriteJSON(w)
		return
	}

	// Get query parameters
	redirectURI := r.URL.Query().Get("redirect_uri")
	finalRedirect := r.URL.Query().Get("final_redirect")

	// Use default frontend callback URL if not provided
	if redirectURI == "" {
		redirectURI = h.oauthConfig.FrontendCallbackURL
	}

	result, err := h.oauthService.GetAuthorizationURL(r.Context(), app.AuthorizationURLInput{
		Provider:      oauthProvider,
		RedirectURI:   redirectURI,
		FinalRedirect: finalRedirect,
	})
	if err != nil {
		h.handleOAuthError(w, err)
		return
	}

	resp := AuthorizeResponse{
		AuthorizationURL: result.AuthorizationURL,
		State:            result.State,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

// CallbackRequest is the request body for OAuth callback.
type CallbackRequest struct {
	Code        string `json:"code"`
	State       string `json:"state"`
	RedirectURI string `json:"redirect_uri"`
}

// CallbackResponse is the response body for OAuth callback.
type CallbackResponse struct {
	AccessToken  string   `json:"access_token"`
	RefreshToken string   `json:"refresh_token"`
	TokenType    string   `json:"token_type"`
	ExpiresIn    int64    `json:"expires_in"`
	User         UserInfo `json:"user"`
}

// Callback handles the OAuth callback from the provider.
// @Summary      OAuth callback handler
// @Description  Handles the OAuth callback after user authorization
// @Tags         OAuth
// @Accept       json
// @Produce      json
// @Param        provider  path      string            true  "OAuth provider"
// @Param        request   body      CallbackRequest   true  "Callback data"
// @Success      200  {object}  CallbackResponse
// @Failure      400  {object}  map[string]string
// @Router       /auth/oauth/{provider}/callback [post]
func (h *OAuthHandler) Callback(w http.ResponseWriter, r *http.Request) {
	provider := r.PathValue("provider")
	if provider == "" {
		apierror.BadRequest("Provider is required").WriteJSON(w)
		return
	}

	oauthProvider := app.OAuthProvider(provider)
	if !oauthProvider.IsValid() {
		apierror.BadRequest("Invalid OAuth provider").WriteJSON(w)
		return
	}

	var req CallbackRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if req.Code == "" {
		apierror.BadRequest("Authorization code is required").WriteJSON(w)
		return
	}

	if req.State == "" {
		apierror.BadRequest("State is required").WriteJSON(w)
		return
	}

	// Use default frontend callback URL if not provided
	if req.RedirectURI == "" {
		req.RedirectURI = h.oauthConfig.FrontendCallbackURL
	}

	result, err := h.oauthService.HandleCallback(r.Context(), app.CallbackInput{
		Provider:    oauthProvider,
		Code:        req.Code,
		State:       req.State,
		RedirectURI: req.RedirectURI,
	})
	if err != nil {
		h.handleOAuthError(w, err)
		return
	}

	resp := CallbackResponse{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		TokenType:    result.TokenType,
		ExpiresIn:    result.ExpiresIn,
		User: UserInfo{
			ID:    result.User.ID().String(),
			Email: result.User.Email(),
			Name:  result.User.Name(),
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

// ProvidersResponse is the response body for listing available providers.
type ProvidersResponse struct {
	Providers []app.ProviderInfo `json:"providers"`
}

// ListProviders returns the list of available OAuth providers.
// @Summary      List OAuth providers
// @Description  Returns list of available and configured OAuth providers
// @Tags         OAuth
// @Produce      json
// @Success      200  {object}  ProvidersResponse
// @Router       /auth/oauth/providers [get]
func (h *OAuthHandler) ListProviders(w http.ResponseWriter, r *http.Request) {
	providers := h.oauthService.GetAvailableProviders()

	resp := ProvidersResponse{
		Providers: providers,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

// handleOAuthError handles OAuth errors and returns appropriate HTTP responses.
func (h *OAuthHandler) handleOAuthError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, app.ErrOAuthDisabled):
		apierror.Forbidden("OAuth is disabled").WriteJSON(w)
	case errors.Is(err, app.ErrProviderDisabled):
		apierror.Forbidden("This OAuth provider is not configured").WriteJSON(w)
	case errors.Is(err, app.ErrInvalidProvider):
		apierror.BadRequest("Invalid OAuth provider").WriteJSON(w)
	case errors.Is(err, app.ErrInvalidState):
		apierror.BadRequest("Invalid or expired state token").WriteJSON(w)
	case errors.Is(err, app.ErrOAuthExchangeFailed):
		apierror.BadRequest("Failed to exchange authorization code").WriteJSON(w)
	case errors.Is(err, app.ErrOAuthUserInfoFailed):
		apierror.BadRequest("Failed to get user information from provider").WriteJSON(w)
	default:
		h.logger.Error("oauth error", "error", err)
		apierror.InternalError(err).WriteJSON(w)
	}
}
