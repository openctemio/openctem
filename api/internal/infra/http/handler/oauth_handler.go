package handler

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// OAuthHandler handles OAuth authentication requests.
type OAuthHandler struct {
	oauthService *auth.OAuthService
	oauthConfig  config.OAuthConfig
	authConfig   config.AuthConfig
	logger       *logger.Logger
}

// NewOAuthHandler creates a new OAuthHandler.
func NewOAuthHandler(
	oauthService *auth.OAuthService,
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
	// BrowserBinding must be kept in an HttpOnly cookie and sent back with
	// the callback.
	BrowserBinding string `json:"browser_binding"`
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

	oauthProvider := auth.OAuthProvider(provider)
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

	// Security: Validate redirect_uri against allowed origins (CWE-601)
	if !h.isRedirectAllowed(redirectURI) {
		apierror.BadRequest("Invalid redirect URI").WriteJSON(w)
		return
	}

	// Security: Validate final_redirect against allowed origins (CWE-601)
	if finalRedirect != "" && !h.isFinalRedirectAllowed(finalRedirect) {
		apierror.BadRequest("Invalid redirect URI").WriteJSON(w)
		return
	}

	result, err := h.oauthService.GetAuthorizationURL(r.Context(), auth.AuthorizationURLInput{
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
		BrowserBinding:   result.BrowserBinding,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

// CallbackRequest is the request body for OAuth callback.
type CallbackRequest struct {
	Code        string `json:"code"`
	State       string `json:"state"`
	RedirectURI string `json:"redirect_uri"`
	// BrowserBinding is the secret the authorize response gave this browser.
	BrowserBinding string `json:"browser_binding"`
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
// @Description  Handles the OAuth callback after user authorization. A refusal carries a stable `code` (api/internal/infra/http/handler/auth_error_codes.go), for example EMAIL_UNVERIFIED_AT_IDP, USE_ADMIN_CONSOLE, OAUTH_INVALID_STATE, ACCOUNT_LINK_REQUIRED; the console words it in the person's language.
// @Tags         OAuth
// @Accept       json
// @Produce      json
// @Param        provider  path      string            true  "OAuth provider"
// @Param        request   body      CallbackRequest   true  "Callback data"
// @Success      200  {object}  CallbackResponse
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Router       /auth/oauth/{provider}/callback [post]
func (h *OAuthHandler) Callback(w http.ResponseWriter, r *http.Request) {
	provider := r.PathValue("provider")
	if provider == "" {
		apierror.BadRequest("Provider is required").WriteJSON(w)
		return
	}

	oauthProvider := auth.OAuthProvider(provider)
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

	result, err := h.oauthService.HandleCallback(auth.WithClientInfo(r.Context(), getClientIP(r), r.UserAgent()), auth.CallbackInput{
		Provider:    oauthProvider,
		Code:        req.Code,
		State:       req.State,
		RedirectURI: req.RedirectURI,

		BrowserBinding: req.BrowserBinding,
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

// handleOAuthError handles OAuth errors and returns appropriate HTTP responses.
func (h *OAuthHandler) handleOAuthError(w http.ResponseWriter, err error) {
	if writeAuthTableError(w, err) {
		return
	}
	h.logger.Error("oauth error", "error", err)
	apierror.InternalError(err).WriteJSON(w)
}

// isFinalRedirectAllowed checks where the web app sends the person after a
// successful sign-in: a path on this site ("/", "/findings?x=1") or an
// absolute URL that isRedirectAllowed accepts. Protocol-relative ("//host")
// and backslash forms ("/\\host"), which browsers treat as another host, and
// control characters are refused.
func (h *OAuthHandler) isFinalRedirectAllowed(raw string) bool {
	if strings.HasPrefix(raw, "/") {
		if strings.HasPrefix(raw, "//") || strings.ContainsAny(raw, "\\\r\n\t") {
			return false
		}
		u, err := url.Parse(raw)
		return err == nil && u.Scheme == "" && u.Host == ""
	}
	return h.isRedirectAllowed(raw)
}

// isRedirectAllowed validates that a redirect URL is safe (CWE-601 protection).
// Only allows URLs whose origin matches the configured FrontendCallbackURL.
func (h *OAuthHandler) isRedirectAllowed(rawURL string) bool {
	if rawURL == "" {
		return true
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}

	// Only allow http/https schemes
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return false
	}

	// If AllowedRedirectURLs is configured, check against it
	if len(h.oauthConfig.AllowedRedirectURLs) > 0 {
		for _, allowed := range h.oauthConfig.AllowedRedirectURLs {
			allowedParsed, err := url.Parse(allowed)
			if err != nil {
				continue
			}
			if strings.EqualFold(parsed.Host, allowedParsed.Host) &&
				strings.EqualFold(parsed.Scheme, allowedParsed.Scheme) {
				return true
			}
		}
		return false
	}

	// Default: only allow the configured FrontendCallbackURL origin
	if h.oauthConfig.FrontendCallbackURL == "" {
		return false
	}

	frontendParsed, err := url.Parse(h.oauthConfig.FrontendCallbackURL)
	if err != nil {
		return false
	}

	return strings.EqualFold(parsed.Host, frontendParsed.Host) &&
		strings.EqualFold(parsed.Scheme, frontendParsed.Scheme)
}
