package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/identityprovider"
	"github.com/openctemio/api/pkg/logger"
)

// SSOHandler handles per-tenant SSO authentication requests.
type SSOHandler struct {
	ssoService *app.SSOService
	logger     *logger.Logger
}

// NewSSOHandler creates a new SSOHandler.
func NewSSOHandler(ssoService *app.SSOService, log *logger.Logger) *SSOHandler {
	return &SSOHandler{
		ssoService: ssoService,
		logger:     log.With("handler", "sso"),
	}
}

// === Public endpoints (no auth required) ===

// ListTenantProviders returns active SSO providers for a tenant.
// GET /api/v1/auth/sso/providers?org={slug}
func (h *SSOHandler) ListTenantProviders(w http.ResponseWriter, r *http.Request) {
	orgSlug := r.URL.Query().Get("org")
	if orgSlug == "" {
		apierror.BadRequest("org parameter is required").WriteJSON(w)
		return
	}

	providers, err := h.ssoService.GetProvidersForTenant(r.Context(), orgSlug)
	if err != nil {
		h.handlePublicError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"providers": providers,
	})
}

// Authorize returns the SSO authorization URL for a tenant's provider.
// GET /api/v1/auth/sso/{provider}/authorize?org={slug}&redirect_uri={uri}
func (h *SSOHandler) Authorize(w http.ResponseWriter, r *http.Request) {
	provider := r.PathValue("provider")
	if provider == "" {
		apierror.BadRequest("provider is required").WriteJSON(w)
		return
	}

	orgSlug := r.URL.Query().Get("org")
	if orgSlug == "" {
		apierror.BadRequest("org parameter is required").WriteJSON(w)
		return
	}

	redirectURI := r.URL.Query().Get("redirect_uri")
	if redirectURI == "" {
		apierror.BadRequest("redirect_uri parameter is required").WriteJSON(w)
		return
	}

	result, err := h.ssoService.GenerateAuthorizeURL(r.Context(), app.SSOAuthorizeInput{
		OrgSlug:     orgSlug,
		Provider:    provider,
		RedirectURI: redirectURI,
	})
	if err != nil {
		h.handlePublicError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// SSOCallbackRequest is the request body for SSO callback.
type SSOCallbackRequest struct {
	Code        string `json:"code" validate:"required"`
	State       string `json:"state" validate:"required"`
	RedirectURI string `json:"redirect_uri" validate:"required"`
}

// Callback handles the SSO OAuth callback.
// POST /api/v1/auth/sso/{provider}/callback
func (h *SSOHandler) Callback(w http.ResponseWriter, r *http.Request) {
	provider := r.PathValue("provider")
	if provider == "" {
		apierror.BadRequest("provider is required").WriteJSON(w)
		return
	}

	var req SSOCallbackRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}

	if req.Code == "" || req.State == "" {
		apierror.BadRequest("code and state are required").WriteJSON(w)
		return
	}

	result, err := h.ssoService.HandleCallback(r.Context(), app.SSOCallbackInput{
		Provider:    provider,
		Code:        req.Code,
		State:       req.State,
		RedirectURI: req.RedirectURI,
	})
	if err != nil {
		h.handlePublicError(w, err)
		return
	}

	resp := map[string]interface{}{
		"access_token":  result.AccessToken,
		"refresh_token": result.RefreshToken,
		"token_type":    result.TokenType,
		"expires_in":    result.ExpiresIn,
		"tenant_id":     result.TenantID,
		"tenant_slug":   result.TenantSlug,
		"user": UserInfo{
			ID:    result.User.ID().String(),
			Email: result.User.Email(),
			Name:  result.User.Name(),
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handlePublicError handles errors for public SSO endpoints with generic messages.
func (h *SSOHandler) handlePublicError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, app.ErrSSOTenantNotFound):
		apierror.NotFound("Organization not found").WriteJSON(w)
	case errors.Is(err, app.ErrSSONoActiveProviders):
		apierror.NotFound("No SSO providers configured").WriteJSON(w)
	case errors.Is(err, app.ErrSSOProviderNotFound):
		apierror.NotFound("SSO provider not configured").WriteJSON(w)
	case errors.Is(err, app.ErrSSOProviderInactive):
		apierror.BadRequest("SSO provider is not active").WriteJSON(w)
	case errors.Is(err, app.ErrSSOInvalidState):
		apierror.BadRequest("Invalid or expired state token").WriteJSON(w)
	case errors.Is(err, app.ErrSSOExchangeFailed):
		apierror.BadRequest("Failed to complete SSO authentication").WriteJSON(w)
	case errors.Is(err, app.ErrSSOUserInfoFailed):
		apierror.BadRequest("Failed to retrieve user information").WriteJSON(w)
	case errors.Is(err, app.ErrSSODomainNotAllowed):
		apierror.Forbidden("Your email domain is not allowed for this organization").WriteJSON(w)
	default:
		h.logger.Error("SSO error", "error", err)
		apierror.InternalError(err).WriteJSON(w)
	}
}

// === Admin endpoints (authenticated, tenant-scoped) ===

// CreateProviderRequest is the request body for creating an identity provider.
type CreateProviderRequest struct {
	Provider         string   `json:"provider" validate:"required,oneof=entra_id okta google_workspace"`
	DisplayName      string   `json:"display_name" validate:"required,min=1,max=255"`
	ClientID         string   `json:"client_id" validate:"required,max=255"`
	ClientSecret     string   `json:"client_secret" validate:"required,max=1000"`
	IssuerURL        string   `json:"issuer_url" validate:"omitempty,url,max=500"`
	TenantIdentifier string   `json:"tenant_identifier" validate:"max=255"`
	Scopes           []string `json:"scopes" validate:"max=20,dive,max=100"`
	AllowedDomains   []string `json:"allowed_domains" validate:"max=50,dive,max=255"`
	AutoProvision    bool     `json:"auto_provision"`
	DefaultRole      string   `json:"default_role" validate:"omitempty,oneof=member viewer"`
}

// CreateProvider creates a new identity provider configuration.
// POST /api/v1/settings/identity-providers
func (h *SSOHandler) CreateProvider(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())

	var req CreateProviderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}

	if req.Provider == "" || req.DisplayName == "" || req.ClientID == "" || req.ClientSecret == "" {
		apierror.BadRequest("provider, display_name, client_id, and client_secret are required").WriteJSON(w)
		return
	}

	ip, err := h.ssoService.CreateProvider(r.Context(), app.CreateProviderInput{
		TenantID:         tenantID,
		Provider:         req.Provider,
		DisplayName:      req.DisplayName,
		ClientID:         req.ClientID,
		ClientSecret:     req.ClientSecret,
		IssuerURL:        req.IssuerURL,
		TenantIdentifier: req.TenantIdentifier,
		Scopes:           req.Scopes,
		AllowedDomains:   req.AllowedDomains,
		AutoProvision:    req.AutoProvision,
		DefaultRole:      req.DefaultRole,
		CreatedBy:        userID,
	})
	if err != nil {
		h.handleAdminError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(h.toProviderResponse(ip))
}

// ListProviders lists all identity provider configurations for the tenant.
// GET /api/v1/settings/identity-providers
func (h *SSOHandler) ListProviders(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())

	providers, err := h.ssoService.ListProviders(r.Context(), tenantID)
	if err != nil {
		h.handleAdminError(w, err)
		return
	}

	result := make([]ProviderDetailResponse, 0, len(providers))
	for _, ip := range providers {
		result = append(result, h.toProviderResponse(ip))
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"providers": result,
	})
}

// GetProvider retrieves a single identity provider configuration.
// GET /api/v1/settings/identity-providers/{id}
func (h *SSOHandler) GetProvider(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())

	id := r.PathValue("id")
	if id == "" {
		apierror.BadRequest("id is required").WriteJSON(w)
		return
	}

	ip, err := h.ssoService.GetProvider(r.Context(), tenantID, id)
	if err != nil {
		h.handleAdminError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(h.toProviderResponse(ip))
}

// UpdateProviderRequest is the request body for updating an identity provider.
type UpdateProviderRequest struct {
	DisplayName      *string  `json:"display_name" validate:"omitempty,min=1,max=255"`
	ClientID         *string  `json:"client_id" validate:"omitempty,max=255"`
	ClientSecret     *string  `json:"client_secret" validate:"omitempty,max=1000"`
	IssuerURL        *string  `json:"issuer_url" validate:"omitempty,url,max=500"`
	TenantIdentifier *string  `json:"tenant_identifier" validate:"omitempty,max=255"`
	Scopes           []string `json:"scopes" validate:"max=20,dive,max=100"`
	AllowedDomains   []string `json:"allowed_domains" validate:"max=50,dive,max=255"`
	AutoProvision    *bool    `json:"auto_provision"`
	DefaultRole      *string  `json:"default_role" validate:"omitempty,oneof=member viewer"`
	IsActive         *bool    `json:"is_active"`
}

// UpdateProvider updates an identity provider configuration.
// PUT /api/v1/settings/identity-providers/{id}
func (h *SSOHandler) UpdateProvider(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())

	id := r.PathValue("id")
	if id == "" {
		apierror.BadRequest("id is required").WriteJSON(w)
		return
	}

	var req UpdateProviderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}

	ip, err := h.ssoService.UpdateProvider(r.Context(), app.UpdateProviderInput{
		ID:               id,
		TenantID:         tenantID,
		DisplayName:      req.DisplayName,
		ClientID:         req.ClientID,
		ClientSecret:     req.ClientSecret,
		IssuerURL:        req.IssuerURL,
		TenantIdentifier: req.TenantIdentifier,
		Scopes:           req.Scopes,
		AllowedDomains:   req.AllowedDomains,
		AutoProvision:    req.AutoProvision,
		DefaultRole:      req.DefaultRole,
		IsActive:         req.IsActive,
	})
	if err != nil {
		h.handleAdminError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(h.toProviderResponse(ip))
}

// DeleteProvider deletes an identity provider configuration.
// DELETE /api/v1/settings/identity-providers/{id}
func (h *SSOHandler) DeleteProvider(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())

	id := r.PathValue("id")
	if id == "" {
		apierror.BadRequest("id is required").WriteJSON(w)
		return
	}

	if err := h.ssoService.DeleteProvider(r.Context(), tenantID, id); err != nil {
		h.handleAdminError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ProviderDetailResponse is the JSON response for an identity provider.
type ProviderDetailResponse struct {
	ID               string   `json:"id"`
	TenantID         string   `json:"tenant_id"`
	Provider         string   `json:"provider"`
	DisplayName      string   `json:"display_name"`
	ClientID         string   `json:"client_id"`
	IssuerURL        string   `json:"issuer_url,omitempty"`
	TenantIdentifier string   `json:"tenant_identifier,omitempty"`
	Scopes           []string `json:"scopes"`
	AllowedDomains   []string `json:"allowed_domains"`
	AutoProvision    bool     `json:"auto_provision"`
	DefaultRole      string   `json:"default_role"`
	IsActive         bool     `json:"is_active"`
	CreatedAt        string   `json:"created_at"`
	UpdatedAt        string   `json:"updated_at"`
	CreatedBy        string   `json:"created_by,omitempty"`
}

func (h *SSOHandler) toProviderResponse(ip *identityprovider.IdentityProvider) ProviderDetailResponse {
	scopes := ip.Scopes()
	if scopes == nil {
		scopes = []string{}
	}
	domains := ip.AllowedDomains()
	if domains == nil {
		domains = []string{}
	}

	return ProviderDetailResponse{
		ID:               ip.ID(),
		TenantID:         ip.TenantID(),
		Provider:         string(ip.Provider()),
		DisplayName:      ip.DisplayName(),
		ClientID:         ip.ClientID(),
		IssuerURL:        ip.IssuerURL(),
		TenantIdentifier: ip.TenantIdentifier(),
		Scopes:           scopes,
		AllowedDomains:   domains,
		AutoProvision:    ip.AutoProvision(),
		DefaultRole:      ip.DefaultRole(),
		IsActive:         ip.IsActive(),
		CreatedAt:        ip.CreatedAt().Format("2006-01-02T15:04:05Z"),
		UpdatedAt:        ip.UpdatedAt().Format("2006-01-02T15:04:05Z"),
		CreatedBy:        ip.CreatedBy(),
	}
}

// handleAdminError handles errors for admin SSO endpoints.
func (h *SSOHandler) handleAdminError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, identityprovider.ErrNotFound):
		apierror.NotFound("Identity provider not found").WriteJSON(w)
	case errors.Is(err, identityprovider.ErrAlreadyExists):
		apierror.Conflict("Identity provider already configured for this tenant and provider type").WriteJSON(w)
	case errors.Is(err, identityprovider.ErrInvalidProvider):
		apierror.BadRequest("Invalid identity provider type. Supported: entra_id, okta, google_workspace").WriteJSON(w)
	case errors.Is(err, identityprovider.ErrInvalidConfig):
		h.logger.Warn("invalid provider configuration", "error", err)
		apierror.BadRequest("Invalid identity provider configuration. Please verify all required fields.").WriteJSON(w)
	case errors.Is(err, app.ErrSSOInvalidDefaultRole):
		apierror.BadRequest("Invalid default role. Must be admin, member, or viewer").WriteJSON(w)
	default:
		h.logger.Error("identity provider error", "error", err)
		apierror.InternalServerError("An internal error occurred").WriteJSON(w)
	}
}
