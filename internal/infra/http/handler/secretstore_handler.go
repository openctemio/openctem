package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/secretstore"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/validator"
)

// SecretStoreHandler handles HTTP requests for secret store credentials.
type SecretStoreHandler struct {
	service   *app.SecretStoreService
	validator *validator.Validator
	logger    *logger.Logger
}

// NewSecretStoreHandler creates a new SecretStoreHandler.
func NewSecretStoreHandler(service *app.SecretStoreService, v *validator.Validator, log *logger.Logger) *SecretStoreHandler {
	return &SecretStoreHandler{
		service:   service,
		validator: v,
		logger:    log.With("handler", "secretstore"),
	}
}

// CreateCredentialRequest represents the request body for creating a credential.
type CreateCredentialRequest struct {
	Name           string `json:"name" validate:"required,min=1,max=255"`
	CredentialType string `json:"credential_type" validate:"required,oneof=api_key basic_auth bearer_token ssh_key aws_role gcp_service_account azure_service_principal github_app gitlab_token"`
	Description    string `json:"description" validate:"max=1000"`
	ExpiresAt      string `json:"expires_at,omitempty"`

	// Credential data (only one should be set based on credential_type)
	APIKey                *APIKeyDataRequest                `json:"api_key,omitempty"`
	BasicAuth             *BasicAuthDataRequest             `json:"basic_auth,omitempty"`
	BearerToken           *BearerTokenDataRequest           `json:"bearer_token,omitempty"`
	SSHKey                *SSHKeyDataRequest                `json:"ssh_key,omitempty"`
	AWSRole               *AWSRoleDataRequest               `json:"aws_role,omitempty"`
	GCPServiceAccount     *GCPServiceAccountDataRequest     `json:"gcp_service_account,omitempty"`
	AzureServicePrincipal *AzureServicePrincipalDataRequest `json:"azure_service_principal,omitempty"`
	GitHubApp             *GitHubAppDataRequest             `json:"github_app,omitempty"`
	GitLabToken           *GitLabTokenDataRequest           `json:"gitlab_token,omitempty"`
}

// APIKeyDataRequest represents API key credential data.
type APIKeyDataRequest struct {
	Key string `json:"key" validate:"required"`
}

// BasicAuthDataRequest represents basic auth credential data.
type BasicAuthDataRequest struct {
	Username string `json:"username" validate:"required"`
	Password string `json:"password" validate:"required"`
}

// BearerTokenDataRequest represents bearer token credential data.
type BearerTokenDataRequest struct {
	Token string `json:"token" validate:"required"`
}

// SSHKeyDataRequest represents SSH key credential data.
type SSHKeyDataRequest struct {
	PrivateKey string `json:"private_key" validate:"required"`
	Passphrase string `json:"passphrase,omitempty"`
}

// AWSRoleDataRequest represents AWS role credential data.
type AWSRoleDataRequest struct {
	RoleARN    string `json:"role_arn" validate:"required"`
	ExternalID string `json:"external_id,omitempty"`
}

// GCPServiceAccountDataRequest represents GCP service account credential data.
type GCPServiceAccountDataRequest struct {
	JSONKey string `json:"json_key" validate:"required"`
}

// AzureServicePrincipalDataRequest represents Azure service principal credential data.
type AzureServicePrincipalDataRequest struct {
	TenantID     string `json:"tenant_id" validate:"required"`
	ClientID     string `json:"client_id" validate:"required"`
	ClientSecret string `json:"client_secret" validate:"required"`
}

// GitHubAppDataRequest represents GitHub App credential data.
type GitHubAppDataRequest struct {
	AppID          string `json:"app_id" validate:"required"`
	InstallationID string `json:"installation_id" validate:"required"`
	PrivateKey     string `json:"private_key" validate:"required"`
}

// GitLabTokenDataRequest represents GitLab token credential data.
type GitLabTokenDataRequest struct {
	Token string `json:"token" validate:"required"`
}

// UpdateCredentialRequest represents the request body for updating a credential.
type UpdateCredentialRequest struct {
	Name        string `json:"name" validate:"omitempty,min=1,max=255"`
	Description string `json:"description" validate:"max=1000"`
	ExpiresAt   string `json:"expires_at,omitempty"`
}

// CredentialResponse represents the response for a credential.
type CredentialResponse struct {
	ID             string  `json:"id"`
	TenantID       string  `json:"tenant_id"`
	Name           string  `json:"name"`
	CredentialType string  `json:"credential_type"`
	Description    string  `json:"description,omitempty"`
	ExpiresAt      *string `json:"expires_at,omitempty"`
	LastUsedAt     *string `json:"last_used_at,omitempty"`
	LastRotatedAt  *string `json:"last_rotated_at,omitempty"`
	CreatedBy      *string `json:"created_by,omitempty"`
	CreatedAt      string  `json:"created_at"`
	UpdatedAt      string  `json:"updated_at"`
}

// ListCredentialsResponse represents the response for listing credentials.
type ListCredentialsResponse struct {
	Items      []CredentialResponse `json:"items"`
	TotalCount int                  `json:"total_count"`
	Page       int                  `json:"page"`
	PageSize   int                  `json:"page_size"`
}

// Create handles POST /api/v1/credentials
// @Summary      Create credential
// @Description  Create a new credential for template sources
// @Tags         Credentials
// @Accept       json
// @Produce      json
// @Param        body  body      CreateCredentialRequest  true  "Credential data"
// @Success      201   {object}  CredentialResponse
// @Failure      400   {object}  apierror.Error
// @Failure      409   {object}  apierror.Error
// @Failure      500   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /credentials [post]
func (h *SecretStoreHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req CreateCredentialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	tenantIDStr := middleware.GetTenantID(r.Context())
	userIDStr := middleware.GetUserID(r.Context())

	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		apierror.BadRequest("Invalid tenant ID").WriteJSON(w)
		return
	}

	userID, err := shared.IDFromString(userIDStr)
	if err != nil {
		apierror.BadRequest("Invalid user ID").WriteJSON(w)
		return
	}

	// Convert request data to credential data type
	credData, err := h.toCredentialData(req)
	if err != nil {
		apierror.BadRequest(err.Error()).WriteJSON(w)
		return
	}

	input := app.CreateCredentialInput{
		TenantID:       tenantID,
		UserID:         userID,
		Name:           req.Name,
		CredentialType: secretstore.CredentialType(req.CredentialType),
		Description:    req.Description,
		Data:           credData,
	}

	// Parse expires_at if provided
	if req.ExpiresAt != "" {
		expiresAt, err := time.Parse(time.RFC3339, req.ExpiresAt)
		if err != nil {
			apierror.BadRequest("Invalid expires_at format, use RFC3339").WriteJSON(w)
			return
		}
		input.ExpiresAt = &expiresAt
	}

	cred, err := h.service.CreateCredential(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(toCredentialResponse(cred))
}

// Get handles GET /api/v1/credentials/{id}
// @Summary      Get credential
// @Description  Get a single credential by ID (without sensitive data)
// @Tags         Credentials
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Credential ID"
// @Success      200  {object}  CredentialResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /credentials/{id} [get]
func (h *SecretStoreHandler) Get(w http.ResponseWriter, r *http.Request) {
	credentialID := chi.URLParam(r, "id")
	if credentialID == "" {
		apierror.BadRequest("Credential ID is required").WriteJSON(w)
		return
	}

	tenantIDStr := middleware.GetTenantID(r.Context())
	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		apierror.BadRequest("Invalid tenant ID").WriteJSON(w)
		return
	}

	cred, err := h.service.GetCredential(r.Context(), tenantID, credentialID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toCredentialResponse(cred))
}

// List handles GET /api/v1/credentials
// @Summary      List credentials
// @Description  List credentials with optional filters
// @Tags         Credentials
// @Accept       json
// @Produce      json
// @Param        credential_type  query     string  false  "Filter by credential type"
// @Param        page             query     int     false  "Page number"
// @Param        page_size        query     int     false  "Page size"
// @Success      200  {object}  ListCredentialsResponse
// @Failure      400  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /credentials [get]
func (h *SecretStoreHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantIDStr := middleware.GetTenantID(r.Context())
	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		apierror.BadRequest("Invalid tenant ID").WriteJSON(w)
		return
	}

	input := app.ListCredentialsInput{
		TenantID: tenantID,
		Page:     1,
		PageSize: 20,
	}

	// Parse optional filters
	if credType := r.URL.Query().Get("credential_type"); credType != "" {
		input.CredentialType = &credType
	}
	if pageStr := r.URL.Query().Get("page"); pageStr != "" {
		if page, err := strconv.Atoi(pageStr); err == nil && page > 0 {
			input.Page = page
		}
	}
	if pageSizeStr := r.URL.Query().Get("page_size"); pageSizeStr != "" {
		if pageSize, err := strconv.Atoi(pageSizeStr); err == nil && pageSize > 0 && pageSize <= 100 {
			input.PageSize = pageSize
		}
	}

	result, err := h.service.ListCredentials(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// Convert to response
	items := make([]CredentialResponse, len(result.Items))
	for i, cred := range result.Items {
		items[i] = *toCredentialResponse(cred)
	}

	response := ListCredentialsResponse{
		Items:      items,
		TotalCount: result.TotalCount,
		Page:       input.Page,
		PageSize:   input.PageSize,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Update handles PUT /api/v1/credentials/{id}
// @Summary      Update credential
// @Description  Update credential metadata (not sensitive data)
// @Tags         Credentials
// @Accept       json
// @Produce      json
// @Param        id    path      string                   true  "Credential ID"
// @Param        body  body      UpdateCredentialRequest  true  "Updated credential data"
// @Success      200   {object}  CredentialResponse
// @Failure      400   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Failure      500   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /credentials/{id} [put]
func (h *SecretStoreHandler) Update(w http.ResponseWriter, r *http.Request) {
	credentialID := chi.URLParam(r, "id")
	if credentialID == "" {
		apierror.BadRequest("Credential ID is required").WriteJSON(w)
		return
	}

	var req UpdateCredentialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	tenantIDStr := middleware.GetTenantID(r.Context())
	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		apierror.BadRequest("Invalid tenant ID").WriteJSON(w)
		return
	}

	input := app.UpdateCredentialInput{
		TenantID:     tenantID,
		CredentialID: credentialID,
		Name:         req.Name,
		Description:  req.Description,
	}

	// Parse expires_at if provided
	if req.ExpiresAt != "" {
		expiresAt, err := time.Parse(time.RFC3339, req.ExpiresAt)
		if err != nil {
			apierror.BadRequest("Invalid expires_at format, use RFC3339").WriteJSON(w)
			return
		}
		input.ExpiresAt = &expiresAt
	}

	cred, err := h.service.UpdateCredential(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toCredentialResponse(cred))
}

// Delete handles DELETE /api/v1/credentials/{id}
// @Summary      Delete credential
// @Description  Delete a credential
// @Tags         Credentials
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Credential ID"
// @Success      204  "No Content"
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /credentials/{id} [delete]
func (h *SecretStoreHandler) Delete(w http.ResponseWriter, r *http.Request) {
	credentialID := chi.URLParam(r, "id")
	if credentialID == "" {
		apierror.BadRequest("Credential ID is required").WriteJSON(w)
		return
	}

	tenantIDStr := middleware.GetTenantID(r.Context())
	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		apierror.BadRequest("Invalid tenant ID").WriteJSON(w)
		return
	}

	if err := h.service.DeleteCredential(r.Context(), tenantID, credentialID); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// toCredentialData converts request data to appropriate credential data type.
func (h *SecretStoreHandler) toCredentialData(req CreateCredentialRequest) (any, error) {
	switch secretstore.CredentialType(req.CredentialType) {
	case secretstore.CredentialTypeAPIKey:
		if req.APIKey == nil {
			return nil, errors.New("api_key data is required for api_key credential type")
		}
		return &secretstore.APIKeyData{Key: req.APIKey.Key}, nil

	case secretstore.CredentialTypeBasicAuth:
		if req.BasicAuth == nil {
			return nil, errors.New("basic_auth data is required for basic_auth credential type")
		}
		return &secretstore.BasicAuthData{
			Username: req.BasicAuth.Username,
			Password: req.BasicAuth.Password,
		}, nil

	case secretstore.CredentialTypeBearerToken:
		if req.BearerToken == nil {
			return nil, errors.New("bearer_token data is required for bearer_token credential type")
		}
		return &secretstore.BearerTokenData{Token: req.BearerToken.Token}, nil

	case secretstore.CredentialTypeSSHKey:
		if req.SSHKey == nil {
			return nil, errors.New("ssh_key data is required for ssh_key credential type")
		}
		return &secretstore.SSHKeyData{
			PrivateKey: req.SSHKey.PrivateKey,
			Passphrase: req.SSHKey.Passphrase,
		}, nil

	case secretstore.CredentialTypeAWSRole:
		if req.AWSRole == nil {
			return nil, errors.New("aws_role data is required for aws_role credential type")
		}
		return &secretstore.AWSRoleData{
			RoleARN:    req.AWSRole.RoleARN,
			ExternalID: req.AWSRole.ExternalID,
		}, nil

	case secretstore.CredentialTypeGCPServiceAccount:
		if req.GCPServiceAccount == nil {
			return nil, errors.New("gcp_service_account data is required for gcp_service_account credential type")
		}
		return &secretstore.GCPServiceAccountData{JSONKey: req.GCPServiceAccount.JSONKey}, nil

	case secretstore.CredentialTypeAzureServicePrincipal:
		if req.AzureServicePrincipal == nil {
			return nil, errors.New("azure_service_principal data is required for azure_service_principal credential type")
		}
		return &secretstore.AzureServicePrincipalData{
			TenantID:     req.AzureServicePrincipal.TenantID,
			ClientID:     req.AzureServicePrincipal.ClientID,
			ClientSecret: req.AzureServicePrincipal.ClientSecret,
		}, nil

	case secretstore.CredentialTypeGitHubApp:
		if req.GitHubApp == nil {
			return nil, errors.New("github_app data is required for github_app credential type")
		}
		return &secretstore.GitHubAppData{
			AppID:          req.GitHubApp.AppID,
			InstallationID: req.GitHubApp.InstallationID,
			PrivateKey:     req.GitHubApp.PrivateKey,
		}, nil

	case secretstore.CredentialTypeGitLabToken:
		if req.GitLabToken == nil {
			return nil, errors.New("gitlab_token data is required for gitlab_token credential type")
		}
		return &secretstore.GitLabTokenData{Token: req.GitLabToken.Token}, nil

	default:
		return nil, errors.New("unsupported credential type")
	}
}

// handleValidationError handles validation errors.
// Uses safe error messages to prevent information leakage.
func (h *SecretStoreHandler) handleValidationError(w http.ResponseWriter, err error) {
	apierror.SafeBadRequest(err).WriteJSON(w)
}

// handleServiceError handles service errors.
// Uses safe error messages to prevent information leakage.
func (h *SecretStoreHandler) handleServiceError(w http.ResponseWriter, err error) {
	h.logger.Error("service error", "error", err)

	if errors.Is(err, shared.ErrNotFound) {
		apierror.NotFound("Credential not found").WriteJSON(w)
		return
	}
	if errors.Is(err, shared.ErrAlreadyExists) {
		apierror.Conflict("Credential with this name already exists").WriteJSON(w)
		return
	}
	if errors.Is(err, shared.ErrForbidden) {
		apierror.SafeForbidden(err).WriteJSON(w)
		return
	}
	if errors.Is(err, shared.ErrValidation) {
		apierror.SafeBadRequest(err).WriteJSON(w)
		return
	}

	apierror.InternalError(err).WriteJSON(w)
}

// toCredentialResponse converts a domain Credential to a CredentialResponse.
func toCredentialResponse(c *secretstore.Credential) *CredentialResponse {
	resp := &CredentialResponse{
		ID:             c.ID.String(),
		TenantID:       c.TenantID.String(),
		Name:           c.Name,
		CredentialType: string(c.CredentialType),
		Description:    c.Description,
		CreatedAt:      c.CreatedAt.Format(time.RFC3339),
		UpdatedAt:      c.UpdatedAt.Format(time.RFC3339),
	}

	if c.ExpiresAt != nil {
		expiresAt := c.ExpiresAt.Format(time.RFC3339)
		resp.ExpiresAt = &expiresAt
	}
	if c.LastUsedAt != nil {
		lastUsedAt := c.LastUsedAt.Format(time.RFC3339)
		resp.LastUsedAt = &lastUsedAt
	}
	if c.LastRotatedAt != nil {
		lastRotatedAt := c.LastRotatedAt.Format(time.RFC3339)
		resp.LastRotatedAt = &lastRotatedAt
	}
	if c.CreatedBy != nil {
		createdBy := c.CreatedBy.String()
		resp.CreatedBy = &createdBy
	}

	return resp
}
