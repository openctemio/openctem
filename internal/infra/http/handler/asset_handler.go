package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/internal/infra/scm"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/validator"
)

// AssetHandler handles asset-related HTTP requests.
type AssetHandler struct {
	service            *app.AssetService
	integrationService *app.IntegrationService
	validator          *validator.Validator
	logger             *logger.Logger
}

// NewAssetHandler creates a new asset handler.
func NewAssetHandler(svc *app.AssetService, v *validator.Validator, log *logger.Logger) *AssetHandler {
	return &AssetHandler{
		service:   svc,
		validator: v,
		logger:    log,
	}
}

// SetIntegrationService sets the integration service for sync operations.
func (h *AssetHandler) SetIntegrationService(svc *app.IntegrationService) {
	h.integrationService = svc
}

// AssetResponse represents an asset in API responses.
type AssetResponse struct {
	ID           string         `json:"id"`
	TenantID     string         `json:"tenant_id,omitempty"`
	Name         string         `json:"name"`
	Type         string         `json:"type"`
	Provider     string         `json:"provider,omitempty"`
	ExternalID   string         `json:"external_id,omitempty"`
	Criticality  string         `json:"criticality"`
	Status       string         `json:"status"`
	Scope        string         `json:"scope"`
	Exposure     string         `json:"exposure"`
	RiskScore    int            `json:"risk_score"`
	FindingCount int            `json:"finding_count"`
	Description  string         `json:"description,omitempty"`
	Tags         []string       `json:"tags,omitempty"`
	Metadata     map[string]any `json:"metadata,omitempty"`
	FirstSeen    time.Time      `json:"first_seen"`
	LastSeen     time.Time      `json:"last_seen"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
}

// ListResponse is defined in common.go

// CreateAssetRequest represents the request to create an asset.
type CreateAssetRequest struct {
	Name        string   `json:"name" validate:"required,min=1,max=255"`
	Type        string   `json:"type" validate:"required,asset_type"`
	Criticality string   `json:"criticality" validate:"required,criticality"`
	Scope       string   `json:"scope" validate:"omitempty,scope"`
	Exposure    string   `json:"exposure" validate:"omitempty,exposure"`
	Description string   `json:"description" validate:"max=1000"`
	Tags        []string `json:"tags" validate:"max=20,dive,max=50"`
}

// UpdateAssetRequest represents the request to update an asset.
type UpdateAssetRequest struct {
	Name        *string  `json:"name" validate:"omitempty,min=1,max=255"`
	Criticality *string  `json:"criticality" validate:"omitempty,criticality"`
	Scope       *string  `json:"scope" validate:"omitempty,scope"`
	Exposure    *string  `json:"exposure" validate:"omitempty,exposure"`
	Description *string  `json:"description" validate:"omitempty,max=1000"`
	Tags        []string `json:"tags" validate:"omitempty,max=20,dive,max=50"`
}

// toAssetResponse converts a domain asset to API response.
func toAssetResponse(a *asset.Asset) AssetResponse {
	var tenantID string
	if !a.TenantID().IsZero() {
		tenantID = a.TenantID().String()
	}

	return AssetResponse{
		ID:           a.ID().String(),
		TenantID:     tenantID,
		Name:         a.Name(),
		Type:         a.Type().String(),
		Provider:     a.Provider().String(),
		ExternalID:   a.ExternalID(),
		Criticality:  a.Criticality().String(),
		Status:       a.Status().String(),
		Scope:        a.Scope().String(),
		Exposure:     a.Exposure().String(),
		RiskScore:    a.RiskScore(),
		FindingCount: a.FindingCount(),
		Description:  a.Description(),
		Tags:         a.Tags(),
		Metadata:     a.Metadata(),
		FirstSeen:    a.FirstSeen(),
		LastSeen:     a.LastSeen(),
		CreatedAt:    a.CreatedAt(),
		UpdatedAt:    a.UpdatedAt(),
	}
}

// handleValidationError converts validation errors to API errors and writes response.
func (h *AssetHandler) handleValidationError(w http.ResponseWriter, err error) {
	var validationErrors validator.ValidationErrors
	if errors.As(err, &validationErrors) {
		apiErrors := make([]apierror.ValidationError, len(validationErrors))
		for i, ve := range validationErrors {
			apiErrors[i] = apierror.ValidationError{
				Field:   ve.Field,
				Message: ve.Message,
			}
		}
		apierror.ValidationFailed("Validation failed", apiErrors).WriteJSON(w)
		return
	}
	apierror.BadRequest("Validation error").WriteJSON(w)
}

// handleServiceError converts service errors to API errors and writes response.
func (h *AssetHandler) handleServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Asset").WriteJSON(w)
	case errors.Is(err, shared.ErrAlreadyExists):
		apierror.Conflict("Asset already exists").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	default:
		h.logger.Error("service error", "error", err)
		apierror.InternalError(err).WriteJSON(w)
	}
}

// List handles GET /api/v1/assets
// @Summary      List assets
// @Description  Retrieves a paginated list of assets for the current tenant
// @Tags         Assets
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        name          query     string  false  "Filter by name (partial match)"
// @Param        types         query     string  false  "Filter by types (comma-separated)"
// @Param        criticalities query     string  false  "Filter by criticalities (comma-separated)"
// @Param        statuses      query     string  false  "Filter by statuses (comma-separated)"
// @Param        scopes        query     string  false  "Filter by scopes (comma-separated)"
// @Param        exposures     query     string  false  "Filter by exposures (comma-separated)"
// @Param        tags          query     string  false  "Filter by tags (comma-separated)"
// @Param        search        query     string  false  "Full-text search across name and description"
// @Param        min_risk_score  query   int     false  "Minimum risk score (0-100)"
// @Param        max_risk_score  query   int     false  "Maximum risk score (0-100)"
// @Param        has_findings  query     bool    false  "Filter by whether asset has findings"
// @Param        sort          query     string  false  "Sort field (e.g., -created_at, name, -risk_score)"
// @Param        page          query     int     false  "Page number"  default(1)
// @Param        per_page      query     int     false  "Items per page"  default(20)  maximum(100)
// @Success      200  {object}  map[string]interface{}
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      500  {object}  map[string]string
// @Router       /assets [get]
func (h *AssetHandler) List(w http.ResponseWriter, r *http.Request) {
	// Get tenant ID from JWT token (RequireTenant middleware guarantees this exists)
	tenantID := middleware.MustGetTenantID(r.Context())

	query := r.URL.Query()

	input := app.ListAssetsInput{
		TenantID:      tenantID,
		Name:          query.Get("name"),
		Types:         parseQueryArray(query.Get("types")),
		Criticalities: parseQueryArray(query.Get("criticalities")),
		Statuses:      parseQueryArray(query.Get("statuses")),
		Scopes:        parseQueryArray(query.Get("scopes")),
		Exposures:     parseQueryArray(query.Get("exposures")),
		Tags:          parseQueryArray(query.Get("tags")),
		Search:        query.Get("search"),
		MinRiskScore:  parseQueryIntPtr(query.Get("min_risk_score")),
		MaxRiskScore:  parseQueryIntPtr(query.Get("max_risk_score")),
		HasFindings:   parseQueryBoolPtr(query.Get("has_findings")),
		Sort:          query.Get("sort"),
		Page:          parseQueryInt(query.Get("page"), 1),
		PerPage:       parseQueryInt(query.Get("per_page"), 20),
	}

	if err := h.validator.Validate(input); err != nil {
		h.handleValidationError(w, err)
		return
	}

	result, err := h.service.ListAssets(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// Check if we're filtering by repository type to include extensions
	isRepositoryTypeFilter := len(input.Types) == 1 && input.Types[0] == "repository"

	// If filtering by repository type, fetch extensions and return combined response
	if isRepositoryTypeFilter && h.service.HasRepositoryExtensionRepository() {
		data := make([]AssetWithRepositoryResponse, len(result.Data))
		for i, a := range result.Data {
			resp := AssetWithRepositoryResponse{
				AssetResponse: toAssetResponse(a),
			}
			// Fetch repository extension for this asset
			ext, err := h.service.GetRepositoryExtension(r.Context(), tenantID, a.ID().String())
			if err == nil && ext != nil {
				resp.Repository = toRepositoryExtensionResponse(ext)
			}
			data[i] = resp
		}

		response := ListResponse[AssetWithRepositoryResponse]{
			Data:       data,
			Total:      result.Total,
			Page:       result.Page,
			PerPage:    result.PerPage,
			TotalPages: result.TotalPages,
			Links:      NewPaginationLinks(r, result.Page, result.PerPage, result.TotalPages),
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(response)
		return
	}

	// Default response without extensions
	data := make([]AssetResponse, len(result.Data))
	for i, a := range result.Data {
		data[i] = toAssetResponse(a)
	}

	response := ListResponse[AssetResponse]{
		Data:       data,
		Total:      result.Total,
		Page:       result.Page,
		PerPage:    result.PerPage,
		TotalPages: result.TotalPages,
		Links:      NewPaginationLinks(r, result.Page, result.PerPage, result.TotalPages),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

// Create handles POST /api/v1/assets
// @Summary      Create asset
// @Description  Creates a new asset for the current tenant
// @Tags         Assets
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        request  body      CreateAssetRequest  true  "Asset data"
// @Success      201  {object}  AssetResponse
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      409  {object}  map[string]string
// @Failure      500  {object}  map[string]string
// @Router       /assets [post]
func (h *AssetHandler) Create(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	var req CreateAssetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := app.CreateAssetInput{
		TenantID:    tenantID,
		Name:        req.Name,
		Type:        req.Type,
		Criticality: req.Criticality,
		Scope:       req.Scope,
		Exposure:    req.Exposure,
		Description: req.Description,
		Tags:        req.Tags,
	}

	a, err := h.service.CreateAsset(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(toAssetResponse(a))
}

// Get handles GET /api/v1/assets/{id}
// @Summary      Get asset
// @Description  Retrieves an asset by ID
// @Tags         Assets
// @Produce      json
// @Security     BearerAuth
// @Param        id   path      string  true  "Asset ID"
// @Success      200  {object}  AssetResponse
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Failure      500  {object}  map[string]string
// @Router       /assets/{id} [get]
func (h *AssetHandler) Get(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	id := r.PathValue("id")
	if id == "" {
		apierror.BadRequest("Asset ID is required").WriteJSON(w)
		return
	}

	// GetAsset now enforces tenant isolation internally
	a, err := h.service.GetAsset(r.Context(), tenantID, id)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toAssetResponse(a))
}

// Update handles PUT /api/v1/assets/{id}
// @Summary      Update asset
// @Description  Updates an existing asset
// @Tags         Assets
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id       path      string              true  "Asset ID"
// @Param        request  body      UpdateAssetRequest  true  "Asset data"
// @Success      200  {object}  AssetResponse
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Failure      500  {object}  map[string]string
// @Router       /assets/{id} [put]
func (h *AssetHandler) Update(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	id := r.PathValue("id")
	if id == "" {
		apierror.BadRequest("Asset ID is required").WriteJSON(w)
		return
	}

	var req UpdateAssetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := app.UpdateAssetInput{
		Name:        req.Name,
		Criticality: req.Criticality,
		Scope:       req.Scope,
		Exposure:    req.Exposure,
		Description: req.Description,
		Tags:        req.Tags,
	}

	a, err := h.service.UpdateAsset(r.Context(), id, tenantID, input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toAssetResponse(a))
}

// Delete handles DELETE /api/v1/assets/{id}
// @Summary      Delete asset
// @Description  Deletes an asset by ID
// @Tags         Assets
// @Security     BearerAuth
// @Param        id   path      string  true  "Asset ID"
// @Success      204  "No Content"
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Failure      500  {object}  map[string]string
// @Router       /assets/{id} [delete]
func (h *AssetHandler) Delete(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	id := r.PathValue("id")
	if id == "" {
		apierror.BadRequest("Asset ID is required").WriteJSON(w)
		return
	}

	if err := h.service.DeleteAsset(r.Context(), id, tenantID); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// RepositoryExtensionResponse represents a repository extension in API responses.
type RepositoryExtensionResponse struct {
	AssetID              string           `json:"asset_id"`
	RepoID               string           `json:"repo_id,omitempty"`
	FullName             string           `json:"full_name"`
	SCMOrganization      string           `json:"scm_organization,omitempty"`
	CloneURL             string           `json:"clone_url,omitempty"`
	WebURL               string           `json:"web_url,omitempty"`
	SSHURL               string           `json:"ssh_url,omitempty"`
	DefaultBranch        string           `json:"default_branch,omitempty"`
	Visibility           string           `json:"visibility"`
	Language             string           `json:"language,omitempty"`
	Languages            map[string]int64 `json:"languages,omitempty"`
	Topics               []string         `json:"topics,omitempty"`
	Stars                int              `json:"stars"`
	Forks                int              `json:"forks"`
	Watchers             int              `json:"watchers"`
	OpenIssues           int              `json:"open_issues"`
	ContributorsCount    int              `json:"contributors_count"`
	SizeKB               int              `json:"size_kb"`
	BranchCount          int              `json:"branch_count"`
	ProtectedBranchCount int              `json:"protected_branch_count"`
	ComponentCount       int              `json:"component_count"`
	VulnComponentCount   int              `json:"vulnerable_component_count"`
	FindingCount         int              `json:"finding_count"`
	ScanEnabled          bool             `json:"scan_enabled"`
	ScanSchedule         string           `json:"scan_schedule,omitempty"`
	LastScannedAt        *time.Time       `json:"last_scanned_at,omitempty"`
	RepoCreatedAt        *time.Time       `json:"repo_created_at,omitempty"`
	RepoUpdatedAt        *time.Time       `json:"repo_updated_at,omitempty"`
	RepoPushedAt         *time.Time       `json:"repo_pushed_at,omitempty"`
}

// AssetWithRepositoryResponse combines asset and repository extension.
type AssetWithRepositoryResponse struct {
	AssetResponse
	Repository *RepositoryExtensionResponse `json:"repository,omitempty"`
}

// CreateRepositoryAssetRequest represents the request to create a repository asset.
type CreateRepositoryAssetRequest struct {
	// Basic info
	Name        string   `json:"name" validate:"required,min=1,max=255"`
	Description string   `json:"description" validate:"max=1000"`
	Criticality string   `json:"criticality" validate:"required,criticality"`
	Scope       string   `json:"scope" validate:"omitempty,scope"`
	Exposure    string   `json:"exposure" validate:"omitempty,exposure"`
	Tags        []string `json:"tags" validate:"max=20,dive,max=50"`
	// SCM connection info
	Provider        string `json:"provider" validate:"omitempty"`
	ExternalID      string `json:"external_id" validate:"omitempty,max=255"`
	RepoID          string `json:"repo_id" validate:"omitempty,max=255"`
	FullName        string `json:"full_name" validate:"required,max=500"`
	SCMOrganization string `json:"scm_organization" validate:"omitempty,max=255"`
	// URLs
	CloneURL string `json:"clone_url" validate:"omitempty,url"`
	WebURL   string `json:"web_url" validate:"omitempty,url"`
	SSHURL   string `json:"ssh_url" validate:"omitempty,max=500"`
	// Repository settings
	DefaultBranch string           `json:"default_branch" validate:"omitempty,max=100"`
	Visibility    string           `json:"visibility" validate:"omitempty"`
	Language      string           `json:"language" validate:"omitempty,max=50"`
	Languages     map[string]int64 `json:"languages" validate:"omitempty"`
	Topics        []string         `json:"topics" validate:"max=50,dive,max=100"`
	// Stats
	Stars      int `json:"stars" validate:"min=0"`
	Forks      int `json:"forks" validate:"min=0"`
	Watchers   int `json:"watchers" validate:"min=0"`
	OpenIssues int `json:"open_issues" validate:"min=0"`
	SizeKB     int `json:"size_kb" validate:"min=0"`
	// Scan settings
	ScanEnabled  bool   `json:"scan_enabled"`
	ScanSchedule string `json:"scan_schedule" validate:"omitempty,max=100"`
	// Timestamps from SCM (ISO 8601 format)
	RepoCreatedAt string `json:"repo_created_at" validate:"omitempty"`
	RepoUpdatedAt string `json:"repo_updated_at" validate:"omitempty"`
	RepoPushedAt  string `json:"repo_pushed_at" validate:"omitempty"`
}

// UpdateRepositoryExtensionRequest represents the request to update a repository extension.
type UpdateRepositoryExtensionRequest struct {
	RepoID               *string          `json:"repo_id" validate:"omitempty,max=255"`
	FullName             *string          `json:"full_name" validate:"omitempty,max=500"`
	SCMOrganization      *string          `json:"scm_organization" validate:"omitempty,max=255"`
	CloneURL             *string          `json:"clone_url" validate:"omitempty,url"`
	WebURL               *string          `json:"web_url" validate:"omitempty,url"`
	SSHURL               *string          `json:"ssh_url" validate:"omitempty,max=500"`
	DefaultBranch        *string          `json:"default_branch" validate:"omitempty,max=100"`
	Visibility           *string          `json:"visibility" validate:"omitempty"`
	Language             *string          `json:"language" validate:"omitempty,max=50"`
	Languages            map[string]int64 `json:"languages" validate:"omitempty"`
	Topics               []string         `json:"topics" validate:"omitempty,max=50,dive,max=100"`
	Stars                *int             `json:"stars" validate:"omitempty,min=0"`
	Forks                *int             `json:"forks" validate:"omitempty,min=0"`
	Watchers             *int             `json:"watchers" validate:"omitempty,min=0"`
	OpenIssues           *int             `json:"open_issues" validate:"omitempty,min=0"`
	ContributorsCount    *int             `json:"contributors_count" validate:"omitempty,min=0"`
	SizeKB               *int             `json:"size_kb" validate:"omitempty,min=0"`
	BranchCount          *int             `json:"branch_count" validate:"omitempty,min=0"`
	ProtectedBranchCount *int             `json:"protected_branch_count" validate:"omitempty,min=0"`
	ComponentCount       *int             `json:"component_count" validate:"omitempty,min=0"`
}

// toRepositoryExtensionResponse converts a domain repository extension to API response.
func toRepositoryExtensionResponse(ext *asset.RepositoryExtension) *RepositoryExtensionResponse {
	if ext == nil {
		return nil
	}
	return &RepositoryExtensionResponse{
		AssetID:              ext.AssetID().String(),
		RepoID:               ext.RepoID(),
		FullName:             ext.FullName(),
		SCMOrganization:      ext.SCMOrganization(),
		CloneURL:             ext.CloneURL(),
		WebURL:               ext.WebURL(),
		SSHURL:               ext.SSHURL(),
		DefaultBranch:        ext.DefaultBranch(),
		Visibility:           ext.Visibility().String(),
		Language:             ext.Language(),
		Languages:            ext.Languages(),
		Topics:               ext.Topics(),
		Stars:                ext.Stars(),
		Forks:                ext.Forks(),
		Watchers:             ext.Watchers(),
		OpenIssues:           ext.OpenIssues(),
		ContributorsCount:    ext.ContributorsCount(),
		SizeKB:               ext.SizeKB(),
		BranchCount:          ext.BranchCount(),
		ProtectedBranchCount: ext.ProtectedBranchCount(),
		ComponentCount:       ext.ComponentCount(),
		VulnComponentCount:   ext.VulnerableComponentCount(),
		FindingCount:         ext.FindingCount(),
		ScanEnabled:          ext.ScanEnabled(),
		ScanSchedule:         ext.ScanSchedule(),
		LastScannedAt:        ext.LastScannedAt(),
		RepoCreatedAt:        ext.RepoCreatedAt(),
		RepoUpdatedAt:        ext.RepoUpdatedAt(),
		RepoPushedAt:         ext.RepoPushedAt(),
	}
}

// CreateRepository handles POST /api/v1/assets/repository
// @Summary      Create repository asset
// @Description  Creates a new repository asset with its extension data
// @Tags         Assets
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        request  body      CreateRepositoryAssetRequest  true  "Repository asset data"
// @Success      201  {object}  AssetWithRepositoryResponse
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      409  {object}  map[string]string
// @Failure      500  {object}  map[string]string
// @Router       /assets/repository [post]
func (h *AssetHandler) CreateRepository(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	var req CreateRepositoryAssetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := app.CreateRepositoryAssetInput{
		TenantID:        tenantID,
		Name:            req.Name,
		Description:     req.Description,
		Criticality:     req.Criticality,
		Scope:           req.Scope,
		Exposure:        req.Exposure,
		Tags:            req.Tags,
		Provider:        req.Provider,
		ExternalID:      req.ExternalID,
		RepoID:          req.RepoID,
		FullName:        req.FullName,
		SCMOrganization: req.SCMOrganization,
		CloneURL:        req.CloneURL,
		WebURL:          req.WebURL,
		SSHURL:          req.SSHURL,
		DefaultBranch:   req.DefaultBranch,
		Visibility:      req.Visibility,
		Language:        req.Language,
		Languages:       req.Languages,
		Topics:          req.Topics,
		Stars:           req.Stars,
		Forks:           req.Forks,
		Watchers:        req.Watchers,
		OpenIssues:      req.OpenIssues,
		SizeKB:          req.SizeKB,
		ScanEnabled:     req.ScanEnabled,
		ScanSchedule:    req.ScanSchedule,
		RepoCreatedAt:   req.RepoCreatedAt,
		RepoUpdatedAt:   req.RepoUpdatedAt,
		RepoPushedAt:    req.RepoPushedAt,
	}

	a, ext, err := h.service.CreateRepositoryAsset(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	response := AssetWithRepositoryResponse{
		AssetResponse: toAssetResponse(a),
		Repository:    toRepositoryExtensionResponse(ext),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(response)
}

// GetRepository handles GET /api/v1/assets/{id}/repository
// @Summary      Get repository extension
// @Description  Retrieves the repository extension for an asset
// @Tags         Assets
// @Produce      json
// @Security     BearerAuth
// @Param        id   path      string  true  "Asset ID"
// @Success      200  {object}  RepositoryExtensionResponse
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Failure      500  {object}  map[string]string
// @Router       /assets/{id}/repository [get]
func (h *AssetHandler) GetRepository(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	id := r.PathValue("id")
	if id == "" {
		apierror.BadRequest("Asset ID is required").WriteJSON(w)
		return
	}

	// GetAsset now enforces tenant isolation internally
	a, err := h.service.GetAsset(r.Context(), tenantID, id)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// Check if asset is a repository type - return 404 to avoid leaking asset type info
	if a.Type() != asset.AssetTypeRepository {
		apierror.NotFound("Repository").WriteJSON(w)
		return
	}

	ext, err := h.service.GetRepositoryExtension(r.Context(), tenantID, id)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toRepositoryExtensionResponse(ext))
}

// GetWithRepository handles GET /api/v1/assets/{id}/full
// @Summary      Get asset with repository
// @Description  Retrieves an asset with its repository extension (if applicable)
// @Tags         Assets
// @Produce      json
// @Security     BearerAuth
// @Param        id   path      string  true  "Asset ID"
// @Success      200  {object}  AssetWithRepositoryResponse
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Failure      500  {object}  map[string]string
// @Router       /assets/{id}/full [get]
func (h *AssetHandler) GetWithRepository(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	id := r.PathValue("id")
	if id == "" {
		apierror.BadRequest("Asset ID is required").WriteJSON(w)
		return
	}

	// GetAssetWithRepository now enforces tenant isolation internally
	a, ext, err := h.service.GetAssetWithRepository(r.Context(), tenantID, id)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	response := AssetWithRepositoryResponse{
		AssetResponse: toAssetResponse(a),
		Repository:    toRepositoryExtensionResponse(ext),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

// UpdateRepository handles PUT /api/v1/assets/{id}/repository
// @Summary      Update repository extension
// @Description  Updates the repository extension for an asset
// @Tags         Assets
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id       path      string                          true  "Asset ID"
// @Param        request  body      UpdateRepositoryExtensionRequest  true  "Repository extension data"
// @Success      200  {object}  RepositoryExtensionResponse
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Failure      500  {object}  map[string]string
// @Router       /assets/{id}/repository [put]
func (h *AssetHandler) UpdateRepository(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	id := r.PathValue("id")
	if id == "" {
		apierror.BadRequest("Asset ID is required").WriteJSON(w)
		return
	}

	// GetAsset now enforces tenant isolation internally
	a, err := h.service.GetAsset(r.Context(), tenantID, id)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// Check if asset is a repository type - return 404 to avoid leaking asset type info
	if a.Type() != asset.AssetTypeRepository {
		apierror.NotFound("Repository").WriteJSON(w)
		return
	}

	var req UpdateRepositoryExtensionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := app.UpdateRepositoryExtensionInput{
		RepoID:               req.RepoID,
		FullName:             req.FullName,
		SCMOrganization:      req.SCMOrganization,
		CloneURL:             req.CloneURL,
		WebURL:               req.WebURL,
		SSHURL:               req.SSHURL,
		DefaultBranch:        req.DefaultBranch,
		Visibility:           req.Visibility,
		Language:             req.Language,
		Languages:            req.Languages,
		Topics:               req.Topics,
		Stars:                req.Stars,
		Forks:                req.Forks,
		Watchers:             req.Watchers,
		OpenIssues:           req.OpenIssues,
		ContributorsCount:    req.ContributorsCount,
		SizeKB:               req.SizeKB,
		BranchCount:          req.BranchCount,
		ProtectedBranchCount: req.ProtectedBranchCount,
		ComponentCount:       req.ComponentCount,
	}

	ext, err := h.service.UpdateRepositoryExtension(r.Context(), tenantID, id, input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toRepositoryExtensionResponse(ext))
}

// Activate handles POST /api/v1/assets/{id}/activate
// @Summary      Activate asset
// @Description  Activates an asset
// @Tags         Assets
// @Produce      json
// @Security     BearerAuth
// @Param        id   path      string  true  "Asset ID"
// @Success      200  {object}  AssetResponse
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Failure      500  {object}  map[string]string
// @Router       /assets/{id}/activate [post]
func (h *AssetHandler) Activate(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	id := r.PathValue("id")
	if id == "" {
		apierror.BadRequest("Asset ID is required").WriteJSON(w)
		return
	}

	// ActivateAsset now enforces tenant isolation internally
	a, err := h.service.ActivateAsset(r.Context(), tenantID, id)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toAssetResponse(a))
}

// Deactivate handles POST /api/v1/assets/{id}/deactivate
// @Summary      Deactivate asset
// @Description  Deactivates an asset
// @Tags         Assets
// @Produce      json
// @Security     BearerAuth
// @Param        id   path      string  true  "Asset ID"
// @Success      200  {object}  AssetResponse
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Failure      500  {object}  map[string]string
// @Router       /assets/{id}/deactivate [post]
func (h *AssetHandler) Deactivate(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	id := r.PathValue("id")
	if id == "" {
		apierror.BadRequest("Asset ID is required").WriteJSON(w)
		return
	}

	// DeactivateAsset now enforces tenant isolation internally
	a, err := h.service.DeactivateAsset(r.Context(), tenantID, id)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toAssetResponse(a))
}

// Archive handles POST /api/v1/assets/{id}/archive
// @Summary      Archive asset
// @Description  Archives an asset
// @Tags         Assets
// @Produce      json
// @Security     BearerAuth
// @Param        id   path      string  true  "Asset ID"
// @Success      200  {object}  AssetResponse
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Failure      500  {object}  map[string]string
// @Router       /assets/{id}/archive [post]
func (h *AssetHandler) Archive(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	id := r.PathValue("id")
	if id == "" {
		apierror.BadRequest("Asset ID is required").WriteJSON(w)
		return
	}

	// ArchiveAsset now enforces tenant isolation internally
	a, err := h.service.ArchiveAsset(r.Context(), tenantID, id)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toAssetResponse(a))
}

// AssetBulkStatusRequest represents a bulk asset status update request.
type AssetBulkStatusRequest struct {
	AssetIDs []string `json:"asset_ids" validate:"required,min=1,max=100,dive,uuid"`
	Status   string   `json:"status" validate:"required,oneof=active inactive archived"`
}

// AssetBulkStatusResponse represents a bulk asset status update response.
type AssetBulkStatusResponse struct {
	Updated int      `json:"updated"`
	Failed  int      `json:"failed"`
	Errors  []string `json:"errors,omitempty"`
}

// BulkUpdateStatus handles POST /api/v1/assets/bulk/status
// @Summary      Bulk update asset status
// @Description  Updates the status of multiple assets at once
// @Tags         Assets
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        request  body      AssetBulkStatusRequest  true  "Bulk update data"
// @Success      200  {object}  AssetBulkStatusResponse
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      500  {object}  map[string]string
// @Router       /assets/bulk/status [post]
func (h *AssetHandler) BulkUpdateStatus(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	var req AssetBulkStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid JSON body").WriteJSON(w)
		return
	}

	if len(req.AssetIDs) == 0 {
		apierror.BadRequest("asset_ids is required").WriteJSON(w)
		return
	}

	if len(req.AssetIDs) > 100 {
		apierror.BadRequest("Cannot update more than 100 assets at once").WriteJSON(w)
		return
	}

	input := app.BulkUpdateAssetStatusInput{
		AssetIDs: req.AssetIDs,
		Status:   req.Status,
	}

	result, err := h.service.BulkUpdateAssetStatus(r.Context(), tenantID, input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	resp := AssetBulkStatusResponse{
		Updated: result.Updated,
		Failed:  result.Failed,
		Errors:  result.Errors,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// AssetStatsResponse represents asset statistics in API responses.
type AssetStatsResponse struct {
	Total         int            `json:"total"`
	ByType        map[string]int `json:"by_type"`
	ByStatus      map[string]int `json:"by_status"`
	ByCriticality map[string]int `json:"by_criticality"`
	ByScope       map[string]int `json:"by_scope"`
	ByExposure    map[string]int `json:"by_exposure"`
	WithFindings  int            `json:"with_findings"`
	RiskScoreAvg  float64        `json:"risk_score_avg"`
	FindingsTotal int            `json:"findings_total"`
	HighRiskCount int            `json:"high_risk_count"` // Assets with risk_score >= 70
}

// GetStats handles GET /api/v1/assets/stats
// @Summary      Get asset statistics
// @Description  Returns aggregated statistics for assets
// @Tags         Assets
// @Produce      json
// @Security     BearerAuth
// @Param        types         query     string  false  "Filter by types (comma-separated)"
// @Success      200  {object}  AssetStatsResponse
// @Failure      401  {object}  map[string]string
// @Failure      500  {object}  map[string]string
// @Router       /assets/stats [get]
func (h *AssetHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	query := r.URL.Query()
	typesFilter := parseQueryArray(query.Get("types"))

	// Build filter for stats
	input := app.ListAssetsInput{
		TenantID: tenantID,
		PerPage:  1000, // Get enough for stats calculation
	}
	if len(typesFilter) > 0 {
		input.Types = typesFilter
	}

	// Get assets to calculate stats
	result, err := h.service.ListAssets(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// Calculate stats from results
	stats := AssetStatsResponse{
		Total:         int(result.Total),
		ByType:        make(map[string]int),
		ByStatus:      make(map[string]int),
		ByCriticality: make(map[string]int),
		ByScope:       make(map[string]int),
		ByExposure:    make(map[string]int),
	}

	var totalRiskScore int
	for _, a := range result.Data {
		stats.ByType[a.Type().String()]++
		stats.ByStatus[a.Status().String()]++
		stats.ByCriticality[a.Criticality().String()]++
		stats.ByScope[a.Scope().String()]++
		stats.ByExposure[a.Exposure().String()]++
		stats.FindingsTotal += a.FindingCount()
		if a.FindingCount() > 0 {
			stats.WithFindings++
		}
		totalRiskScore += a.RiskScore()
		// Count high-risk assets (risk_score >= 70)
		if a.RiskScore() >= 70 {
			stats.HighRiskCount++
		}
	}

	if len(result.Data) > 0 {
		stats.RiskScoreAvg = float64(totalRiskScore) / float64(len(result.Data))
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(stats)
}

// SyncResponse represents the response from a sync operation.
type SyncResponse struct {
	Success       bool      `json:"success"`
	Message       string    `json:"message"`
	SyncedAt      time.Time `json:"synced_at"`
	UpdatedFields []string  `json:"updated_fields,omitempty"`
}

// BulkSyncRequest represents the request to sync multiple assets.
type BulkSyncRequest struct {
	AssetIDs []string `json:"asset_ids" validate:"required,min=1,max=100,dive,uuid"`
}

// BulkSyncResultItem represents the sync result for a single asset.
type BulkSyncResultItem struct {
	AssetID       string   `json:"asset_id"`
	Success       bool     `json:"success"`
	Message       string   `json:"message,omitempty"`
	UpdatedFields []string `json:"updated_fields,omitempty"`
	Error         string   `json:"error,omitempty"`
}

// BulkSyncResponse represents the response from a bulk sync operation.
type BulkSyncResponse struct {
	TotalCount   int                  `json:"total_count"`
	SuccessCount int                  `json:"success_count"`
	FailedCount  int                  `json:"failed_count"`
	SyncedAt     time.Time            `json:"synced_at"`
	Results      []BulkSyncResultItem `json:"results"`
}

// scmConnectionMatch holds matching integration info
type scmConnectionMatch struct {
	ID              string
	SCMOrganization string
}

// findMatchingSCMConnection finds an SCM integration matching the repository's provider/organization
func (h *AssetHandler) findMatchingSCMConnection(
	ctx context.Context,
	tenantID, provider, scmOrg string,
) (*scmConnectionMatch, error) {
	integration, err := h.integrationService.FindSCMIntegration(ctx, app.FindSCMIntegrationInput{
		TenantID: tenantID,
		Provider: provider,
		SCMOrg:   scmOrg,
	})
	if err != nil {
		return nil, err
	}

	scmOrgResult := ""
	if integration.SCM != nil {
		scmOrgResult = integration.SCM.SCMOrganization()
	}

	return &scmConnectionMatch{
		ID:              integration.ID().String(),
		SCMOrganization: scmOrgResult,
	}, nil
}

// buildSyncUpdateInput compares SCM data with current extension and builds update input
func buildSyncUpdateInput(scmRepo *scm.Repository, repoExt *asset.RepositoryExtension) (app.UpdateRepositoryExtensionInput, []string) {
	var updatedFields []string
	updateInput := app.UpdateRepositoryExtensionInput{}

	if scmRepo.DefaultBranch != "" && scmRepo.DefaultBranch != repoExt.DefaultBranch() {
		branch := scmRepo.DefaultBranch
		updateInput.DefaultBranch = &branch
		updatedFields = append(updatedFields, "default_branch")
	}
	if scmRepo.Language != "" && scmRepo.Language != repoExt.Language() {
		lang := scmRepo.Language
		updateInput.Language = &lang
		updatedFields = append(updatedFields, "language")
	}
	if scmRepo.Stars != repoExt.Stars() {
		stars := scmRepo.Stars
		updateInput.Stars = &stars
		updatedFields = append(updatedFields, "stars")
	}
	if scmRepo.Forks != repoExt.Forks() {
		forks := scmRepo.Forks
		updateInput.Forks = &forks
		updatedFields = append(updatedFields, "forks")
	}
	if scmRepo.Size != repoExt.SizeKB() {
		size := scmRepo.Size
		updateInput.SizeKB = &size
		updatedFields = append(updatedFields, "size_kb")
	}
	if len(scmRepo.Topics) > 0 {
		updateInput.Topics = scmRepo.Topics
		updatedFields = append(updatedFields, "topics")
	}
	if len(scmRepo.Languages) > 0 {
		languages := make(map[string]int64, len(scmRepo.Languages))
		for lang, bytes := range scmRepo.Languages {
			languages[lang] = int64(bytes)
		}
		updateInput.Languages = languages
		updatedFields = append(updatedFields, "languages")
	}

	visibility := "public"
	if scmRepo.IsPrivate {
		visibility = "private"
	}
	if visibility != repoExt.Visibility().String() {
		updateInput.Visibility = &visibility
		updatedFields = append(updatedFields, "visibility")
	}

	return updateInput, updatedFields
}

// validateSyncAsset validates the asset for sync operation
func (h *AssetHandler) validateSyncAsset(
	ctx context.Context,
	id, tenantID string,
) (*asset.Asset, *asset.RepositoryExtension, error) {
	// GetAsset now enforces tenant isolation internally
	a, err := h.service.GetAsset(ctx, tenantID, id)
	if err != nil {
		return nil, nil, err
	}

	if a.Type() != asset.AssetTypeRepository {
		return nil, nil, errors.New("asset is not a repository")
	}

	repoExt, err := h.service.GetRepositoryExtension(ctx, tenantID, id)
	if err != nil {
		return nil, nil, err
	}

	return a, repoExt, nil
}

// performSync fetches data from SCM and updates the repository extension
func (h *AssetHandler) performSync(
	ctx context.Context,
	assetID, tenantID, integrationID string,
	repoExt *asset.RepositoryExtension,
	a *asset.Asset,
) ([]string, error) {
	scmRepo, err := h.integrationService.GetSCMRepository(ctx, app.GetSCMRepositoryInput{
		IntegrationID: integrationID,
		TenantID:      tenantID,
		FullName:      repoExt.FullName(),
	})
	if err != nil {
		h.logger.Error("failed to get repository from SCM", "error", err)
		return nil, err
	}

	updateInput, updatedFields := buildSyncUpdateInput(scmRepo, repoExt)

	if len(updatedFields) > 0 {
		_, err = h.service.UpdateRepositoryExtension(ctx, tenantID, assetID, updateInput)
		if err != nil {
			h.logger.Error("failed to update repository extension", "error", err)
			return nil, err
		}
	}

	if a.Description() == "" && scmRepo.Description != "" {
		desc := scmRepo.Description
		_, err = h.service.UpdateAsset(ctx, assetID, tenantID, app.UpdateAssetInput{Description: &desc})
		if err != nil {
			h.logger.Warn("failed to update asset description", "error", err)
		} else {
			updatedFields = append(updatedFields, "description")
		}
	}

	h.logger.Info("repository synced",
		"asset_id", assetID,
		"repository", repoExt.FullName(),
		"updated_fields", updatedFields,
	)

	return updatedFields, nil
}

// Sync handles POST /api/v1/assets/{id}/sync
// @Summary      Sync repository from SCM
// @Description  Syncs repository metadata from the connected SCM provider
// @Tags         Assets
// @Produce      json
// @Security     BearerAuth
// @Param        id   path      string  true  "Asset ID"
// @Success      200  {object}  SyncResponse
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Failure      500  {object}  map[string]string
// @Router       /assets/{id}/sync [post]
func (h *AssetHandler) Sync(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	ctx := r.Context()

	id := r.PathValue("id")
	if id == "" {
		apierror.BadRequest("Asset ID is required").WriteJSON(w)
		return
	}

	if h.integrationService == nil {
		apierror.InternalError(errors.New("integration service not configured")).WriteJSON(w)
		return
	}

	// Validate asset
	a, repoExt, err := h.validateSyncAsset(ctx, id, tenantID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	if a == nil {
		return // Error already written
	}

	provider := string(a.Provider())
	if provider == "" {
		apierror.BadRequest("Repository has no SCM provider configured").WriteJSON(w)
		return
	}

	// Find matching connection
	matchingConn, err := h.findMatchingSCMConnection(ctx, tenantID, provider, repoExt.SCMOrganization())
	if err != nil {
		h.logger.Error("failed to list SCM connections", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}
	if matchingConn == nil {
		apierror.BadRequest("No matching SCM connection found for this repository").WriteJSON(w)
		return
	}

	// Perform sync
	updatedFields, err := h.performSync(ctx, id, tenantID, matchingConn.ID, repoExt, a)
	if err != nil {
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	response := SyncResponse{
		Success:       true,
		Message:       "Repository synced successfully",
		SyncedAt:      time.Now(),
		UpdatedFields: updatedFields,
	}

	if len(updatedFields) == 0 {
		response.Message = "Repository is already up to date"
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

// BulkSync handles POST /api/v1/assets/bulk-sync
// @Summary      Bulk sync repositories
// @Description  Syncs multiple repository assets from their SCM providers in a single request
// @Tags         Assets
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        request  body      BulkSyncRequest  true  "Asset IDs to sync"
// @Success      200      {object}  BulkSyncResponse
// @Failure      400      {object}  map[string]string
// @Failure      401      {object}  map[string]string
// @Failure      500      {object}  map[string]string
// @Router       /assets/bulk-sync [post]
func (h *AssetHandler) BulkSync(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	ctx := r.Context()

	if h.integrationService == nil {
		apierror.InternalError(errors.New("integration service not configured")).WriteJSON(w)
		return
	}

	var req BulkSyncRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	results := make([]BulkSyncResultItem, 0, len(req.AssetIDs))
	successCount := 0
	failedCount := 0

	for _, assetID := range req.AssetIDs {
		result := BulkSyncResultItem{
			AssetID: assetID,
		}

		// Validate asset
		a, repoExt, err := h.validateSyncAsset(ctx, assetID, tenantID)
		if err != nil {
			result.Success = false
			result.Error = err.Error()
			failedCount++
			results = append(results, result)
			continue
		}
		if a == nil {
			result.Success = false
			result.Error = "Asset validation failed"
			failedCount++
			results = append(results, result)
			continue
		}

		provider := string(a.Provider())
		if provider == "" {
			result.Success = false
			result.Error = "Repository has no SCM provider configured"
			failedCount++
			results = append(results, result)
			continue
		}

		// Find matching connection
		matchingConn, err := h.findMatchingSCMConnection(ctx, tenantID, provider, repoExt.SCMOrganization())
		if err != nil {
			result.Success = false
			result.Error = "Failed to find SCM connection"
			failedCount++
			results = append(results, result)
			continue
		}
		if matchingConn == nil {
			result.Success = false
			result.Error = "No matching SCM connection found for this repository"
			failedCount++
			results = append(results, result)
			continue
		}

		// Perform sync
		updatedFields, err := h.performSync(ctx, assetID, tenantID, matchingConn.ID, repoExt, a)
		if err != nil {
			result.Success = false
			result.Error = err.Error()
			failedCount++
			results = append(results, result)
			continue
		}

		result.Success = true
		result.UpdatedFields = updatedFields
		if len(updatedFields) == 0 {
			result.Message = "Already up to date"
		} else {
			result.Message = "Synced successfully"
		}
		successCount++
		results = append(results, result)
	}

	response := BulkSyncResponse{
		TotalCount:   len(req.AssetIDs),
		SuccessCount: successCount,
		FailedCount:  failedCount,
		SyncedAt:     time.Now(),
		Results:      results,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

// ScanResponse represents the response from a scan trigger.
type ScanResponse struct {
	Success  bool      `json:"success"`
	Message  string    `json:"message"`
	ScanID   string    `json:"scan_id,omitempty"`
	QueuedAt time.Time `json:"queued_at"`
}

// TriggerScan handles POST /api/v1/assets/{id}/scan
// @Summary      Trigger security scan
// @Description  Triggers a security scan for the repository asset
// @Tags         Assets
// @Produce      json
// @Security     BearerAuth
// @Param        id   path      string  true  "Asset ID"
// @Success      202  {object}  ScanResponse
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Failure      500  {object}  map[string]string
// @Router       /assets/{id}/scan [post]
func (h *AssetHandler) TriggerScan(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	id := r.PathValue("id")
	if id == "" {
		apierror.BadRequest("Asset ID is required").WriteJSON(w)
		return
	}

	// GetAsset now enforces tenant isolation internally
	a, err := h.service.GetAsset(r.Context(), tenantID, id)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// Verify it's a repository asset
	if a.Type() != asset.AssetTypeRepository {
		apierror.BadRequest("Asset is not a repository").WriteJSON(w)
		return
	}

	// Get repository extension to check if scanning is enabled
	repoExt, err := h.service.GetRepositoryExtension(r.Context(), tenantID, id)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// Record the scan request
	err = h.service.RecordRepositoryScan(r.Context(), id)
	if err != nil {
		h.logger.Error("failed to record scan", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	// TODO: In the future, this would queue a scan job
	// For now, we just record the request and return success
	// The actual scan infrastructure (workers, scanners) will be implemented later

	response := ScanResponse{
		Success:  true,
		Message:  "Scan queued successfully",
		QueuedAt: time.Now(),
	}

	// Add note about scan status
	if !repoExt.ScanEnabled() {
		response.Message = "Scan queued. Note: Automatic scanning is disabled for this repository."
	}

	h.logger.Info("scan triggered for repository",
		"asset_id", id,
		"repository", repoExt.FullName(),
		"scan_enabled", repoExt.ScanEnabled(),
	)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(response)
}

// Helper functions are defined in common.go
