package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/shared"
	ts "github.com/openctemio/api/pkg/domain/templatesource"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/validator"
)

// TemplateSourceHandler handles HTTP requests for template sources.
type TemplateSourceHandler struct {
	service   *app.TemplateSourceService
	validator *validator.Validator
	logger    *logger.Logger
}

// NewTemplateSourceHandler creates a new TemplateSourceHandler.
func NewTemplateSourceHandler(service *app.TemplateSourceService, v *validator.Validator, log *logger.Logger) *TemplateSourceHandler {
	return &TemplateSourceHandler{
		service:   service,
		validator: v,
		logger:    log.With("handler", "template_source"),
	}
}

// CreateTemplateSourceRequest represents the request body for creating a template source.
type CreateTemplateSourceRequest struct {
	Name            string               `json:"name" validate:"required,min=1,max=255"`
	SourceType      string               `json:"source_type" validate:"required,oneof=git s3 http"`
	TemplateType    string               `json:"template_type" validate:"required,oneof=nuclei semgrep gitleaks"`
	Description     string               `json:"description" validate:"max=1000"`
	Enabled         bool                 `json:"enabled"`
	AutoSyncOnScan  bool                 `json:"auto_sync_on_scan"`
	CacheTTLMinutes int                  `json:"cache_ttl_minutes" validate:"min=0,max=10080"`
	GitConfig       *ts.GitSourceConfig  `json:"git_config,omitempty"`
	S3Config        *ts.S3SourceConfig   `json:"s3_config,omitempty"`
	HTTPConfig      *ts.HTTPSourceConfig `json:"http_config,omitempty"`
	CredentialID    string               `json:"credential_id" validate:"omitempty,uuid"`
}

// UpdateTemplateSourceRequest represents the request body for updating a template source.
type UpdateTemplateSourceRequest struct {
	Name            string               `json:"name" validate:"omitempty,min=1,max=255"`
	Description     string               `json:"description" validate:"max=1000"`
	Enabled         *bool                `json:"enabled"`
	AutoSyncOnScan  *bool                `json:"auto_sync_on_scan"`
	CacheTTLMinutes *int                 `json:"cache_ttl_minutes" validate:"omitempty,min=0,max=10080"`
	GitConfig       *ts.GitSourceConfig  `json:"git_config,omitempty"`
	S3Config        *ts.S3SourceConfig   `json:"s3_config,omitempty"`
	HTTPConfig      *ts.HTTPSourceConfig `json:"http_config,omitempty"`
	CredentialID    *string              `json:"credential_id" validate:"omitempty,uuid"`
}

// TemplateSourceResponse represents the response for a template source.
type TemplateSourceResponse struct {
	ID              string               `json:"id"`
	TenantID        string               `json:"tenant_id"`
	Name            string               `json:"name"`
	SourceType      string               `json:"source_type"`
	TemplateType    string               `json:"template_type"`
	Description     string               `json:"description,omitempty"`
	Enabled         bool                 `json:"enabled"`
	AutoSyncOnScan  bool                 `json:"auto_sync_on_scan"`
	CacheTTLMinutes int                  `json:"cache_ttl_minutes"`
	GitConfig       *ts.GitSourceConfig  `json:"git_config,omitempty"`
	S3Config        *ts.S3SourceConfig   `json:"s3_config,omitempty"`
	HTTPConfig      *ts.HTTPSourceConfig `json:"http_config,omitempty"`
	LastSyncAt      *string              `json:"last_sync_at,omitempty"`
	LastSyncHash    string               `json:"last_sync_hash,omitempty"`
	LastSyncStatus  string               `json:"last_sync_status"`
	LastSyncError   *string              `json:"last_sync_error,omitempty"`
	TotalTemplates  int                  `json:"total_templates"`
	LastSyncCount   int                  `json:"last_sync_count"`
	CredentialID    *string              `json:"credential_id,omitempty"`
	CreatedBy       *string              `json:"created_by,omitempty"`
	CreatedAt       string               `json:"created_at"`
	UpdatedAt       string               `json:"updated_at"`
}

// ListSourcesResponse represents the response for listing template sources.
type ListSourcesResponse struct {
	Items      []TemplateSourceResponse `json:"items"`
	TotalCount int                      `json:"total_count"`
	Page       int                      `json:"page"`
	PageSize   int                      `json:"page_size"`
}

// Create handles POST /api/v1/template-sources
// @Summary      Create template source
// @Description  Create a new template source (Git, S3, or HTTP)
// @Tags         Template Sources
// @Accept       json
// @Produce      json
// @Param        body  body      CreateTemplateSourceRequest  true  "Source data"
// @Success      201   {object}  TemplateSourceResponse
// @Failure      400   {object}  apierror.Error
// @Failure      409   {object}  apierror.Error
// @Failure      500   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /template-sources [post]
func (h *TemplateSourceHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req CreateTemplateSourceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	tenantID := middleware.GetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())

	input := app.CreateTemplateSourceInput{
		TenantID:        tenantID,
		UserID:          userID,
		Name:            req.Name,
		SourceType:      req.SourceType,
		TemplateType:    req.TemplateType,
		Description:     req.Description,
		Enabled:         req.Enabled,
		AutoSyncOnScan:  req.AutoSyncOnScan,
		CacheTTLMinutes: req.CacheTTLMinutes,
		GitConfig:       req.GitConfig,
		S3Config:        req.S3Config,
		HTTPConfig:      req.HTTPConfig,
		CredentialID:    req.CredentialID,
	}

	source, err := h.service.CreateSource(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(toTemplateSourceResponse(source))
}

// Get handles GET /api/v1/template-sources/{id}
// @Summary      Get template source
// @Description  Get a single template source by ID
// @Tags         Template Sources
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Source ID"
// @Success      200  {object}  TemplateSourceResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /template-sources/{id} [get]
func (h *TemplateSourceHandler) Get(w http.ResponseWriter, r *http.Request) {
	sourceID := chi.URLParam(r, "id")
	if sourceID == "" {
		apierror.BadRequest("Source ID is required").WriteJSON(w)
		return
	}

	tenantID := middleware.GetTenantID(r.Context())

	source, err := h.service.GetSource(r.Context(), tenantID, sourceID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toTemplateSourceResponse(source))
}

// List handles GET /api/v1/template-sources
// @Summary      List template sources
// @Description  List template sources with optional filters
// @Tags         Template Sources
// @Accept       json
// @Produce      json
// @Param        source_type    query     string  false  "Filter by source type (git, s3, http)"
// @Param        template_type  query     string  false  "Filter by template type (nuclei, semgrep, gitleaks)"
// @Param        enabled        query     bool    false  "Filter by enabled status"
// @Param        page           query     int     false  "Page number"
// @Param        page_size      query     int     false  "Page size"
// @Param        sort_by        query     string  false  "Sort by field"
// @Param        sort_order     query     string  false  "Sort order (asc, desc)"
// @Success      200  {object}  ListSourcesResponse
// @Failure      400  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /template-sources [get]
func (h *TemplateSourceHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())

	input := app.ListTemplateSourcesInput{
		TenantID:  tenantID,
		SortBy:    r.URL.Query().Get("sort_by"),
		SortOrder: r.URL.Query().Get("sort_order"),
	}

	// Parse optional filters
	if sourceType := r.URL.Query().Get("source_type"); sourceType != "" {
		input.SourceType = &sourceType
	}
	if templateType := r.URL.Query().Get("template_type"); templateType != "" {
		input.TemplateType = &templateType
	}
	if enabledStr := r.URL.Query().Get("enabled"); enabledStr != "" {
		enabled := enabledStr == queryParamTrue
		input.Enabled = &enabled
	}
	if pageStr := r.URL.Query().Get("page"); pageStr != "" {
		if page, err := strconv.Atoi(pageStr); err == nil {
			input.Page = page
		}
	}
	if pageSizeStr := r.URL.Query().Get("page_size"); pageSizeStr != "" {
		if pageSize, err := strconv.Atoi(pageSizeStr); err == nil {
			input.PageSize = pageSize
		}
	}

	result, err := h.service.ListSources(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// Convert to response
	items := make([]TemplateSourceResponse, len(result.Items))
	for i, source := range result.Items {
		items[i] = *toTemplateSourceResponse(source)
	}

	response := ListSourcesResponse{
		Items:      items,
		TotalCount: result.TotalCount,
		Page:       input.Page,
		PageSize:   input.PageSize,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Update handles PUT /api/v1/template-sources/{id}
// @Summary      Update template source
// @Description  Update an existing template source
// @Tags         Template Sources
// @Accept       json
// @Produce      json
// @Param        id    path      string               true  "Source ID"
// @Param        body  body      UpdateTemplateSourceRequest  true  "Updated source data"
// @Success      200   {object}  TemplateSourceResponse
// @Failure      400   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Failure      500   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /template-sources/{id} [put]
func (h *TemplateSourceHandler) Update(w http.ResponseWriter, r *http.Request) {
	sourceID := chi.URLParam(r, "id")
	if sourceID == "" {
		apierror.BadRequest("Source ID is required").WriteJSON(w)
		return
	}

	var req UpdateTemplateSourceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	tenantID := middleware.GetTenantID(r.Context())

	input := app.UpdateTemplateSourceInput{
		TenantID:        tenantID,
		SourceID:        sourceID,
		Name:            req.Name,
		Description:     req.Description,
		Enabled:         req.Enabled,
		AutoSyncOnScan:  req.AutoSyncOnScan,
		CacheTTLMinutes: req.CacheTTLMinutes,
		GitConfig:       req.GitConfig,
		S3Config:        req.S3Config,
		HTTPConfig:      req.HTTPConfig,
		CredentialID:    req.CredentialID,
	}

	source, err := h.service.UpdateSource(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toTemplateSourceResponse(source))
}

// Delete handles DELETE /api/v1/template-sources/{id}
// @Summary      Delete template source
// @Description  Delete a template source
// @Tags         Template Sources
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Source ID"
// @Success      204  "No Content"
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /template-sources/{id} [delete]
func (h *TemplateSourceHandler) Delete(w http.ResponseWriter, r *http.Request) {
	sourceID := chi.URLParam(r, "id")
	if sourceID == "" {
		apierror.BadRequest("Source ID is required").WriteJSON(w)
		return
	}

	tenantID := middleware.GetTenantID(r.Context())

	if err := h.service.DeleteSource(r.Context(), tenantID, sourceID); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Enable handles POST /api/v1/template-sources/{id}/enable
// @Summary      Enable template source
// @Description  Enable a disabled template source
// @Tags         Template Sources
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Source ID"
// @Success      200  {object}  TemplateSourceResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /template-sources/{id}/enable [post]
func (h *TemplateSourceHandler) Enable(w http.ResponseWriter, r *http.Request) {
	sourceID := chi.URLParam(r, "id")
	if sourceID == "" {
		apierror.BadRequest("Source ID is required").WriteJSON(w)
		return
	}

	tenantID := middleware.GetTenantID(r.Context())

	source, err := h.service.EnableSource(r.Context(), tenantID, sourceID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toTemplateSourceResponse(source))
}

// Disable handles POST /api/v1/template-sources/{id}/disable
// @Summary      Disable template source
// @Description  Disable an active template source
// @Tags         Template Sources
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Source ID"
// @Success      200  {object}  TemplateSourceResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /template-sources/{id}/disable [post]
func (h *TemplateSourceHandler) Disable(w http.ResponseWriter, r *http.Request) {
	sourceID := chi.URLParam(r, "id")
	if sourceID == "" {
		apierror.BadRequest("Source ID is required").WriteJSON(w)
		return
	}

	tenantID := middleware.GetTenantID(r.Context())

	source, err := h.service.DisableSource(r.Context(), tenantID, sourceID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toTemplateSourceResponse(source))
}

// handleValidationError handles validation errors.
// Uses safe error messages to prevent information leakage.
func (h *TemplateSourceHandler) handleValidationError(w http.ResponseWriter, err error) {
	apierror.SafeBadRequest(err).WriteJSON(w)
}

// handleServiceError handles service errors.
// Uses safe error messages to prevent information leakage.
func (h *TemplateSourceHandler) handleServiceError(w http.ResponseWriter, err error) {
	h.logger.Error("service error", "error", err)

	if errors.Is(err, shared.ErrNotFound) {
		apierror.NotFound("Template source not found").WriteJSON(w)
		return
	}
	if errors.Is(err, shared.ErrAlreadyExists) {
		apierror.Conflict("Template source already exists").WriteJSON(w)
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

// toTemplateSourceResponse converts a domain TemplateSource to a TemplateSourceResponse.
func toTemplateSourceResponse(s *ts.TemplateSource) *TemplateSourceResponse {
	resp := &TemplateSourceResponse{
		ID:              s.ID.String(),
		TenantID:        s.TenantID.String(),
		Name:            s.Name,
		SourceType:      string(s.SourceType),
		TemplateType:    string(s.TemplateType),
		Description:     s.Description,
		Enabled:         s.Enabled,
		AutoSyncOnScan:  s.AutoSyncOnScan,
		CacheTTLMinutes: s.CacheTTLMinutes,
		GitConfig:       s.GitConfig,
		S3Config:        s.S3Config,
		HTTPConfig:      s.HTTPConfig,
		LastSyncHash:    s.LastSyncHash,
		LastSyncStatus:  string(s.LastSyncStatus),
		LastSyncError:   s.LastSyncError,
		TotalTemplates:  s.TotalTemplates,
		LastSyncCount:   s.LastSyncCount,
		CreatedAt:       s.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:       s.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}

	if s.LastSyncAt != nil {
		syncAt := s.LastSyncAt.Format("2006-01-02T15:04:05Z07:00")
		resp.LastSyncAt = &syncAt
	}
	if s.CredentialID != nil {
		credID := s.CredentialID.String()
		resp.CredentialID = &credID
	}
	if s.CreatedBy != nil {
		createdBy := s.CreatedBy.String()
		resp.CreatedBy = &createdBy
	}

	return resp
}

// TemplateSyncResponse represents the response for a template source sync operation.
type TemplateSyncResponse struct {
	Success        bool   `json:"success"`
	TemplatesFound int    `json:"templates_found"`
	TemplatesAdded int    `json:"templates_added"`
	Duration       string `json:"duration"`
	Error          string `json:"error,omitempty"`
}

// Sync triggers an immediate sync for a template source.
// POST /api/v1/template-sources/{id}/sync
func (h *TemplateSourceHandler) Sync(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())
	if tenantID == "" {
		apierror.Unauthorized("tenant ID not found").WriteJSON(w)
		return
	}

	id := chi.URLParam(r, "id")
	if id == "" {
		apierror.BadRequest("source id is required").WriteJSON(w)
		return
	}

	result, err := h.service.ForceSync(r.Context(), tenantID, id)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			apierror.NotFound("template source").WriteJSON(w)
			return
		}
		var domainErr *shared.DomainError
		if errors.As(err, &domainErr) {
			apierror.BadRequest(domainErr.Message).WriteJSON(w)
			return
		}
		h.logger.Error("failed to sync template source", "error", err, "source_id", id)
		apierror.InternalServerError("failed to sync template source").WriteJSON(w)
		return
	}

	resp := TemplateSyncResponse{
		Success:        result.Success,
		TemplatesFound: result.TemplatesFound,
		TemplatesAdded: result.TemplatesAdded,
		Duration:       result.Duration.String(),
	}
	if result.Error != "" {
		resp.Error = result.Error
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}
