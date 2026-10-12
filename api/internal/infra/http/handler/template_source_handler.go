package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/template"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	ts "github.com/openctemio/openctem/api/pkg/domain/templatesource"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// TemplateSourceHandler handles HTTP requests for template sources.
type TemplateSourceHandler struct {
	configAuditor
	service   *template.SourceService
	validator *validator.Validator
	logger    *logger.Logger
}

// NewTemplateSourceHandler creates a new TemplateSourceHandler.
func NewTemplateSourceHandler(service *template.SourceService, v *validator.Validator, log *logger.Logger) *TemplateSourceHandler {
	return &TemplateSourceHandler{
		service:   service,
		validator: v,
		logger:    log.With("handler", "template_source"),
	}
}

// buildAuditContext attributes template-source audit events to the caller.
func (h *TemplateSourceHandler) buildAuditContext(r *http.Request) auditapp.AuditContext {
	return auditapp.AuditContext{
		TenantID:   middleware.GetTenantID(r.Context()),
		ActorID:    middleware.GetUserID(r.Context()),
		ActorEmail: auditActorEmail(r.Context()),
		ActorIP:    getClientIP(r),
		UserAgent:  r.UserAgent(),
		RequestID:  r.Header.Get("X-Request-ID"),
	}
}

// CreateTemplateSourceRequest represents the request body for creating a template source.
type CreateTemplateSourceRequest struct {
	Name            string               `json:"name" validate:"required,min=1,max=255"`
	SourceType      string               `json:"source_type" validate:"required,oneof=git s3 http"`
	TemplateType    string               `json:"template_type" validate:"required,oneof=nuclei semgrep betterleaks"`
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

	// Security: Validate source URLs against SSRF (CWE-918)
	if req.GitConfig != nil && req.GitConfig.URL != "" {
		if err := validator.ValidateWebhookURL(req.GitConfig.URL); err != nil {
			apierror.BadRequest("git_config.url: " + err.Error()).WriteJSON(w)
			return
		}
	}
	if req.HTTPConfig != nil && req.HTTPConfig.URL != "" {
		if err := validator.ValidateWebhookURL(req.HTTPConfig.URL); err != nil {
			apierror.BadRequest("http_config.url: " + err.Error()).WriteJSON(w)
			return
		}
	}

	tenantID := middleware.GetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())

	input := template.CreateSourceInput{
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
		ActorIsAdmin:    middleware.IsAdmin(r.Context()),
		Audit:           h.buildAuditContext(r),
	}

	source, err := h.service.CreateSource(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	created := toTemplateSourceResponse(source)
	h.recordChange(r, h.logger, auditdom.ActionRuleSourceCreated, auditdom.ResourceTypeTemplateSource, created.ID, created.Name,
		nil, created, auditdom.SeverityMedium, "Template source created")

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
// @Param        template_type  query     string  false  "Filter by template type (nuclei, semgrep, betterleaks)"
// @Param        enabled        query     bool    false  "Filter by enabled status"
// @Param        page           query     int     false  "Page number"
// @Param        per_page       query     int     false  "Page size (max 100)"
// @Param        sort_by        query     string  false  "Sort by field"
// @Param        sort_order     query     string  false  "Sort order (asc, desc)"
// @Success      200  {object}  ListSourcesResponse
// @Failure      400  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /template-sources [get]
func (h *TemplateSourceHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())

	input := template.ListSourcesInput{
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
	paging, ok := listPage(w, r, 20)
	if !ok {
		return
	}
	input.Page, input.PageSize = paging.Page, paging.PerPage

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

	// Security: Validate source URLs against SSRF (CWE-918)
	if req.GitConfig != nil && req.GitConfig.URL != "" {
		if err := validator.ValidateWebhookURL(req.GitConfig.URL); err != nil {
			apierror.BadRequest("git_config.url: " + err.Error()).WriteJSON(w)
			return
		}
	}
	if req.HTTPConfig != nil && req.HTTPConfig.URL != "" {
		if err := validator.ValidateWebhookURL(req.HTTPConfig.URL); err != nil {
			apierror.BadRequest("http_config.url: " + err.Error()).WriteJSON(w)
			return
		}
	}

	tenantID := middleware.GetTenantID(r.Context())

	input := template.UpdateSourceInput{
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
		UserID:          middleware.GetUserID(r.Context()),
		ActorIsAdmin:    middleware.IsAdmin(r.Context()),
		Audit:           h.buildAuditContext(r),
	}

	var before any
	if prev, gerr := h.service.GetSource(r.Context(), input.TenantID, input.SourceID); gerr == nil {
		before = toTemplateSourceResponse(prev)
	}
	source, err := h.service.UpdateSource(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	updated := toTemplateSourceResponse(source)
	h.recordChange(r, h.logger, auditdom.ActionRuleSourceUpdated, auditdom.ResourceTypeTemplateSource, updated.ID, updated.Name,
		before, updated, auditdom.SeverityMedium, "Template source updated")

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

	var before any
	name := ""
	if prev, gerr := h.service.GetSource(r.Context(), tenantID, sourceID); gerr == nil {
		view := toTemplateSourceResponse(prev)
		before, name = view, view.Name
	}
	if err := h.service.DeleteSource(r.Context(), tenantID, sourceID); err != nil {
		h.handleServiceError(w, err)
		return
	}
	h.recordChange(r, h.logger, auditdom.ActionRuleSourceDeleted, auditdom.ResourceTypeTemplateSource, sourceID, name,
		before, nil, auditdom.SeverityMedium, "Template source deleted")

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
	h.recordChange(r, h.logger, auditdom.ActionRuleSourceUpdated, auditdom.ResourceTypeTemplateSource, sourceID, source.Name,
		map[string]any{"enabled": false}, map[string]any{"enabled": true}, auditdom.SeverityMedium, "Template source enabled")

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
	h.recordChange(r, h.logger, auditdom.ActionRuleSourceUpdated, auditdom.ResourceTypeTemplateSource, sourceID, source.Name,
		map[string]any{"enabled": true}, map[string]any{"enabled": false}, auditdom.SeverityMedium, "Template source disabled")

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
		GitConfig:       maskedGitConfig(s.GitConfig),
		S3Config:        s.S3Config,
		HTTPConfig:      maskedHTTPConfig(s.HTTPConfig),
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

// writeSyncError maps a failed force sync to its status: 404 for an unknown
// source, 400 for a refused request (domain error), 502 when the source
// itself could not be fetched (it answered 500 before), 500 otherwise.
func (h *TemplateSourceHandler) writeSyncError(w http.ResponseWriter, id string, err error) {
	var domainErr *shared.DomainError
	switch {
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("template source").WriteJSON(w)
	case errors.As(err, &domainErr):
		apierror.BadRequest(domainErr.Message).WriteJSON(w)
	case errors.Is(err, template.ErrSourceFetchFailed):
		h.logger.Warn("template source fetch failed", "error", err, "source_id", sanitizeLogField(id))
		apierror.BadGateway("The template source could not be fetched. Check its URL, branch or path, and credentials.").WriteJSON(w)
	default:
		h.logger.Error("failed to sync template source", "error", err, "source_id", sanitizeLogField(id))
		apierror.InternalServerError("failed to sync template source").WriteJSON(w)
	}
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
		h.writeSyncError(w, id, err)
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

// secretHeaderMask replaces a credential header value in responses.
const secretHeaderMask = "********"

// maskedGitConfig returns a copy with any password embedded in the URL
// hidden. Sources stored before the https/no-credentials rule may still hold
// "https://user:token@host/..."; viewers of the source must not read it.
func maskedGitConfig(c *ts.GitSourceConfig) *ts.GitSourceConfig {
	if c == nil {
		return nil
	}
	out := *c
	out.URL = ts.MaskedURL(c.URL)
	return &out
}

// maskedHTTPConfig returns a copy with credential headers and any password in
// the URL hidden (legacy rows; new ones are refused at write).
func maskedHTTPConfig(c *ts.HTTPSourceConfig) *ts.HTTPSourceConfig {
	if c == nil {
		return nil
	}
	out := *c
	out.URL = ts.MaskedURL(c.URL)
	if len(c.Headers) > 0 {
		out.Headers = make(map[string]string, len(c.Headers))
		for k, v := range c.Headers {
			if ts.IsSecretHeader(k) {
				v = secretHeaderMask
			}
			out.Headers[k] = v
		}
	}
	return &out
}
