package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/app/validators"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/scannertemplate"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/validator"
)

const (
	// maxTemplateRequestSize is the maximum request body size for template operations.
	// This prevents memory exhaustion attacks via large payloads.
	// Set to 2MB to accommodate base64-encoded templates (1MB content ~= 1.37MB base64).
	maxTemplateRequestSize = 2 * 1024 * 1024 // 2MB

	// errRequestBodyTooLarge is the error message for max bytes reader.
	errRequestBodyTooLarge = "http: request body too large"
)

// ScannerTemplateHandler handles HTTP requests for scanner templates.
type ScannerTemplateHandler struct {
	service   *app.ScannerTemplateService
	validator *validator.Validator
	logger    *logger.Logger
}

// NewScannerTemplateHandler creates a new ScannerTemplateHandler.
func NewScannerTemplateHandler(service *app.ScannerTemplateService, v *validator.Validator, log *logger.Logger) *ScannerTemplateHandler {
	return &ScannerTemplateHandler{
		service:   service,
		validator: v,
		logger:    log.With("handler", "scanner_template"),
	}
}

// CreateScannerTemplateRequest represents the request body for creating a template.
type CreateScannerTemplateRequest struct {
	Name         string   `json:"name" validate:"required,min=1,max=255"`
	TemplateType string   `json:"template_type" validate:"required,oneof=nuclei semgrep gitleaks"`
	Description  string   `json:"description" validate:"max=1000"`
	Content      string   `json:"content" validate:"required"` // Base64 encoded
	Tags         []string `json:"tags" validate:"max=20,dive,max=50"`
}

// UpdateScannerTemplateRequest represents the request body for updating a template.
type UpdateScannerTemplateRequest struct {
	Name        string   `json:"name" validate:"omitempty,min=1,max=255"`
	Description string   `json:"description" validate:"max=1000"`
	Content     string   `json:"content"` // Base64 encoded, optional
	Tags        []string `json:"tags" validate:"max=20,dive,max=50"`
}

// ValidateScannerTemplateRequest represents the request body for validating template content.
type ValidateScannerTemplateRequest struct {
	TemplateType string `json:"template_type" validate:"required,oneof=nuclei semgrep gitleaks"`
	Content      string `json:"content" validate:"required"` // Base64 encoded
}

// ScannerTemplateResponse represents the response for a scanner template.
type ScannerTemplateResponse struct {
	ID              string         `json:"id"`
	TenantID        string         `json:"tenant_id"`
	Name            string         `json:"name"`
	TemplateType    string         `json:"template_type"`
	Version         string         `json:"version"`
	ContentHash     string         `json:"content_hash"`
	RuleCount       int            `json:"rule_count"`
	Description     string         `json:"description,omitempty"`
	Tags            []string       `json:"tags"`
	Metadata        map[string]any `json:"metadata,omitempty"`
	Status          string         `json:"status"`
	ValidationError *string        `json:"validation_error,omitempty"`
	CreatedBy       *string        `json:"created_by,omitempty"`
	CreatedAt       string         `json:"created_at"`
	UpdatedAt       string         `json:"updated_at"`
}

// ValidationResultResponse represents the response for template validation.
type ValidationResultResponse struct {
	Valid     bool                      `json:"valid"`
	Errors    []ValidationErrorResponse `json:"errors,omitempty"`
	RuleCount int                       `json:"rule_count"`
	Metadata  map[string]any            `json:"metadata,omitempty"`
}

// ValidationErrorResponse represents a single validation error.
type ValidationErrorResponse struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	Code    string `json:"code"`
}

// Create handles POST /api/v1/scanner-templates
// @Summary      Create scanner template
// @Description  Create a new custom scanner template (Nuclei, Semgrep, or Gitleaks)
// @Tags         Scanner Templates
// @Accept       json
// @Produce      json
// @Param        body  body      CreateScannerTemplateRequest  true  "Template data"
// @Success      201   {object}  ScannerTemplateResponse
// @Failure      400   {object}  apierror.Error
// @Failure      409   {object}  apierror.Error
// @Failure      413   {object}  apierror.Error
// @Failure      500   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scanner-templates [post]
func (h *ScannerTemplateHandler) Create(w http.ResponseWriter, r *http.Request) {
	// Limit request body size to prevent memory exhaustion
	r.Body = http.MaxBytesReader(w, r.Body, maxTemplateRequestSize)

	var req CreateScannerTemplateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Check if this is a max bytes error
		if err.Error() == errRequestBodyTooLarge {
			apierror.New(http.StatusRequestEntityTooLarge, "Request body too large", "Maximum size is 2MB").WriteJSON(w)
			return
		}
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	tenantID := middleware.GetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())

	input := app.CreateScannerTemplateInput{
		TenantID:     tenantID,
		UserID:       userID,
		Name:         req.Name,
		TemplateType: req.TemplateType,
		Description:  req.Description,
		Content:      req.Content,
		Tags:         req.Tags,
	}

	template, err := h.service.CreateTemplate(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(toScannerTemplateResponse(template))
}

// Get handles GET /api/v1/scanner-templates/{id}
// @Summary      Get scanner template
// @Description  Get a single scanner template by ID
// @Tags         Scanner Templates
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Template ID"
// @Success      200  {object}  ScannerTemplateResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scanner-templates/{id} [get]
func (h *ScannerTemplateHandler) Get(w http.ResponseWriter, r *http.Request) {
	templateID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())

	template, err := h.service.GetTemplate(r.Context(), tenantID, templateID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toScannerTemplateResponse(template))
}

// List handles GET /api/v1/scanner-templates
// @Summary      List scanner templates
// @Description  Get a paginated list of scanner templates for the current tenant
// @Tags         Scanner Templates
// @Accept       json
// @Produce      json
// @Param        template_type  query     string   false  "Filter by template type (nuclei, semgrep, gitleaks)"
// @Param        status         query     string   false  "Filter by status (active, pending_review, deprecated, revoked)"
// @Param        tags           query     string   false  "Filter by tags (comma-separated)"
// @Param        search         query     string   false  "Search by name or description"
// @Param        page           query     int      false  "Page number" default(1)
// @Param        per_page       query     int      false  "Items per page" default(20)
// @Success      200  {object}  ListResponse[ScannerTemplateResponse]
// @Failure      400  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scanner-templates [get]
func (h *ScannerTemplateHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())

	input := app.ListScannerTemplatesInput{
		TenantID: tenantID,
		Search:   r.URL.Query().Get("search"),
		Page:     parseQueryInt(r.URL.Query().Get("page"), 1),
		PerPage:  parseQueryInt(r.URL.Query().Get("per_page"), 20),
	}

	if templateType := r.URL.Query().Get("template_type"); templateType != "" {
		input.TemplateType = &templateType
	}

	if status := r.URL.Query().Get("status"); status != "" {
		input.Status = &status
	}

	if tags := r.URL.Query().Get("tags"); tags != "" {
		input.Tags = parseQueryArray(tags)
	}

	result, err := h.service.ListTemplates(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	items := make([]*ScannerTemplateResponse, len(result.Data))
	for i, template := range result.Data {
		items[i] = toScannerTemplateResponse(template)
	}

	resp := map[string]any{
		"items":    items,
		"total":    result.Total,
		"page":     result.Page,
		"per_page": result.PerPage,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// Update handles PUT /api/v1/scanner-templates/{id}
// @Summary      Update scanner template
// @Description  Update an existing scanner template
// @Tags         Scanner Templates
// @Accept       json
// @Produce      json
// @Param        id    path      string                 true  "Template ID"
// @Param        body  body      UpdateScannerTemplateRequest  true  "Update data"
// @Success      200   {object}  ScannerTemplateResponse
// @Failure      400   {object}  apierror.Error
// @Failure      403   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Failure      413   {object}  apierror.Error
// @Failure      500   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scanner-templates/{id} [put]
func (h *ScannerTemplateHandler) Update(w http.ResponseWriter, r *http.Request) {
	templateID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())

	// Limit request body size to prevent memory exhaustion
	r.Body = http.MaxBytesReader(w, r.Body, maxTemplateRequestSize)

	var req UpdateScannerTemplateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		if err.Error() == errRequestBodyTooLarge {
			apierror.New(http.StatusRequestEntityTooLarge, "Request body too large", "Maximum size is 2MB").WriteJSON(w)
			return
		}
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := app.UpdateScannerTemplateInput{
		TenantID:    tenantID,
		TemplateID:  templateID,
		Name:        req.Name,
		Description: req.Description,
		Content:     req.Content,
		Tags:        req.Tags,
	}

	template, err := h.service.UpdateTemplate(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toScannerTemplateResponse(template))
}

// Delete handles DELETE /api/v1/scanner-templates/{id}
// @Summary      Delete scanner template
// @Description  Delete a scanner template
// @Tags         Scanner Templates
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Template ID"
// @Success      204  "No Content"
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scanner-templates/{id} [delete]
func (h *ScannerTemplateHandler) Delete(w http.ResponseWriter, r *http.Request) {
	templateID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())

	if err := h.service.DeleteTemplate(r.Context(), tenantID, templateID); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Validate handles POST /api/v1/scanner-templates/validate
// @Summary      Validate template content
// @Description  Validate scanner template content without saving
// @Tags         Scanner Templates
// @Accept       json
// @Produce      json
// @Param        body  body      ValidateScannerTemplateRequest  true  "Template content to validate"
// @Success      200   {object}  ValidationResultResponse
// @Failure      400   {object}  apierror.Error
// @Failure      413   {object}  apierror.Error
// @Failure      500   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scanner-templates/validate [post]
func (h *ScannerTemplateHandler) Validate(w http.ResponseWriter, r *http.Request) {
	// Limit request body size to prevent memory exhaustion
	r.Body = http.MaxBytesReader(w, r.Body, maxTemplateRequestSize)

	var req ValidateScannerTemplateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		if err.Error() == errRequestBodyTooLarge {
			apierror.New(http.StatusRequestEntityTooLarge, "Request body too large", "Maximum size is 2MB").WriteJSON(w)
			return
		}
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := app.ValidateTemplateInput{
		TemplateType: req.TemplateType,
		Content:      req.Content,
	}

	result, err := h.service.ValidateTemplate(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toValidationResultResponse(result))
}

// Download handles GET /api/v1/scanner-templates/{id}/download
// @Summary      Download template content
// @Description  Download the raw template content as a file
// @Tags         Scanner Templates
// @Produce      application/octet-stream
// @Param        id   path      string  true  "Template ID"
// @Success      200  {file}    binary
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scanner-templates/{id}/download [get]
func (h *ScannerTemplateHandler) Download(w http.ResponseWriter, r *http.Request) {
	templateID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())

	content, filename, err := h.service.DownloadTemplate(r.Context(), tenantID, templateID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+filename+"\"")
	w.Write(content)
}

// Deprecate handles POST /api/v1/scanner-templates/{id}/deprecate
// @Summary      Deprecate template
// @Description  Mark a scanner template as deprecated
// @Tags         Scanner Templates
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Template ID"
// @Success      200  {object}  ScannerTemplateResponse
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scanner-templates/{id}/deprecate [post]
func (h *ScannerTemplateHandler) Deprecate(w http.ResponseWriter, r *http.Request) {
	templateID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())

	template, err := h.service.DeprecateTemplate(r.Context(), tenantID, templateID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toScannerTemplateResponse(template))
}

// TemplateUsageResponse represents the response for template usage and quota.
type TemplateUsageResponse struct {
	Usage TemplateUsageData `json:"usage"`
	Quota TemplateQuotaData `json:"quota"`
}

// TemplateUsageData represents current template usage.
type TemplateUsageData struct {
	TotalTemplates    int64 `json:"total_templates"`
	NucleiTemplates   int64 `json:"nuclei_templates"`
	SemgrepTemplates  int64 `json:"semgrep_templates"`
	GitleaksTemplates int64 `json:"gitleaks_templates"`
	TotalStorageBytes int64 `json:"total_storage_bytes"`
}

// TemplateQuotaData represents quota limits.
type TemplateQuotaData struct {
	MaxTemplates         int   `json:"max_templates"`
	MaxTemplatesNuclei   int   `json:"max_templates_nuclei"`
	MaxTemplatesSemgrep  int   `json:"max_templates_semgrep"`
	MaxTemplatesGitleaks int   `json:"max_templates_gitleaks"`
	MaxTotalStorageBytes int64 `json:"max_total_storage_bytes"`
}

// GetUsage handles GET /api/v1/scanner-templates/usage
// @Summary      Get template usage and quota
// @Description  Get the current template usage and quota limits for the tenant
// @Tags         Scanner Templates
// @Produce      json
// @Success      200  {object}  TemplateUsageResponse
// @Failure      400  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scanner-templates/usage [get]
func (h *ScannerTemplateHandler) GetUsage(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())

	result, err := h.service.GetUsage(r.Context(), tenantID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	response := TemplateUsageResponse{
		Usage: TemplateUsageData{
			TotalTemplates:    result.Usage.TotalTemplates,
			NucleiTemplates:   result.Usage.NucleiTemplates,
			SemgrepTemplates:  result.Usage.SemgrepTemplates,
			GitleaksTemplates: result.Usage.GitleaksTemplates,
			TotalStorageBytes: result.Usage.TotalStorageBytes,
		},
		Quota: TemplateQuotaData{
			MaxTemplates:         result.Quota.MaxTemplates,
			MaxTemplatesNuclei:   result.Quota.MaxTemplatesNuclei,
			MaxTemplatesSemgrep:  result.Quota.MaxTemplatesSemgrep,
			MaxTemplatesGitleaks: result.Quota.MaxTemplatesGitleaks,
			MaxTotalStorageBytes: result.Quota.MaxTotalStorageBytes,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// toScannerTemplateResponse converts a scanner template entity to response.
func toScannerTemplateResponse(t *scannertemplate.ScannerTemplate) *ScannerTemplateResponse {
	resp := &ScannerTemplateResponse{
		ID:              t.ID.String(),
		TenantID:        t.TenantID.String(),
		Name:            t.Name,
		TemplateType:    string(t.TemplateType),
		Version:         t.Version,
		ContentHash:     t.ContentHash,
		RuleCount:       t.RuleCount,
		Description:     t.Description,
		Tags:            t.Tags,
		Metadata:        t.Metadata,
		Status:          string(t.Status),
		ValidationError: t.ValidationError,
		CreatedAt:       t.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:       t.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}

	if t.CreatedBy != nil {
		createdByStr := t.CreatedBy.String()
		resp.CreatedBy = &createdByStr
	}

	if resp.Tags == nil {
		resp.Tags = []string{}
	}

	if resp.Metadata == nil {
		resp.Metadata = make(map[string]any)
	}

	return resp
}

// toValidationResultResponse converts a validation result to response.
func toValidationResultResponse(r *validators.ValidationResult) *ValidationResultResponse {
	resp := &ValidationResultResponse{
		Valid:     r.Valid,
		RuleCount: r.RuleCount,
		Metadata:  r.Metadata,
	}

	if len(r.Errors) > 0 {
		resp.Errors = make([]ValidationErrorResponse, len(r.Errors))
		for i, e := range r.Errors {
			resp.Errors[i] = ValidationErrorResponse{
				Field:   e.Field,
				Message: e.Message,
				Code:    e.Code,
			}
		}
	}

	return resp
}

// handleValidationError converts validation errors to API errors.
func (h *ScannerTemplateHandler) handleValidationError(w http.ResponseWriter, err error) {
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

// handleServiceError converts service errors to API errors.
// Uses safe error messages to prevent information leakage.
func (h *ScannerTemplateHandler) handleServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Scanner template").WriteJSON(w)
	case errors.Is(err, shared.ErrAlreadyExists):
		apierror.Conflict("Scanner template already exists").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.SafeBadRequest(err).WriteJSON(w)
	case errors.Is(err, shared.ErrForbidden):
		apierror.Forbidden("Permission denied").WriteJSON(w)
	default:
		h.logger.Error("service error", "error", err)
		apierror.InternalError(err).WriteJSON(w)
	}
}
