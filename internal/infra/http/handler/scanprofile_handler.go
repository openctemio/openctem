package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/scanprofile"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/validator"
)

// ScanProfileHandler handles HTTP requests for scan profiles.
type ScanProfileHandler struct {
	service   *app.ScanProfileService
	validator *validator.Validator
	logger    *logger.Logger
}

// NewScanProfileHandler creates a new ScanProfileHandler.
func NewScanProfileHandler(service *app.ScanProfileService, v *validator.Validator, log *logger.Logger) *ScanProfileHandler {
	return &ScanProfileHandler{
		service:   service,
		validator: v,
		logger:    log.With("handler", "scan_profile"),
	}
}

// ToolConfigRequest represents tool configuration in request.
type ToolConfigRequest struct {
	Enabled           bool           `json:"enabled"`
	Severity          string         `json:"severity,omitempty"`
	Timeout           int            `json:"timeout,omitempty"`
	Options           map[string]any `json:"options,omitempty"`
	TemplateMode      string         `json:"template_mode,omitempty"`       // "default", "custom", "both"
	CustomTemplateIDs []string       `json:"custom_template_ids,omitempty"` // IDs of custom templates
}

// QualityGateRequest represents quality gate configuration in request.
type QualityGateRequest struct {
	Enabled         bool   `json:"enabled"`
	FailOnCritical  bool   `json:"fail_on_critical"`
	FailOnHigh      bool   `json:"fail_on_high"`
	MaxCritical     int    `json:"max_critical"`
	MaxHigh         int    `json:"max_high"`
	MaxMedium       int    `json:"max_medium"`
	MaxTotal        int    `json:"max_total"`
	NewFindingsOnly bool   `json:"new_findings_only,omitempty"`
	BaselineBranch  string `json:"baseline_branch,omitempty"`
}

// CreateScanProfileRequest represents the request body for creating a scan profile.
type CreateScanProfileRequest struct {
	Name               string                       `json:"name" validate:"required,min=1,max=100"`
	Description        string                       `json:"description" validate:"max=500"`
	ToolsConfig        map[string]ToolConfigRequest `json:"tools_config"`
	Intensity          string                       `json:"intensity" validate:"omitempty,oneof=low medium high"`
	MaxConcurrentScans int                          `json:"max_concurrent_scans" validate:"omitempty,min=1,max=100"`
	TimeoutSeconds     int                          `json:"timeout_seconds" validate:"omitempty,min=60,max=86400"`
	Tags               []string                     `json:"tags" validate:"max=20,dive,max=50"`
	IsDefault          bool                         `json:"is_default"`
	QualityGate        *QualityGateRequest          `json:"quality_gate,omitempty"`
}

// UpdateScanProfileRequest represents the request body for updating a scan profile.
type UpdateScanProfileRequest struct {
	Name               string                       `json:"name" validate:"omitempty,min=1,max=100"`
	Description        string                       `json:"description" validate:"max=500"`
	ToolsConfig        map[string]ToolConfigRequest `json:"tools_config"`
	Intensity          string                       `json:"intensity" validate:"omitempty,oneof=low medium high"`
	MaxConcurrentScans int                          `json:"max_concurrent_scans" validate:"omitempty,min=1,max=100"`
	TimeoutSeconds     int                          `json:"timeout_seconds" validate:"omitempty,min=60,max=86400"`
	Tags               []string                     `json:"tags" validate:"max=20,dive,max=50"`
	QualityGate        *QualityGateRequest          `json:"quality_gate,omitempty"`
}

// UpdateQualityGateRequest represents the request body for updating quality gate.
type UpdateQualityGateRequest struct {
	Enabled         bool   `json:"enabled"`
	FailOnCritical  bool   `json:"fail_on_critical"`
	FailOnHigh      bool   `json:"fail_on_high"`
	MaxCritical     int    `json:"max_critical"`
	MaxHigh         int    `json:"max_high"`
	MaxMedium       int    `json:"max_medium"`
	MaxTotal        int    `json:"max_total"`
	NewFindingsOnly bool   `json:"new_findings_only,omitempty"`
	BaselineBranch  string `json:"baseline_branch,omitempty"`
}

// CloneScanProfileRequest represents the request body for cloning a scan profile.
type CloneScanProfileRequest struct {
	NewName string `json:"new_name" validate:"required,min=1,max=100"`
}

// EvaluateQualityGateRequest represents the request body for evaluating quality gate.
type EvaluateQualityGateRequest struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// QualityGateResultResponse represents the result of quality gate evaluation.
type QualityGateResultResponse struct {
	Passed   bool                        `json:"passed"`
	Reason   string                      `json:"reason,omitempty"`
	Breaches []QualityGateBreachResponse `json:"breaches,omitempty"`
	Counts   FindingCountsResponse       `json:"counts"`
}

// QualityGateBreachResponse represents a single threshold violation.
type QualityGateBreachResponse struct {
	Metric string `json:"metric"`
	Limit  int    `json:"limit"`
	Actual int    `json:"actual"`
}

// FindingCountsResponse represents finding counts by severity.
type FindingCountsResponse struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
	Total    int `json:"total"`
}

// QualityGateResponse represents quality gate configuration in response.
type QualityGateResponse struct {
	Enabled         bool   `json:"enabled"`
	FailOnCritical  bool   `json:"fail_on_critical"`
	FailOnHigh      bool   `json:"fail_on_high"`
	MaxCritical     int    `json:"max_critical"`
	MaxHigh         int    `json:"max_high"`
	MaxMedium       int    `json:"max_medium"`
	MaxTotal        int    `json:"max_total"`
	NewFindingsOnly bool   `json:"new_findings_only,omitempty"`
	BaselineBranch  string `json:"baseline_branch,omitempty"`
}

// ScanProfileResponse represents the response for a scan profile.
type ScanProfileResponse struct {
	ID                 string                        `json:"id"`
	TenantID           string                        `json:"tenant_id"`
	Name               string                        `json:"name"`
	Description        string                        `json:"description,omitempty"`
	IsDefault          bool                          `json:"is_default"`
	IsSystem           bool                          `json:"is_system"`
	ToolsConfig        map[string]ToolConfigResponse `json:"tools_config"`
	Intensity          string                        `json:"intensity"`
	MaxConcurrentScans int                           `json:"max_concurrent_scans"`
	TimeoutSeconds     int                           `json:"timeout_seconds"`
	Tags               []string                      `json:"tags"`
	Metadata           map[string]any                `json:"metadata,omitempty"`
	QualityGate        QualityGateResponse           `json:"quality_gate"`
	CreatedBy          *string                       `json:"created_by,omitempty"`
	CreatedAt          string                        `json:"created_at"`
	UpdatedAt          string                        `json:"updated_at"`
}

// ToolConfigResponse represents tool configuration in response.
type ToolConfigResponse struct {
	Enabled           bool           `json:"enabled"`
	Severity          string         `json:"severity,omitempty"`
	Timeout           int            `json:"timeout,omitempty"`
	Options           map[string]any `json:"options,omitempty"`
	TemplateMode      string         `json:"template_mode,omitempty"`       // "default", "custom", "both"
	CustomTemplateIDs []string       `json:"custom_template_ids,omitempty"` // IDs of custom templates
}

// Create handles POST /api/v1/scan-profiles
// @Summary      Create scan profile
// @Description  Create a new scan profile with tool configurations
// @Tags         Scan Profiles
// @Accept       json
// @Produce      json
// @Param        body  body      CreateScanProfileRequest  true  "Scan profile data"
// @Success      201   {object}  ScanProfileResponse
// @Failure      400   {object}  apierror.Error
// @Failure      409   {object}  apierror.Error
// @Failure      500   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scan-profiles [post]
func (h *ScanProfileHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req CreateScanProfileRequest
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

	input := app.CreateScanProfileInput{
		TenantID:           tenantID,
		UserID:             userID,
		Name:               req.Name,
		Description:        req.Description,
		ToolsConfig:        toToolsConfigDomain(req.ToolsConfig),
		Intensity:          req.Intensity,
		MaxConcurrentScans: req.MaxConcurrentScans,
		TimeoutSeconds:     req.TimeoutSeconds,
		Tags:               req.Tags,
		IsDefault:          req.IsDefault,
		QualityGate:        toQualityGateDomain(req.QualityGate),
	}

	profile, err := h.service.CreateScanProfile(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(toScanProfileResponse(profile))
}

// Get handles GET /api/v1/scan-profiles/{id}
// @Summary      Get scan profile
// @Description  Get a single scan profile by ID
// @Tags         Scan Profiles
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Scan Profile ID"
// @Success      200  {object}  ScanProfileResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scan-profiles/{id} [get]
func (h *ScanProfileHandler) Get(w http.ResponseWriter, r *http.Request) {
	profileID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())

	profile, err := h.service.GetScanProfile(r.Context(), tenantID, profileID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toScanProfileResponse(profile))
}

// GetDefault handles GET /api/v1/scan-profiles/default
// @Summary      Get default scan profile
// @Description  Get the default scan profile for the current tenant
// @Tags         Scan Profiles
// @Accept       json
// @Produce      json
// @Success      200  {object}  ScanProfileResponse
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scan-profiles/default [get]
func (h *ScanProfileHandler) GetDefault(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())

	profile, err := h.service.GetDefaultScanProfile(r.Context(), tenantID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toScanProfileResponse(profile))
}

// List handles GET /api/v1/scan-profiles
// @Summary      List scan profiles
// @Description  Get a paginated list of scan profiles for the current tenant
// @Tags         Scan Profiles
// @Accept       json
// @Produce      json
// @Param        is_default      query     boolean  false  "Filter by default status"
// @Param        is_system       query     boolean  false  "Filter by system status"
// @Param        include_system  query     boolean  false  "Include system profiles in results (default: true)"
// @Param        tags            query     string   false  "Filter by tags (comma-separated)"
// @Param        search          query     string   false  "Search by name or description"
// @Param        page            query     int      false  "Page number" default(1)
// @Param        per_page        query     int      false  "Items per page" default(20)
// @Success      200  {object}  ListResponse[ScanProfileResponse]
// @Failure      400  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scan-profiles [get]
func (h *ScanProfileHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())

	// Default to include system profiles unless explicitly set to false
	includeSystem := true
	if includeSystemParam := r.URL.Query().Get("include_system"); includeSystemParam == "false" {
		includeSystem = false
	}

	input := app.ListScanProfilesInput{
		TenantID:      tenantID,
		Search:        r.URL.Query().Get("search"),
		Page:          parseQueryInt(r.URL.Query().Get("page"), 1),
		PerPage:       parseQueryInt(r.URL.Query().Get("per_page"), 20),
		IncludeSystem: includeSystem,
	}

	if isDefault := r.URL.Query().Get("is_default"); isDefault != "" {
		val := isDefault == queryParamTrue
		input.IsDefault = &val
	}

	if isSystem := r.URL.Query().Get("is_system"); isSystem != "" {
		val := isSystem == queryParamTrue
		input.IsSystem = &val
	}

	if tags := r.URL.Query().Get("tags"); tags != "" {
		input.Tags = parseQueryArray(tags)
	}

	result, err := h.service.ListScanProfiles(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	items := make([]*ScanProfileResponse, len(result.Data))
	for i, profile := range result.Data {
		items[i] = toScanProfileResponse(profile)
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

// Update handles PUT /api/v1/scan-profiles/{id}
// @Summary      Update scan profile
// @Description  Update an existing scan profile
// @Tags         Scan Profiles
// @Accept       json
// @Produce      json
// @Param        id    path      string                    true  "Scan Profile ID"
// @Param        body  body      UpdateScanProfileRequest  true  "Update data"
// @Success      200   {object}  ScanProfileResponse
// @Failure      400   {object}  apierror.Error
// @Failure      403   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Failure      500   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scan-profiles/{id} [put]
func (h *ScanProfileHandler) Update(w http.ResponseWriter, r *http.Request) {
	profileID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())

	var req UpdateScanProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := app.UpdateScanProfileInput{
		TenantID:           tenantID,
		ProfileID:          profileID,
		Name:               req.Name,
		Description:        req.Description,
		ToolsConfig:        toToolsConfigDomain(req.ToolsConfig),
		Intensity:          req.Intensity,
		MaxConcurrentScans: req.MaxConcurrentScans,
		TimeoutSeconds:     req.TimeoutSeconds,
		Tags:               req.Tags,
		QualityGate:        toQualityGateDomain(req.QualityGate),
	}

	profile, err := h.service.UpdateScanProfile(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toScanProfileResponse(profile))
}

// Delete handles DELETE /api/v1/scan-profiles/{id}
// @Summary      Delete scan profile
// @Description  Delete a scan profile (system profiles cannot be deleted)
// @Tags         Scan Profiles
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Scan Profile ID"
// @Success      204  "No Content"
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scan-profiles/{id} [delete]
func (h *ScanProfileHandler) Delete(w http.ResponseWriter, r *http.Request) {
	profileID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())

	if err := h.service.DeleteScanProfile(r.Context(), tenantID, profileID); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// SetDefault handles POST /api/v1/scan-profiles/{id}/set-default
// @Summary      Set default scan profile
// @Description  Set a scan profile as the default for the tenant
// @Tags         Scan Profiles
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Scan Profile ID"
// @Success      200  {object}  ScanProfileResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scan-profiles/{id}/set-default [post]
func (h *ScanProfileHandler) SetDefault(w http.ResponseWriter, r *http.Request) {
	profileID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())

	profile, err := h.service.SetDefaultScanProfile(r.Context(), tenantID, profileID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toScanProfileResponse(profile))
}

// Clone handles POST /api/v1/scan-profiles/{id}/clone
// @Summary      Clone scan profile
// @Description  Create a copy of an existing scan profile with a new name
// @Tags         Scan Profiles
// @Accept       json
// @Produce      json
// @Param        id    path      string                   true  "Scan Profile ID to clone"
// @Param        body  body      CloneScanProfileRequest  true  "Clone data"
// @Success      201   {object}  ScanProfileResponse
// @Failure      400   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Failure      409   {object}  apierror.Error
// @Failure      500   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scan-profiles/{id}/clone [post]
func (h *ScanProfileHandler) Clone(w http.ResponseWriter, r *http.Request) {
	profileID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())

	var req CloneScanProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := app.CloneScanProfileInput{
		TenantID:  tenantID,
		ProfileID: profileID,
		NewName:   req.NewName,
		UserID:    userID,
	}

	profile, err := h.service.CloneScanProfile(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(toScanProfileResponse(profile))
}

// UpdateQualityGate handles PUT /api/v1/scan-profiles/{id}/quality-gate
// @Summary      Update quality gate
// @Description  Update the quality gate configuration for a scan profile
// @Tags         Scan Profiles
// @Accept       json
// @Produce      json
// @Param        id    path      string                    true  "Scan Profile ID"
// @Param        body  body      UpdateQualityGateRequest  true  "Quality gate configuration"
// @Success      200   {object}  ScanProfileResponse
// @Failure      400   {object}  apierror.Error
// @Failure      403   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Failure      500   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scan-profiles/{id}/quality-gate [put]
func (h *ScanProfileHandler) UpdateQualityGate(w http.ResponseWriter, r *http.Request) {
	profileID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())

	var req UpdateQualityGateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	input := app.UpdateQualityGateInput{
		TenantID:  tenantID,
		ProfileID: profileID,
		QualityGate: scanprofile.QualityGate{
			Enabled:         req.Enabled,
			FailOnCritical:  req.FailOnCritical,
			FailOnHigh:      req.FailOnHigh,
			MaxCritical:     req.MaxCritical,
			MaxHigh:         req.MaxHigh,
			MaxMedium:       req.MaxMedium,
			MaxTotal:        req.MaxTotal,
			NewFindingsOnly: req.NewFindingsOnly,
			BaselineBranch:  req.BaselineBranch,
		},
	}

	profile, err := h.service.UpdateQualityGate(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toScanProfileResponse(profile))
}

// EvaluateQualityGate handles POST /api/v1/scan-profiles/{id}/evaluate-quality-gate
// @Summary      Evaluate quality gate
// @Description  Evaluate finding counts against a scan profile's quality gate
// @Tags         Scan Profiles
// @Accept       json
// @Produce      json
// @Param        id    path      string                       true  "Scan Profile ID"
// @Param        body  body      EvaluateQualityGateRequest   true  "Finding counts"
// @Success      200   {object}  QualityGateResultResponse
// @Failure      400   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Failure      500   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scan-profiles/{id}/evaluate-quality-gate [post]
func (h *ScanProfileHandler) EvaluateQualityGate(w http.ResponseWriter, r *http.Request) {
	profileID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())

	var req EvaluateQualityGateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	counts := scanprofile.FindingCounts{
		Critical: req.Critical,
		High:     req.High,
		Medium:   req.Medium,
		Low:      req.Low,
		Info:     req.Info,
		Total:    req.Critical + req.High + req.Medium + req.Low + req.Info,
	}

	input := app.EvaluateQualityGateInput{
		TenantID:  tenantID,
		ProfileID: profileID,
		Counts:    counts,
	}

	result, err := h.service.EvaluateQualityGate(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toQualityGateResultResponse(result))
}

// toQualityGateResultResponse converts domain QualityGateResult to response format.
func toQualityGateResultResponse(result *scanprofile.QualityGateResult) *QualityGateResultResponse {
	resp := &QualityGateResultResponse{
		Passed: result.Passed,
		Reason: result.Reason,
		Counts: FindingCountsResponse{
			Critical: result.Counts.Critical,
			High:     result.Counts.High,
			Medium:   result.Counts.Medium,
			Low:      result.Counts.Low,
			Info:     result.Counts.Info,
			Total:    result.Counts.Total,
		},
	}

	if len(result.Breaches) > 0 {
		resp.Breaches = make([]QualityGateBreachResponse, len(result.Breaches))
		for i, b := range result.Breaches {
			resp.Breaches[i] = QualityGateBreachResponse{
				Metric: b.Metric,
				Limit:  b.Limit,
				Actual: b.Actual,
			}
		}
	}

	return resp
}

// toScanProfileResponse converts a scan profile entity to response.
func toScanProfileResponse(p *scanprofile.ScanProfile) *ScanProfileResponse {
	resp := &ScanProfileResponse{
		ID:                 p.ID.String(),
		TenantID:           p.TenantID.String(),
		Name:               p.Name,
		Description:        p.Description,
		IsDefault:          p.IsDefault,
		IsSystem:           p.IsSystem,
		ToolsConfig:        toToolsConfigResponse(p.ToolsConfig),
		Intensity:          string(p.Intensity),
		MaxConcurrentScans: p.MaxConcurrentScans,
		TimeoutSeconds:     p.TimeoutSeconds,
		Tags:               p.Tags,
		Metadata:           p.Metadata,
		QualityGate:        toQualityGateResponse(p.QualityGate),
		CreatedAt:          p.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:          p.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}

	if p.CreatedBy != nil {
		createdByStr := p.CreatedBy.String()
		resp.CreatedBy = &createdByStr
	}

	if resp.Tags == nil {
		resp.Tags = []string{}
	}

	if resp.ToolsConfig == nil {
		resp.ToolsConfig = make(map[string]ToolConfigResponse)
	}

	return resp
}

// toToolsConfigResponse converts domain ToolsConfig to response format.
func toToolsConfigResponse(config map[string]scanprofile.ToolConfig) map[string]ToolConfigResponse {
	if config == nil {
		return make(map[string]ToolConfigResponse)
	}

	result := make(map[string]ToolConfigResponse, len(config))
	for k, v := range config {
		result[k] = ToolConfigResponse{
			Enabled:           v.Enabled,
			Severity:          v.Severity,
			Timeout:           v.Timeout,
			Options:           v.Options,
			TemplateMode:      string(v.TemplateMode),
			CustomTemplateIDs: v.CustomTemplateIDs,
		}
	}
	return result
}

// toToolsConfigDomain converts request ToolsConfig to domain format.
func toToolsConfigDomain(config map[string]ToolConfigRequest) map[string]scanprofile.ToolConfig {
	if config == nil {
		return nil
	}

	result := make(map[string]scanprofile.ToolConfig, len(config))
	for k, v := range config {
		result[k] = scanprofile.ToolConfig{
			Enabled:           v.Enabled,
			Severity:          v.Severity,
			Timeout:           v.Timeout,
			Options:           v.Options,
			TemplateMode:      scanprofile.TemplateMode(v.TemplateMode),
			CustomTemplateIDs: v.CustomTemplateIDs,
		}
	}
	return result
}

// toQualityGateDomain converts request QualityGate to domain format.
func toQualityGateDomain(req *QualityGateRequest) *scanprofile.QualityGate {
	if req == nil {
		return nil
	}

	return &scanprofile.QualityGate{
		Enabled:         req.Enabled,
		FailOnCritical:  req.FailOnCritical,
		FailOnHigh:      req.FailOnHigh,
		MaxCritical:     req.MaxCritical,
		MaxHigh:         req.MaxHigh,
		MaxMedium:       req.MaxMedium,
		MaxTotal:        req.MaxTotal,
		NewFindingsOnly: req.NewFindingsOnly,
		BaselineBranch:  req.BaselineBranch,
	}
}

// toQualityGateResponse converts domain QualityGate to response format.
func toQualityGateResponse(gate scanprofile.QualityGate) QualityGateResponse {
	return QualityGateResponse{
		Enabled:         gate.Enabled,
		FailOnCritical:  gate.FailOnCritical,
		FailOnHigh:      gate.FailOnHigh,
		MaxCritical:     gate.MaxCritical,
		MaxHigh:         gate.MaxHigh,
		MaxMedium:       gate.MaxMedium,
		MaxTotal:        gate.MaxTotal,
		NewFindingsOnly: gate.NewFindingsOnly,
		BaselineBranch:  gate.BaselineBranch,
	}
}

// handleValidationError converts validation errors to API errors.
func (h *ScanProfileHandler) handleValidationError(w http.ResponseWriter, err error) {
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
func (h *ScanProfileHandler) handleServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Scan profile").WriteJSON(w)
	case errors.Is(err, shared.ErrAlreadyExists):
		apierror.Conflict("Scan profile already exists").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	case errors.Is(err, shared.ErrUnauthorized):
		apierror.Unauthorized("").WriteJSON(w)
	case errors.Is(err, shared.ErrForbidden):
		apierror.Forbidden("System profiles cannot be modified").WriteJSON(w)
	default:
		h.logger.Error("service error", "error", err)
		apierror.InternalError(err).WriteJSON(w)
	}
}
