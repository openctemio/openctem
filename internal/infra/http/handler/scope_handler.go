package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/scope"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/validator"
)

// ScopeHandler handles scope configuration HTTP requests.
type ScopeHandler struct {
	service   *app.ScopeService
	validator *validator.Validator
	logger    *logger.Logger
}

// NewScopeHandler creates a new scope handler.
func NewScopeHandler(svc *app.ScopeService, v *validator.Validator, log *logger.Logger) *ScopeHandler {
	return &ScopeHandler{
		service:   svc,
		validator: v,
		logger:    log,
	}
}

// =============================================================================
// Response Types
// =============================================================================

// ScopeTargetResponse represents a scope target in API responses.
type ScopeTargetResponse struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	TargetType  string    `json:"target_type"`
	Pattern     string    `json:"pattern"`
	Description string    `json:"description,omitempty"`
	Priority    int       `json:"priority"`
	Status      string    `json:"status"`
	Tags        []string  `json:"tags,omitempty"`
	CreatedBy   string    `json:"created_by,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// ScopeExclusionResponse represents a scope exclusion in API responses.
type ScopeExclusionResponse struct {
	ID            string     `json:"id"`
	TenantID      string     `json:"tenant_id"`
	ExclusionType string     `json:"exclusion_type"`
	Pattern       string     `json:"pattern"`
	Reason        string     `json:"reason"`
	Status        string     `json:"status"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	ApprovedBy    string     `json:"approved_by,omitempty"`
	ApprovedAt    *time.Time `json:"approved_at,omitempty"`
	CreatedBy     string     `json:"created_by,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

// ScanScheduleResponse represents a scan schedule in API responses.
type ScanScheduleResponse struct {
	ID                   string                 `json:"id"`
	TenantID             string                 `json:"tenant_id"`
	Name                 string                 `json:"name"`
	Description          string                 `json:"description,omitempty"`
	ScanType             string                 `json:"scan_type"`
	TargetScope          string                 `json:"target_scope"`
	TargetIDs            []string               `json:"target_ids,omitempty"`
	TargetTags           []string               `json:"target_tags,omitempty"`
	ScannerConfigs       map[string]interface{} `json:"scanner_configs,omitempty"`
	ScheduleType         string                 `json:"schedule_type"`
	CronExpression       string                 `json:"cron_expression,omitempty"`
	IntervalHours        int                    `json:"interval_hours,omitempty"`
	Enabled              bool                   `json:"enabled"`
	LastRunAt            *time.Time             `json:"last_run_at,omitempty"`
	LastRunStatus        string                 `json:"last_run_status,omitempty"`
	NextRunAt            *time.Time             `json:"next_run_at,omitempty"`
	NotifyOnCompletion   bool                   `json:"notify_on_completion"`
	NotifyOnFindings     bool                   `json:"notify_on_findings"`
	NotificationChannels []string               `json:"notification_channels,omitempty"`
	CreatedBy            string                 `json:"created_by,omitempty"`
	CreatedAt            time.Time              `json:"created_at"`
	UpdatedAt            time.Time              `json:"updated_at"`
}

// ScopeStatsResponse represents scope statistics in API responses.
type ScopeStatsResponse struct {
	TotalTargets     int64   `json:"total_targets"`
	ActiveTargets    int64   `json:"active_targets"`
	TotalExclusions  int64   `json:"total_exclusions"`
	ActiveExclusions int64   `json:"active_exclusions"`
	TotalSchedules   int64   `json:"total_schedules"`
	EnabledSchedules int64   `json:"enabled_schedules"`
	Coverage         float64 `json:"coverage"`
}

// ScopeMatchResponse represents scope matching result in API responses.
type ScopeMatchResponse struct {
	InScope             bool     `json:"in_scope"`
	Excluded            bool     `json:"excluded"`
	MatchedTargetIDs    []string `json:"matched_target_ids,omitempty"`
	MatchedExclusionIDs []string `json:"matched_exclusion_ids,omitempty"`
}

// =============================================================================
// Request Types
// =============================================================================

// CreateScopeTargetRequest represents the request to create a scope target.
type CreateScopeTargetRequest struct {
	TargetType  string   `json:"target_type" validate:"required"`
	Pattern     string   `json:"pattern" validate:"required,max=500"`
	Description string   `json:"description" validate:"max=1000"`
	Priority    int      `json:"priority" validate:"min=0,max=100"`
	Tags        []string `json:"tags" validate:"max=20,dive,max=50"`
}

// UpdateScopeTargetRequest represents the request to update a scope target.
type UpdateScopeTargetRequest struct {
	Description *string  `json:"description" validate:"omitempty,max=1000"`
	Priority    *int     `json:"priority" validate:"omitempty,min=0,max=100"`
	Tags        []string `json:"tags" validate:"omitempty,max=20,dive,max=50"`
}

// CreateScopeExclusionRequest represents the request to create a scope exclusion.
type CreateScopeExclusionRequest struct {
	ExclusionType string     `json:"exclusion_type" validate:"required"`
	Pattern       string     `json:"pattern" validate:"required,max=500"`
	Reason        string     `json:"reason" validate:"required,max=1000"`
	ExpiresAt     *time.Time `json:"expires_at"`
}

// UpdateScopeExclusionRequest represents the request to update a scope exclusion.
type UpdateScopeExclusionRequest struct {
	Reason    *string    `json:"reason" validate:"omitempty,max=1000"`
	ExpiresAt *time.Time `json:"expires_at"`
}

// CreateScanScheduleRequest represents the request to create a scan schedule.
type CreateScanScheduleRequest struct {
	Name                 string                 `json:"name" validate:"required,min=1,max=200"`
	Description          string                 `json:"description" validate:"max=1000"`
	ScanType             string                 `json:"scan_type" validate:"required"`
	TargetScope          string                 `json:"target_scope"`
	TargetIDs            []string               `json:"target_ids" validate:"max=100"`
	TargetTags           []string               `json:"target_tags" validate:"max=20,dive,max=50"`
	ScannerConfigs       map[string]interface{} `json:"scanner_configs"`
	ScheduleType         string                 `json:"schedule_type" validate:"required"`
	CronExpression       string                 `json:"cron_expression" validate:"max=100"`
	IntervalHours        int                    `json:"interval_hours" validate:"min=0,max=8760"`
	NotifyOnCompletion   bool                   `json:"notify_on_completion"`
	NotifyOnFindings     bool                   `json:"notify_on_findings"`
	NotificationChannels []string               `json:"notification_channels" validate:"max=10,dive,max=50"`
}

// UpdateScanScheduleRequest represents the request to update a scan schedule.
type UpdateScanScheduleRequest struct {
	Name                 *string                `json:"name" validate:"omitempty,min=1,max=200"`
	Description          *string                `json:"description" validate:"omitempty,max=1000"`
	TargetScope          *string                `json:"target_scope"`
	TargetIDs            []string               `json:"target_ids" validate:"omitempty,max=100"`
	TargetTags           []string               `json:"target_tags" validate:"omitempty,max=20,dive,max=50"`
	ScannerConfigs       map[string]interface{} `json:"scanner_configs"`
	ScheduleType         *string                `json:"schedule_type"`
	CronExpression       *string                `json:"cron_expression" validate:"omitempty,max=100"`
	IntervalHours        *int                   `json:"interval_hours" validate:"omitempty,min=0,max=8760"`
	NotifyOnCompletion   *bool                  `json:"notify_on_completion"`
	NotifyOnFindings     *bool                  `json:"notify_on_findings"`
	NotificationChannels []string               `json:"notification_channels" validate:"omitempty,max=10,dive,max=50"`
}

// CheckScopeRequest represents the request to check scope matching.
type CheckScopeRequest struct {
	AssetType string `json:"asset_type" validate:"required"`
	Value     string `json:"value" validate:"required"`
}

// =============================================================================
// Conversion Functions
// =============================================================================

func toScopeTargetResponse(t *scope.Target) ScopeTargetResponse {
	return ScopeTargetResponse{
		ID:          t.ID().String(),
		TenantID:    t.TenantID().String(),
		TargetType:  t.TargetType().String(),
		Pattern:     t.Pattern(),
		Description: t.Description(),
		Priority:    t.Priority(),
		Status:      t.Status().String(),
		Tags:        t.Tags(),
		CreatedBy:   t.CreatedBy(),
		CreatedAt:   t.CreatedAt(),
		UpdatedAt:   t.UpdatedAt(),
	}
}

func toScopeExclusionResponse(e *scope.Exclusion) ScopeExclusionResponse {
	return ScopeExclusionResponse{
		ID:            e.ID().String(),
		TenantID:      e.TenantID().String(),
		ExclusionType: e.ExclusionType().String(),
		Pattern:       e.Pattern(),
		Reason:        e.Reason(),
		Status:        e.Status().String(),
		ExpiresAt:     e.ExpiresAt(),
		ApprovedBy:    e.ApprovedBy(),
		ApprovedAt:    e.ApprovedAt(),
		CreatedBy:     e.CreatedBy(),
		CreatedAt:     e.CreatedAt(),
		UpdatedAt:     e.UpdatedAt(),
	}
}

func toScanScheduleResponse(s *scope.Schedule) ScanScheduleResponse {
	targetIDs := make([]string, len(s.TargetIDs()))
	for i, id := range s.TargetIDs() {
		targetIDs[i] = id.String()
	}

	return ScanScheduleResponse{
		ID:                   s.ID().String(),
		TenantID:             s.TenantID().String(),
		Name:                 s.Name(),
		Description:          s.Description(),
		ScanType:             s.ScanType().String(),
		TargetScope:          s.TargetScope().String(),
		TargetIDs:            targetIDs,
		TargetTags:           s.TargetTags(),
		ScannerConfigs:       s.ScannerConfigs(),
		ScheduleType:         s.ScheduleType().String(),
		CronExpression:       s.CronExpression(),
		IntervalHours:        s.IntervalHours(),
		Enabled:              s.Enabled(),
		LastRunAt:            s.LastRunAt(),
		LastRunStatus:        s.LastRunStatus(),
		NextRunAt:            s.NextRunAt(),
		NotifyOnCompletion:   s.NotifyOnCompletion(),
		NotifyOnFindings:     s.NotifyOnFindings(),
		NotificationChannels: s.NotificationChannels(),
		CreatedBy:            s.CreatedBy(),
		CreatedAt:            s.CreatedAt(),
		UpdatedAt:            s.UpdatedAt(),
	}
}

// =============================================================================
// Error Handling
// =============================================================================

func (h *ScopeHandler) handleValidationError(w http.ResponseWriter, err error) {
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

func (h *ScopeHandler) handleServiceError(w http.ResponseWriter, resource string, err error) {
	switch {
	case errors.Is(err, shared.ErrNotFound),
		errors.Is(err, scope.ErrTargetNotFound),
		errors.Is(err, scope.ErrExclusionNotFound),
		errors.Is(err, scope.ErrScheduleNotFound):
		apierror.NotFound(resource).WriteJSON(w)
	case errors.Is(err, shared.ErrAlreadyExists),
		errors.Is(err, scope.ErrTargetAlreadyExists),
		errors.Is(err, scope.ErrExclusionAlreadyExists),
		errors.Is(err, scope.ErrScheduleAlreadyExists):
		apierror.Conflict(resource + " already exists").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	default:
		h.logger.Error("service error", "error", err)
		apierror.InternalError(err).WriteJSON(w)
	}
}

// =============================================================================
// Target Handlers
// =============================================================================

// ListTargets handles GET /api/v1/scope/targets
// @Summary      List scope targets
// @Description  Get a paginated list of scope targets for the current tenant
// @Tags         Scope
// @Accept       json
// @Produce      json
// @Param        types     query     string  false  "Filter by target types (comma-separated)"
// @Param        statuses  query     string  false  "Filter by statuses (comma-separated)"
// @Param        tags      query     string  false  "Filter by tags (comma-separated)"
// @Param        search    query     string  false  "Search by pattern"
// @Param        page      query     int     false  "Page number" default(1)
// @Param        per_page  query     int     false  "Items per page" default(20)
// @Success      200  {object}  ListResponse[ScopeTargetResponse]
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scope/targets [get]
func (h *ScopeHandler) ListTargets(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	query := r.URL.Query()

	input := app.ListTargetsInput{
		TenantID:    tenantID,
		TargetTypes: parseQueryArray(query.Get("types")),
		Statuses:    parseQueryArray(query.Get("statuses")),
		Tags:        parseQueryArray(query.Get("tags")),
		Search:      query.Get("search"),
		Page:        parseQueryInt(query.Get("page"), 1),
		PerPage:     parseQueryInt(query.Get("per_page"), 20),
	}

	result, err := h.service.ListTargets(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, "Scope target", err)
		return
	}

	responses := make([]ScopeTargetResponse, len(result.Data))
	for i, target := range result.Data {
		responses[i] = toScopeTargetResponse(target)
	}

	response := ListResponse[ScopeTargetResponse]{
		Data:       responses,
		Total:      result.Total,
		Page:       result.Page,
		PerPage:    result.PerPage,
		TotalPages: result.TotalPages,
		Links:      NewPaginationLinks(r, result.Page, result.PerPage, result.TotalPages),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// CreateTarget handles POST /api/v1/scope/targets
// @Summary      Create scope target
// @Description  Create a new scope target
// @Tags         Scope
// @Accept       json
// @Produce      json
// @Param        body  body      CreateScopeTargetRequest  true  "Scope target data"
// @Success      201   {object}  ScopeTargetResponse
// @Failure      400   {object}  apierror.Error
// @Failure      409   {object}  apierror.Error
// @Failure      500   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scope/targets [post]
func (h *ScopeHandler) CreateTarget(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())

	var req CreateScopeTargetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid JSON").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := app.CreateTargetInput{
		TenantID:    tenantID,
		TargetType:  req.TargetType,
		Pattern:     req.Pattern,
		Description: req.Description,
		Priority:    req.Priority,
		Tags:        req.Tags,
		CreatedBy:   userID,
	}

	target, err := h.service.CreateTarget(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, "Scope target", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(toScopeTargetResponse(target))
}

// GetTarget handles GET /api/v1/scope/targets/{id}
// @Summary      Get scope target
// @Description  Get a single scope target by ID
// @Tags         Scope
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Target ID"
// @Success      200  {object}  ScopeTargetResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scope/targets/{id} [get]
func (h *ScopeHandler) GetTarget(w http.ResponseWriter, r *http.Request) {
	targetID := chi.URLParam(r, "id")

	target, err := h.service.GetTarget(r.Context(), targetID)
	if err != nil {
		h.handleServiceError(w, "Scope target", err)
		return
	}

	// Verify tenant ownership
	tenantID := middleware.MustGetTenantID(r.Context())
	if target.TenantID().String() != tenantID {
		apierror.NotFound("Scope target").WriteJSON(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toScopeTargetResponse(target))
}

// UpdateTarget handles PUT /api/v1/scope/targets/{id}
// @Summary      Update scope target
// @Description  Update an existing scope target
// @Tags         Scope
// @Accept       json
// @Produce      json
// @Param        id    path      string                    true  "Target ID"
// @Param        body  body      UpdateScopeTargetRequest  true  "Update data"
// @Success      200   {object}  ScopeTargetResponse
// @Failure      400   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Failure      500   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scope/targets/{id} [put]
func (h *ScopeHandler) UpdateTarget(w http.ResponseWriter, r *http.Request) {
	targetID := chi.URLParam(r, "id")
	tenantID := middleware.MustGetTenantID(r.Context())

	var req UpdateScopeTargetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid JSON").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := app.UpdateTargetInput{
		Description: req.Description,
		Priority:    req.Priority,
		Tags:        req.Tags,
	}

	target, err := h.service.UpdateTarget(r.Context(), targetID, tenantID, input)
	if err != nil {
		h.handleServiceError(w, "Scope target", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toScopeTargetResponse(target))
}

// DeleteTarget handles DELETE /api/v1/scope/targets/{id}
// @Summary      Delete scope target
// @Description  Delete a scope target
// @Tags         Scope
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Target ID"
// @Success      204  "No Content"
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scope/targets/{id} [delete]
func (h *ScopeHandler) DeleteTarget(w http.ResponseWriter, r *http.Request) {
	targetID := chi.URLParam(r, "id")
	tenantID := middleware.MustGetTenantID(r.Context())

	if err := h.service.DeleteTarget(r.Context(), targetID, tenantID); err != nil {
		h.handleServiceError(w, "Scope target", err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ActivateTarget handles POST /api/v1/scope/targets/{id}/activate
// @Summary      Activate scope target
// @Description  Activate a scope target
// @Tags         Scope
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Target ID"
// @Success      200  {object}  ScopeTargetResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scope/targets/{id}/activate [post]
func (h *ScopeHandler) ActivateTarget(w http.ResponseWriter, r *http.Request) {
	targetID := chi.URLParam(r, "id")

	target, err := h.service.ActivateTarget(r.Context(), targetID)
	if err != nil {
		h.handleServiceError(w, "Scope target", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toScopeTargetResponse(target))
}

// DeactivateTarget handles POST /api/v1/scope/targets/{id}/deactivate
// @Summary      Deactivate scope target
// @Description  Deactivate a scope target
// @Tags         Scope
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Target ID"
// @Success      200  {object}  ScopeTargetResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scope/targets/{id}/deactivate [post]
func (h *ScopeHandler) DeactivateTarget(w http.ResponseWriter, r *http.Request) {
	targetID := chi.URLParam(r, "id")

	target, err := h.service.DeactivateTarget(r.Context(), targetID)
	if err != nil {
		h.handleServiceError(w, "Scope target", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toScopeTargetResponse(target))
}

// =============================================================================
// Exclusion Handlers
// =============================================================================

// ListExclusions handles GET /api/v1/scope/exclusions
// @Summary      List scope exclusions
// @Description  Get a paginated list of scope exclusions for the current tenant
// @Tags         Scope
// @Accept       json
// @Produce      json
// @Param        types        query     string  false  "Filter by exclusion types (comma-separated)"
// @Param        statuses     query     string  false  "Filter by statuses (comma-separated)"
// @Param        is_approved  query     bool    false  "Filter by approval status"
// @Param        search       query     string  false  "Search by pattern"
// @Param        page         query     int     false  "Page number" default(1)
// @Param        per_page     query     int     false  "Items per page" default(20)
// @Success      200  {object}  ListResponse[ScopeExclusionResponse]
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scope/exclusions [get]
func (h *ScopeHandler) ListExclusions(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	query := r.URL.Query()

	input := app.ListExclusionsInput{
		TenantID:       tenantID,
		ExclusionTypes: parseQueryArray(query.Get("types")),
		Statuses:       parseQueryArray(query.Get("statuses")),
		IsApproved:     parseQueryBoolPtr(query.Get("is_approved")),
		Search:         query.Get("search"),
		Page:           parseQueryInt(query.Get("page"), 1),
		PerPage:        parseQueryInt(query.Get("per_page"), 20),
	}

	result, err := h.service.ListExclusions(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, "Scope exclusion", err)
		return
	}

	responses := make([]ScopeExclusionResponse, len(result.Data))
	for i, exclusion := range result.Data {
		responses[i] = toScopeExclusionResponse(exclusion)
	}

	response := ListResponse[ScopeExclusionResponse]{
		Data:       responses,
		Total:      result.Total,
		Page:       result.Page,
		PerPage:    result.PerPage,
		TotalPages: result.TotalPages,
		Links:      NewPaginationLinks(r, result.Page, result.PerPage, result.TotalPages),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// CreateExclusion handles POST /api/v1/scope/exclusions
// @Summary      Create scope exclusion
// @Description  Create a new scope exclusion
// @Tags         Scope
// @Accept       json
// @Produce      json
// @Param        body  body      CreateScopeExclusionRequest  true  "Scope exclusion data"
// @Success      201   {object}  ScopeExclusionResponse
// @Failure      400   {object}  apierror.Error
// @Failure      409   {object}  apierror.Error
// @Failure      500   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scope/exclusions [post]
func (h *ScopeHandler) CreateExclusion(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())

	var req CreateScopeExclusionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid JSON").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := app.CreateExclusionInput{
		TenantID:      tenantID,
		ExclusionType: req.ExclusionType,
		Pattern:       req.Pattern,
		Reason:        req.Reason,
		ExpiresAt:     req.ExpiresAt,
		CreatedBy:     userID,
	}

	exclusion, err := h.service.CreateExclusion(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, "Scope exclusion", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(toScopeExclusionResponse(exclusion))
}

// GetExclusion handles GET /api/v1/scope/exclusions/{id}
// @Summary      Get scope exclusion
// @Description  Get a single scope exclusion by ID
// @Tags         Scope
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Exclusion ID"
// @Success      200  {object}  ScopeExclusionResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scope/exclusions/{id} [get]
func (h *ScopeHandler) GetExclusion(w http.ResponseWriter, r *http.Request) {
	exclusionID := chi.URLParam(r, "id")

	exclusion, err := h.service.GetExclusion(r.Context(), exclusionID)
	if err != nil {
		h.handleServiceError(w, "Scope exclusion", err)
		return
	}

	// Verify tenant ownership
	tenantID := middleware.MustGetTenantID(r.Context())
	if exclusion.TenantID().String() != tenantID {
		apierror.NotFound("Scope exclusion").WriteJSON(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toScopeExclusionResponse(exclusion))
}

// UpdateExclusion handles PUT /api/v1/scope/exclusions/{id}
// @Summary      Update scope exclusion
// @Description  Update an existing scope exclusion
// @Tags         Scope
// @Accept       json
// @Produce      json
// @Param        id    path      string                       true  "Exclusion ID"
// @Param        body  body      UpdateScopeExclusionRequest  true  "Update data"
// @Success      200   {object}  ScopeExclusionResponse
// @Failure      400   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Failure      500   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scope/exclusions/{id} [put]
func (h *ScopeHandler) UpdateExclusion(w http.ResponseWriter, r *http.Request) {
	exclusionID := chi.URLParam(r, "id")
	tenantID := middleware.MustGetTenantID(r.Context())

	var req UpdateScopeExclusionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid JSON").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := app.UpdateExclusionInput{
		Reason:    req.Reason,
		ExpiresAt: req.ExpiresAt,
	}

	exclusion, err := h.service.UpdateExclusion(r.Context(), exclusionID, tenantID, input)
	if err != nil {
		h.handleServiceError(w, "Scope exclusion", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toScopeExclusionResponse(exclusion))
}

// DeleteExclusion handles DELETE /api/v1/scope/exclusions/{id}
// @Summary      Delete scope exclusion
// @Description  Delete a scope exclusion
// @Tags         Scope
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Exclusion ID"
// @Success      204  "No Content"
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scope/exclusions/{id} [delete]
func (h *ScopeHandler) DeleteExclusion(w http.ResponseWriter, r *http.Request) {
	exclusionID := chi.URLParam(r, "id")
	tenantID := middleware.MustGetTenantID(r.Context())

	if err := h.service.DeleteExclusion(r.Context(), exclusionID, tenantID); err != nil {
		h.handleServiceError(w, "Scope exclusion", err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ApproveExclusion handles POST /api/v1/scope/exclusions/{id}/approve
func (h *ScopeHandler) ApproveExclusion(w http.ResponseWriter, r *http.Request) {
	exclusionID := chi.URLParam(r, "id")
	userID := middleware.GetUserID(r.Context())

	exclusion, err := h.service.ApproveExclusion(r.Context(), exclusionID, userID)
	if err != nil {
		h.handleServiceError(w, "Scope exclusion", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toScopeExclusionResponse(exclusion))
}

// ActivateExclusion handles POST /api/v1/scope/exclusions/{id}/activate
func (h *ScopeHandler) ActivateExclusion(w http.ResponseWriter, r *http.Request) {
	exclusionID := chi.URLParam(r, "id")

	exclusion, err := h.service.ActivateExclusion(r.Context(), exclusionID)
	if err != nil {
		h.handleServiceError(w, "Scope exclusion", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toScopeExclusionResponse(exclusion))
}

// DeactivateExclusion handles POST /api/v1/scope/exclusions/{id}/deactivate
func (h *ScopeHandler) DeactivateExclusion(w http.ResponseWriter, r *http.Request) {
	exclusionID := chi.URLParam(r, "id")

	exclusion, err := h.service.DeactivateExclusion(r.Context(), exclusionID)
	if err != nil {
		h.handleServiceError(w, "Scope exclusion", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toScopeExclusionResponse(exclusion))
}

// =============================================================================
// Schedule Handlers
// =============================================================================

// ListSchedules handles GET /api/v1/scope/schedules
// @Summary      List scan schedules
// @Description  Get a paginated list of scan schedules for the current tenant
// @Tags         Scope
// @Accept       json
// @Produce      json
// @Param        scan_types      query     string  false  "Filter by scan types (comma-separated)"
// @Param        schedule_types  query     string  false  "Filter by schedule types (comma-separated)"
// @Param        enabled         query     bool    false  "Filter by enabled status"
// @Param        search          query     string  false  "Search by name"
// @Param        page            query     int     false  "Page number" default(1)
// @Param        per_page        query     int     false  "Items per page" default(20)
// @Success      200  {object}  ListResponse[ScanScheduleResponse]
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scope/schedules [get]
func (h *ScopeHandler) ListSchedules(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	query := r.URL.Query()

	input := app.ListSchedulesInput{
		TenantID:      tenantID,
		ScanTypes:     parseQueryArray(query.Get("scan_types")),
		ScheduleTypes: parseQueryArray(query.Get("schedule_types")),
		Enabled:       parseQueryBoolPtr(query.Get("enabled")),
		Search:        query.Get("search"),
		Page:          parseQueryInt(query.Get("page"), 1),
		PerPage:       parseQueryInt(query.Get("per_page"), 20),
	}

	result, err := h.service.ListSchedules(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, "Scan schedule", err)
		return
	}

	responses := make([]ScanScheduleResponse, len(result.Data))
	for i, schedule := range result.Data {
		responses[i] = toScanScheduleResponse(schedule)
	}

	response := ListResponse[ScanScheduleResponse]{
		Data:       responses,
		Total:      result.Total,
		Page:       result.Page,
		PerPage:    result.PerPage,
		TotalPages: result.TotalPages,
		Links:      NewPaginationLinks(r, result.Page, result.PerPage, result.TotalPages),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// CreateSchedule handles POST /api/v1/scope/schedules
// @Summary      Create scan schedule
// @Description  Create a new scan schedule
// @Tags         Scope
// @Accept       json
// @Produce      json
// @Param        body  body      CreateScanScheduleRequest  true  "Scan schedule data"
// @Success      201   {object}  ScanScheduleResponse
// @Failure      400   {object}  apierror.Error
// @Failure      409   {object}  apierror.Error
// @Failure      500   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scope/schedules [post]
func (h *ScopeHandler) CreateSchedule(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())

	var req CreateScanScheduleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid JSON").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := app.CreateScheduleInput{
		TenantID:             tenantID,
		Name:                 req.Name,
		Description:          req.Description,
		ScanType:             req.ScanType,
		TargetScope:          req.TargetScope,
		TargetIDs:            req.TargetIDs,
		TargetTags:           req.TargetTags,
		ScannerConfigs:       req.ScannerConfigs,
		ScheduleType:         req.ScheduleType,
		CronExpression:       req.CronExpression,
		IntervalHours:        req.IntervalHours,
		NotifyOnCompletion:   req.NotifyOnCompletion,
		NotifyOnFindings:     req.NotifyOnFindings,
		NotificationChannels: req.NotificationChannels,
		CreatedBy:            userID,
	}

	schedule, err := h.service.CreateSchedule(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, "Scan schedule", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(toScanScheduleResponse(schedule))
}

// GetSchedule handles GET /api/v1/scope/schedules/{id}
// @Summary      Get scan schedule
// @Description  Get a single scan schedule by ID
// @Tags         Scope
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Schedule ID"
// @Success      200  {object}  ScanScheduleResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scope/schedules/{id} [get]
func (h *ScopeHandler) GetSchedule(w http.ResponseWriter, r *http.Request) {
	scheduleID := chi.URLParam(r, "id")

	schedule, err := h.service.GetSchedule(r.Context(), scheduleID)
	if err != nil {
		h.handleServiceError(w, "Scan schedule", err)
		return
	}

	// Verify tenant ownership
	tenantID := middleware.MustGetTenantID(r.Context())
	if schedule.TenantID().String() != tenantID {
		apierror.NotFound("Scan schedule").WriteJSON(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toScanScheduleResponse(schedule))
}

// UpdateSchedule handles PUT /api/v1/scope/schedules/{id}
func (h *ScopeHandler) UpdateSchedule(w http.ResponseWriter, r *http.Request) {
	scheduleID := chi.URLParam(r, "id")
	tenantID := middleware.MustGetTenantID(r.Context())

	var req UpdateScanScheduleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid JSON").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := app.UpdateScheduleInput{
		Name:                 req.Name,
		Description:          req.Description,
		TargetScope:          req.TargetScope,
		TargetIDs:            req.TargetIDs,
		TargetTags:           req.TargetTags,
		ScannerConfigs:       req.ScannerConfigs,
		ScheduleType:         req.ScheduleType,
		CronExpression:       req.CronExpression,
		IntervalHours:        req.IntervalHours,
		NotifyOnCompletion:   req.NotifyOnCompletion,
		NotifyOnFindings:     req.NotifyOnFindings,
		NotificationChannels: req.NotificationChannels,
	}

	schedule, err := h.service.UpdateSchedule(r.Context(), scheduleID, tenantID, input)
	if err != nil {
		h.handleServiceError(w, "Scan schedule", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toScanScheduleResponse(schedule))
}

// DeleteSchedule handles DELETE /api/v1/scope/schedules/{id}
func (h *ScopeHandler) DeleteSchedule(w http.ResponseWriter, r *http.Request) {
	scheduleID := chi.URLParam(r, "id")
	tenantID := middleware.MustGetTenantID(r.Context())

	if err := h.service.DeleteSchedule(r.Context(), scheduleID, tenantID); err != nil {
		h.handleServiceError(w, "Scan schedule", err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// EnableSchedule handles POST /api/v1/scope/schedules/{id}/enable
func (h *ScopeHandler) EnableSchedule(w http.ResponseWriter, r *http.Request) {
	scheduleID := chi.URLParam(r, "id")

	schedule, err := h.service.EnableSchedule(r.Context(), scheduleID)
	if err != nil {
		h.handleServiceError(w, "Scan schedule", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toScanScheduleResponse(schedule))
}

// DisableSchedule handles POST /api/v1/scope/schedules/{id}/disable
func (h *ScopeHandler) DisableSchedule(w http.ResponseWriter, r *http.Request) {
	scheduleID := chi.URLParam(r, "id")

	schedule, err := h.service.DisableSchedule(r.Context(), scheduleID)
	if err != nil {
		h.handleServiceError(w, "Scan schedule", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toScanScheduleResponse(schedule))
}

// =============================================================================
// Stats & Check Handlers
// =============================================================================

// GetStats handles GET /api/v1/scope/stats
func (h *ScopeHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	stats, err := h.service.GetStats(r.Context(), tenantID)
	if err != nil {
		h.handleServiceError(w, "Scope stats", err)
		return
	}

	response := ScopeStatsResponse{
		TotalTargets:     stats.TotalTargets,
		ActiveTargets:    stats.ActiveTargets,
		TotalExclusions:  stats.TotalExclusions,
		ActiveExclusions: stats.ActiveExclusions,
		TotalSchedules:   stats.TotalSchedules,
		EnabledSchedules: stats.EnabledSchedules,
		Coverage:         stats.Coverage,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// CheckScope handles POST /api/v1/scope/check
func (h *ScopeHandler) CheckScope(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	var req CheckScopeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid JSON").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	result, err := h.service.CheckScope(r.Context(), tenantID, req.AssetType, req.Value)
	if err != nil {
		h.handleServiceError(w, "Scope check", err)
		return
	}

	targetIDs := make([]string, len(result.MatchedTargetIDs))
	for i, id := range result.MatchedTargetIDs {
		targetIDs[i] = id.String()
	}

	exclusionIDs := make([]string, len(result.MatchedExclusionIDs))
	for i, id := range result.MatchedExclusionIDs {
		exclusionIDs[i] = id.String()
	}

	response := ScopeMatchResponse{
		InScope:             result.InScope,
		Excluded:            result.Excluded,
		MatchedTargetIDs:    targetIDs,
		MatchedExclusionIDs: exclusionIDs,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
