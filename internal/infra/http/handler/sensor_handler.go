package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/sensor"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/sensorproto/legacyv1"
	"github.com/openctemio/api/pkg/validator"
)

// SensorHandler handles HTTP requests for sensors.
type SensorHandler struct {
	service         *app.SensorService
	templateService *app.SensorConfigTemplateService
	publicAPIURL    string // Public URL sensors will connect to (defaults to API_URL env var)
	validator       *validator.Validator
	logger          *logger.Logger
}

// NewSensorHandler creates a new SensorHandler.
func NewSensorHandler(service *app.SensorService, v *validator.Validator, log *logger.Logger) *SensorHandler {
	return &SensorHandler{
		service:   service,
		validator: v,
		logger:    log.With("handler", "sensor"),
	}
}

// SetTemplateService injects the sensor config template service.
// Optional dependency — if nil, the config template endpoint returns 503.
func (h *SensorHandler) SetTemplateService(svc *app.SensorConfigTemplateService) {
	h.templateService = svc
}

// SetPublicAPIURL sets the public URL that sensor configs will reference.
func (h *SensorHandler) SetPublicAPIURL(url string) {
	h.publicAPIURL = url
}

// CreateSensorRequest represents the request body for creating a sensor.
type CreateSensorRequest struct {
	Name              string   `json:"name" validate:"required,min=1,max=255"`
	Type              string   `json:"type" validate:"required,oneof=runner worker collector sensor"`
	Description       string   `json:"description" validate:"max=1000"`
	Capabilities      []string `json:"capabilities" validate:"max=20,dive,max=50"`
	Tools             []string `json:"tools" validate:"max=20,dive,max=50"`
	ExecutionMode     string   `json:"execution_mode" validate:"omitempty,oneof=standalone daemon"`
	MaxConcurrentJobs int      `json:"max_concurrent_jobs" validate:"omitempty,min=1,max=100"`
}

// SensorResponse represents the response for a sensor.
type SensorResponse struct {
	ID            string         `json:"id"`
	TenantID      string         `json:"tenant_id"`
	Name          string         `json:"name"`
	Type          string         `json:"type"`
	Description   string         `json:"description,omitempty"`
	Capabilities  []string       `json:"capabilities"`
	Tools         []string       `json:"tools"`
	ExecutionMode string         `json:"execution_mode"`
	Status        string         `json:"status"` // Admin-controlled: active, disabled, revoked
	Health        string         `json:"health"` // Automatic: unknown, online, offline, error
	StatusMessage string         `json:"status_message,omitempty"`
	APIKeyPrefix  string         `json:"api_key_prefix,omitempty"`
	Labels        map[string]any `json:"labels,omitempty"`
	Version       string         `json:"version,omitempty"`
	Hostname      string         `json:"hostname,omitempty"`
	IPAddress     string         `json:"ip_address,omitempty"`
	// System metrics
	CPUPercent    float64 `json:"cpu_percent"`
	MemoryPercent float64 `json:"memory_percent"`
	Region        string  `json:"region,omitempty"`
	// Load balancing
	MaxConcurrentJobs int     `json:"max_concurrent_jobs"`
	CurrentJobs       int     `json:"current_jobs"`
	AvailableSlots    int     `json:"available_slots"`
	LoadFactor        float64 `json:"load_factor"` // 0.0 to 1.0
	// Statistics
	LastSeenAt    *string `json:"last_seen_at,omitempty"`
	TotalFindings int64   `json:"total_findings"`
	TotalScans    int64   `json:"total_scans"`
	ErrorCount    int64   `json:"error_count"`
	CreatedAt     string  `json:"created_at"`
	UpdatedAt     string  `json:"updated_at"`
}

// CreateSensorResponse includes the API key (only shown once).
type CreateSensorResponse struct {
	Sensor *SensorResponse `json:"sensor"`
	APIKey string          `json:"api_key"`
}

// Create handles POST /api/v1/sensors
// @Summary      Create sensor
// @Description  Create a new sensor and receive its API key
// @Tags         Sensors
// @Accept       json
// @Produce      json
// @Param        body  body      CreateSensorRequest  true  "Sensor data"
// @Success      201   {object}  CreateSensorResponse
// @Failure      400   {object}  apierror.Error
// @Failure      409   {object}  apierror.Error
// @Failure      500   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /sensors [post]
func (h *SensorHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req CreateSensorRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	tenantID := middleware.GetTenantID(r.Context())

	input := app.CreateSensorInput{
		TenantID:          tenantID,
		Name:              req.Name,
		Type:              req.Type,
		Description:       req.Description,
		Capabilities:      req.Capabilities,
		Tools:             req.Tools,
		ExecutionMode:     req.ExecutionMode,
		MaxConcurrentJobs: req.MaxConcurrentJobs,
	}

	output, err := h.service.CreateSensor(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	response := &CreateSensorResponse{
		Sensor: toSensorResponse(output.Sensor),
		APIKey: output.APIKey,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

// Get handles GET /api/v1/sensors/{id}
// @Summary      Get sensor
// @Description  Get a single sensor by ID
// @Tags         Sensors
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Sensor ID"
// @Success      200  {object}  SensorResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /sensors/{id} [get]
func (h *SensorHandler) Get(w http.ResponseWriter, r *http.Request) {
	sensorID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())

	a, err := h.service.GetSensor(r.Context(), tenantID, sensorID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toSensorResponse(a))
}

// List handles GET /api/v1/sensors
// @Summary      List sensors
// @Description  Get a paginated list of sensors for the current tenant
// @Tags         Sensors
// @Accept       json
// @Produce      json
// @Param        type            query     string  false  "Filter by type (runner, worker, collector, sensor)"
// @Param        status          query     string  false  "Filter by admin-controlled status (active, disabled, revoked)"
// @Param        health          query     string  false  "Filter by automatic health (unknown, online, offline, error)"
// @Param        execution_mode  query     string  false  "Filter by execution mode (standalone, daemon)"
// @Param        capabilities    query     string  false  "Filter by capabilities (comma-separated)"
// @Param        tools           query     string  false  "Filter by tools (comma-separated)"
// @Param        has_capacity    query     bool    false  "Filter by sensors with available capacity"
// @Param        search          query     string  false  "Search by name or description"
// @Param        page            query     int     false  "Page number" default(1)
// @Param        per_page        query     int     false  "Items per page" default(20)
// @Success      200  {object}  ListResponse[SensorResponse]
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /sensors [get]
func (h *SensorHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())

	input := app.ListSensorsInput{
		TenantID:      tenantID,
		Type:          r.URL.Query().Get("type"),
		Status:        r.URL.Query().Get("status"),
		Health:        r.URL.Query().Get("health"),
		ExecutionMode: r.URL.Query().Get("execution_mode"),
		Search:        r.URL.Query().Get("search"),
		Page:          parseQueryInt(r.URL.Query().Get("page"), 1),
		PerPage:       parseQueryIntBounded(r.URL.Query().Get("per_page"), 20, 1, MaxPerPage),
	}

	if caps := r.URL.Query().Get("capabilities"); caps != "" {
		input.Capabilities = parseQueryArray(caps)
	}

	if tools := r.URL.Query().Get("tools"); tools != "" {
		input.Tools = parseQueryArray(tools)
	}

	if hasCapacity := r.URL.Query().Get("has_capacity"); hasCapacity != "" {
		val := hasCapacity == queryParamTrue
		input.HasCapacity = &val
	}

	result, err := h.service.ListSensors(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	items := make([]*SensorResponse, len(result.Data))
	for i, a := range result.Data {
		items[i] = toSensorResponse(a)
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

// SensorStatsResponse mirrors sensor.TenantSensorStats with snake_case JSON.
type SensorStatsResponse struct {
	Total           int            `json:"total"`
	ByStatus        map[string]int `json:"by_status"`
	ByHealth        map[string]int `json:"by_health"`
	ByType          map[string]int `json:"by_type"`
	ByExecutionMode map[string]int `json:"by_execution_mode"`
	ActiveJobs      int            `json:"active_jobs"`
	OnlineActive    int            `json:"online_active"`
}

// GetStats handles GET /api/v1/sensors/stats
// @Summary      Get tenant sensor statistics
// @Description  Returns aggregated stats for the tenant's sensors (status, health, type, mode breakdowns)
// @Tags         Sensors
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  SensorStatsResponse
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Router       /sensors/stats [get]
func (h *SensorHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())

	stats, err := h.service.GetTenantSensorStats(r.Context(), tenantID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	resp := SensorStatsResponse{
		Total:           stats.Total,
		ByStatus:        stats.ByStatus,
		ByHealth:        stats.ByHealth,
		ByType:          stats.ByType,
		ByExecutionMode: stats.ByMode,
		ActiveJobs:      stats.ActiveJobs,
		OnlineActive:    stats.OnlineActive,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// UpdateSensorRequest represents the request body for updating a sensor.
type UpdateSensorRequest struct {
	Name              string   `json:"name" validate:"omitempty,min=1,max=255"`
	Description       string   `json:"description" validate:"max=1000"`
	Capabilities      []string `json:"capabilities" validate:"max=20,dive,max=50"`
	Tools             []string `json:"tools" validate:"max=20,dive,max=50"`
	Status            string   `json:"status" validate:"omitempty,oneof=active disabled revoked"` // Admin-controlled
	MaxConcurrentJobs *int     `json:"max_concurrent_jobs" validate:"omitempty,min=1,max=100"`
}

// Update handles PUT /api/v1/sensors/{id}
// @Summary      Update sensor
// @Description  Update an existing sensor
// @Tags         Sensors
// @Accept       json
// @Produce      json
// @Param        id    path      string              true  "Sensor ID"
// @Param        body  body      UpdateSensorRequest  true  "Update data"
// @Success      200   {object}  SensorResponse
// @Failure      400   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Failure      500   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /sensors/{id} [put]
func (h *SensorHandler) Update(w http.ResponseWriter, r *http.Request) {
	sensorID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())

	var req UpdateSensorRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := app.UpdateSensorInput{
		TenantID:          tenantID,
		SensorID:          sensorID,
		Name:              req.Name,
		Description:       req.Description,
		Capabilities:      req.Capabilities,
		Tools:             req.Tools,
		Status:            req.Status,
		MaxConcurrentJobs: req.MaxConcurrentJobs,
	}

	a, err := h.service.UpdateSensor(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toSensorResponse(a))
}

// Delete handles DELETE /api/v1/sensors/{id}
// @Summary      Delete sensor
// @Description  Delete a sensor and revoke its API key
// @Tags         Sensors
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Sensor ID"
// @Success      204  "No Content"
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /sensors/{id} [delete]
func (h *SensorHandler) Delete(w http.ResponseWriter, r *http.Request) {
	sensorID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())
	auditCtx := h.buildAuditContext(r)

	if err := h.service.DeleteSensor(r.Context(), tenantID, sensorID, auditCtx); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// SensorRegenerateAPIKeyResponse represents the response for regenerating an API key.
type SensorRegenerateAPIKeyResponse struct {
	APIKey string `json:"api_key"`
}

// RegenerateAPIKey handles POST /api/v1/sensors/{id}/regenerate-key
// @Summary      Regenerate API key
// @Description  Regenerate the API key for a sensor. The old key will be invalidated.
// @Tags         Sensors
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Sensor ID"
// @Success      200  {object}  SensorRegenerateAPIKeyResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /sensors/{id}/regenerate-key [post]
func (h *SensorHandler) RegenerateAPIKey(w http.ResponseWriter, r *http.Request) {
	sensorID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())
	auditCtx := h.buildAuditContext(r)

	apiKey, err := h.service.RegenerateAPIKey(r.Context(), tenantID, sensorID, auditCtx)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(&SensorRegenerateAPIKeyResponse{APIKey: apiKey})
}

// Activate handles POST /api/v1/sensors/{id}/activate
// @Summary      Activate sensor
// @Description  Activate a sensor (admin action). Allows the sensor to authenticate.
// @Tags         Sensors
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Sensor ID"
// @Success      200  {object}  SensorResponse
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /sensors/{id}/activate [post]
func (h *SensorHandler) Activate(w http.ResponseWriter, r *http.Request) {
	sensorID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())
	auditCtx := h.buildAuditContext(r)

	a, err := h.service.ActivateSensor(r.Context(), tenantID, sensorID, auditCtx)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toSensorResponse(a))
}

// SensorDisableRequest represents the request body for disabling a sensor.
type SensorDisableRequest struct {
	Reason string `json:"reason" validate:"max=500"`
}

// Disable handles POST /api/v1/sensors/{id}/disable
// @Summary      Disable sensor
// @Description  Disable a sensor (admin action). Prevents the sensor from authenticating.
// @Tags         Sensors
// @Accept       json
// @Produce      json
// @Param        id    path      string              true  "Sensor ID"
// @Param        body  body      SensorDisableRequest false "Disable reason"
// @Success      200   {object}  SensorResponse
// @Failure      400   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Failure      500   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /sensors/{id}/deactivate [post]
func (h *SensorHandler) Disable(w http.ResponseWriter, r *http.Request) {
	sensorID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())
	auditCtx := h.buildAuditContext(r)

	var req SensorDisableRequest
	if r.Body != nil && r.ContentLength > 0 {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}

	a, err := h.service.DisableSensor(r.Context(), tenantID, sensorID, req.Reason, auditCtx)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toSensorResponse(a))
}

// SensorRevokeRequest represents the request body for revoking a sensor.
type SensorRevokeRequest struct {
	Reason string `json:"reason" validate:"max=500"`
}

// Revoke handles POST /api/v1/sensors/{id}/revoke
// @Summary      Revoke sensor
// @Description  Permanently revoke a sensor's access (admin action). Cannot be undone.
// @Tags         Sensors
// @Accept       json
// @Produce      json
// @Param        id    path      string             true  "Sensor ID"
// @Param        body  body      SensorRevokeRequest false "Revoke reason"
// @Success      200   {object}  SensorResponse
// @Failure      400   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Failure      500   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /sensors/{id}/revoke [post]
func (h *SensorHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	sensorID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())
	auditCtx := h.buildAuditContext(r)

	var req SensorRevokeRequest
	if r.Body != nil && r.ContentLength > 0 {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}

	a, err := h.service.RevokeSensor(r.Context(), tenantID, sensorID, req.Reason, auditCtx)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toSensorResponse(a))
}

// toSensorResponse converts a sensor entity to response.
func toSensorResponse(a *sensor.Sensor) *SensorResponse {
	resp := &SensorResponse{
		ID:            a.ID.String(),
		TenantID:      a.TenantID.String(),
		Name:          a.Name,
		Type:          string(a.Type),
		Description:   a.Description,
		Capabilities:  a.Capabilities,
		Tools:         a.Tools,
		ExecutionMode: string(a.ExecutionMode),
		Status:        string(a.Status), // Admin-controlled
		Health:        string(a.Health), // Automatic heartbeat
		StatusMessage: a.StatusMessage,
		APIKeyPrefix:  a.APIKeyPrefix,
		Labels:        a.Labels,
		Version:       a.Version,
		Hostname:      a.Hostname,
		// System metrics
		CPUPercent:    a.CPUPercent,
		MemoryPercent: a.MemoryPercent,
		Region:        a.Region,
		// Load balancing
		MaxConcurrentJobs: a.MaxConcurrentJobs,
		CurrentJobs:       a.CurrentJobs,
		AvailableSlots:    a.AvailableSlots(),
		LoadFactor:        a.LoadFactor(),
		// Statistics
		TotalFindings: a.TotalFindings,
		TotalScans:    a.TotalScans,
		ErrorCount:    a.ErrorCount,
		CreatedAt:     a.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:     a.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}

	if a.IPAddress != nil {
		resp.IPAddress = a.IPAddress.String()
	}

	if a.LastSeenAt != nil {
		ts := a.LastSeenAt.Format("2006-01-02T15:04:05Z07:00")
		resp.LastSeenAt = &ts
	}

	return resp
}

// handleValidationError converts validation errors to API errors.
func (h *SensorHandler) handleValidationError(w http.ResponseWriter, err error) {
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
func (h *SensorHandler) handleServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Sensor").WriteJSON(w)
	case errors.Is(err, shared.ErrAlreadyExists):
		apierror.Conflict("Sensor already exists").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	case errors.Is(err, shared.ErrUnauthorized):
		apierror.Unauthorized("").WriteJSON(w)
	case errors.Is(err, shared.ErrForbidden):
		apierror.Forbidden("").WriteJSON(w)
	default:
		h.logger.Error("service error", "error", err)
		apierror.InternalError(err).WriteJSON(w)
	}
}

// buildAuditContext extracts audit context information from the HTTP request.
func (h *SensorHandler) buildAuditContext(r *http.Request) *app.AuditContext {
	// Extract client IP from headers or remote address
	clientIP := r.RemoteAddr
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		clientIP = xff
	} else if xri := r.Header.Get("X-Real-IP"); xri != "" {
		clientIP = xri
	}

	return &app.AuditContext{
		TenantID:   middleware.GetTenantID(r.Context()),
		ActorID:    middleware.GetUserID(r.Context()),
		ActorEmail: middleware.GetUsername(r.Context()),
		ActorIP:    clientIP,
		UserAgent:  r.UserAgent(),
		RequestID:  r.Header.Get("X-Request-ID"),
	}
}

// =============================================================================
// Available Capabilities
// =============================================================================

// AvailableCapabilitiesResponse represents the response for available capabilities.
type AvailableCapabilitiesResponse struct {
	Capabilities []string `json:"capabilities"`
}

// GetAvailableCapabilities returns all capabilities available to the current tenant.
// GET /api/v1/sensors/available-capabilities
// @Summary Get available capabilities
// @Description Returns all unique capability names from all sensors accessible to the tenant
// @Tags sensors
// @Produce json
// @Success 200 {object} AvailableCapabilitiesResponse
// @Failure 401 {object} apierror.Error "Unauthorized"
// @Failure 500 {object} apierror.Error "Internal server error"
// @Router /sensors/available-capabilities [get]
func (h *SensorHandler) GetAvailableCapabilities(w http.ResponseWriter, r *http.Request) {
	tenantIDStr := middleware.GetTenantID(r.Context())

	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		apierror.BadRequest("invalid tenant ID").WriteJSON(w)
		return
	}

	result, err := h.service.GetAvailableCapabilitiesForTenant(r.Context(), tenantID)
	if err != nil {
		h.logger.Error("failed to get available capabilities", "error", err, "tenant_id", tenantID)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	resp := AvailableCapabilitiesResponse{
		Capabilities: result.Capabilities,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// SensorConfigTemplatesResponse holds the rendered sensor config templates.
type SensorConfigTemplatesResponse struct {
	YAML   string `json:"yaml"`
	Env    string `json:"env"`
	Docker string `json:"docker"`
	CLI    string `json:"cli"`
}

// GetConfigTemplates handles GET /api/v1/sensors/{id}/config-templates
// Returns rendered configuration templates (YAML, env, Docker, CLI) for a sensor.
// Templates are loaded from configs/sensor-templates/*.tmpl on the API host
// and can be edited without rebuilding the frontend.
//
// @Summary Get sensor configuration templates
// @Description Returns rendered config templates for a sensor in multiple formats
// @Tags Sensors
// @Produce json
// @Param id path string true "Sensor ID"
// @Param X-Sensor-API-Key header string false "Optional API key to embed in templates (only available right after creation/regeneration). MUST be sent as header, not query parameter."
// @Success 200 {object} SensorConfigTemplatesResponse
// @Failure 404 {object} apierror.Error
// @Failure 500 {object} apierror.Error
// @Failure 503 {object} apierror.Error "Template service not configured"
// @Security BearerAuth
// @Router /sensors/{id}/config-templates [get]
func (h *SensorHandler) GetConfigTemplates(w http.ResponseWriter, r *http.Request) {
	if h.templateService == nil {
		apierror.New(http.StatusServiceUnavailable, "TEMPLATE_SERVICE_DISABLED",
			"Sensor config template service is not configured").WriteJSON(w)
		return
	}

	sensorID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())

	a, err := h.service.GetSensor(r.Context(), tenantID, sensorID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// API key MUST come from a header, never a query string. Query strings are
	// logged by load balancers, proxies, CDNs, browser history, and referer
	// headers — embedding a credential there is a known leakage vector.
	// Caller passes the freshly issued key from sensor creation/regeneration
	// in the X-Sensor-API-Key header. If absent, we render a placeholder.
	apiKey := r.Header.Get("X-Sensor-API-Key")
	if apiKey == "" {
		apiKey = "<YOUR_API_KEY>"
	}

	baseURL := h.publicAPIURL
	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}

	rendered, err := h.templateService.Render(app.SensorTemplateData{
		Sensor:  a,
		APIKey:  apiKey,
		BaseURL: baseURL,
	})
	if err != nil {
		h.logger.Error("failed to render sensor config templates", "error", err, "sensor_id", sensorID)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	resp := SensorConfigTemplatesResponse{
		YAML:   rendered.YAML,
		Env:    rendered.Env,
		Docker: rendered.Docker,
		CLI:    rendered.CLI,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// RedirectDeprecatedPath answers every route of the deprecated /api/v1/agents
// management path with 308 Permanent Redirect to the same resource under
// /api/v1/sensors (query string kept, method and body preserved), plus
// Deprecation (RFC 9745), Sunset (RFC 8594) and a successor Link. Each use is
// counted (deprecated_management_path_requests_total) and logged so operators
// can find the callers before the sunset date.
// @Summary      Deprecated: moved to /sensors
// @Description  The sensor management API moved from /agents to /sensors. Every /agents route answers 308 to its /sensors equivalent until the date in the Sunset header.
// @Tags         Sensors
// @Deprecated
// @Success      308
// @Router       /agents [get]
// @Router       /agents [post]
// @Router       /agents/stats [get]
// @Router       /agents/available-capabilities [get]
// @Router       /agents/{id} [get]
// @Router       /agents/{id} [put]
// @Router       /agents/{id} [delete]
// @Router       /agents/{id}/config-templates [get]
// @Router       /agents/{id}/regenerate-key [post]
// @Router       /agents/{id}/activate [post]
// @Router       /agents/{id}/deactivate [post]
// @Router       /agents/{id}/revoke [post]
func (h *SensorHandler) RedirectDeprecatedPath(w http.ResponseWriter, r *http.Request) {
	legacyv1.RedirectManagement(func(r *http.Request) {
		// Path and User-Agent are client-controlled: strip line breaks so a
		// crafted request cannot forge log lines.
		path := strings.ReplaceAll(strings.ReplaceAll(r.URL.Path, "\n", ""), "\r", "")
		ua := strings.ReplaceAll(strings.ReplaceAll(r.UserAgent(), "\n", ""), "\r", "")
		h.logger.Info("deprecated management path used; redirecting to /api/v1/sensors",
			"method", r.Method, "path", path, "user_agent", ua)
	})(w, r)
}
