package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

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
	// sensorImage is the image the install snippets run, with its pinned
	// tag (SENSOR_IMAGE + SENSOR_LATEST_VERSION).
	sensorImage string
	// caCertFile is the platform CA the snippets install (SENSOR_CA_CERT_FILE);
	// empty when the platform certificate is publicly trusted.
	caCertFile string
	// healthPolicy holds the thresholds and release channel the computed
	// state, health reasons and version status use.
	healthPolicy sensor.HealthPolicy
	now          func() time.Time
	validator    *validator.Validator
	logger       *logger.Logger
}

// NewSensorHandler creates a new SensorHandler.
func NewSensorHandler(service *app.SensorService, v *validator.Validator, log *logger.Logger) *SensorHandler {
	return &SensorHandler{
		service:      service,
		healthPolicy: sensor.DefaultHealthPolicy(),
		now:          time.Now,
		validator:    v,
		logger:       log.With("handler", "sensor"),
	}
}

// SetHealthPolicy sets the heartbeat windows and the sensor release channel
// (SENSOR_LATEST_VERSION / SENSOR_MIN_VERSION) used for the computed state,
// health reasons and version status. Unset values take the defaults.
func (h *SensorHandler) SetHealthPolicy(p sensor.HealthPolicy) {
	h.healthPolicy = p.Normalized()
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

// SetSensorImage sets the image reference (with tag) the install snippets run.
func (h *SensorHandler) SetSensorImage(image string) {
	h.sensorImage = image
}

// SetCACertificateFile sets the platform CA file the install snippets embed
// (SENSOR_CA_CERT_FILE). It is read on each request, so a CA the gateway
// exports after the API started is picked up.
func (h *SensorHandler) SetCACertificateFile(path string) {
	h.caCertFile = path
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
	// Outbox is the last outbox state the sensor reported on its heartbeat;
	// null when it never reported one (an SDK without a durable outbox).
	Outbox *SensorOutboxResponse `json:"outbox"`
	// OutboxWarning is true when the last snapshot shows lost or stuck
	// results: dead_letter_count > 0, evicted_count > 0, or
	// oldest_age_seconds > 3600. False when there is no snapshot.
	OutboxWarning bool `json:"outbox_warning"`
	// Protocol is what the platform last saw of the sensor's protocol
	// (RFC-029 §5.3); null before the first heartbeat that recorded it.
	// deprecated is true for protocol v1: the sensor needs an upgrade.
	Protocol *SensorProtocolResponse `json:"protocol"`

	// State is the computed operational state: online, degraded, stale,
	// offline, idle (a CI sensor between runs), never_connected, disabled or
	// revoked. Online means a heartbeat within the online window (see
	// GET /sensors/stats online_window_seconds); stale is older than that but
	// within the heartbeat timeout; degraded is heartbeating with at least
	// one health reason.
	State string `json:"state" enums:"online,degraded,stale,offline,idle,never_connected,disabled,revoked"`
	// HealthReasons lists the problems found (never null): an outbox backlog
	// or lost results, an expired or expiring key, a version below the
	// minimum, no scan tools, an error the sensor reported.
	HealthReasons []SensorHealthReasonResponse `json:"health_reasons"`
	// VersionStatus compares the version with the release channel.
	VersionStatus string `json:"version_status" enums:"latest,update_available,unsupported,unknown"`
	// KeyExpiresAt is when the current API key stops working; null = never.
	KeyExpiresAt *string `json:"key_expires_at"`
	// LastOfflineAt is when the sensor was last marked offline.
	LastOfflineAt *string `json:"last_offline_at"`
	// LastErrorAt is when the sensor last reported an error.
	LastErrorAt *string `json:"last_error_at"`
	// StartedAt is when the sensor process started (from the uptime its
	// heartbeat reports); null when it never reported one.
	StartedAt *string `json:"started_at"`
	// UptimeSeconds is the process uptime at the last heartbeat; null unless
	// the sensor is heartbeating and reports its uptime.
	UptimeSeconds *int64 `json:"uptime_seconds"`
	// IsPlatformSensor marks shared platform infrastructure.
	IsPlatformSensor bool `json:"is_platform_sensor"`
}

// SensorProtocolResponse is the protocol telemetry of a sensor's last
// heartbeat. user_agent is reported by the sensor (sanitized) and is display
// data only.
type SensorProtocolResponse struct {
	Version    int    `json:"version"`
	UserAgent  string `json:"user_agent"`
	SeenAt     string `json:"seen_at"`
	Deprecated bool   `json:"deprecated"`
}

// SensorHealthReasonResponse is one problem found on a sensor. code is
// stable (clients map it to their own wording and fix actions); message is a
// plain-English fallback.
type SensorHealthReasonResponse struct {
	Code     string `json:"code" enums:"outbox_backlog,outbox_dead_letters,outbox_evicted,key_expired,key_expiring,version_unsupported,no_tools,error_reported"`
	Severity string `json:"severity" enums:"warning,critical"`
	Message  string `json:"message"`
}

// SensorOutboxResponse is a sensor's last reported outbox state. Values are
// reported by the sensor (clamped on ingest); reported_at is the server time
// the snapshot was stored, so an old reported_at means a stale snapshot.
type SensorOutboxResponse struct {
	PendingCount     int64  `json:"pending_count"`
	PendingBytes     int64  `json:"pending_bytes"`
	OldestAgeSeconds int64  `json:"oldest_age_seconds"`
	DeadLetterCount  int64  `json:"dead_letter_count"`
	EvictedCount     int64  `json:"evicted_count"`
	ReportedAt       string `json:"reported_at"`
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
		AuditContext:      h.buildAuditContext(r),
	}

	output, err := h.service.CreateSensor(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	response := &CreateSensorResponse{
		Sensor: h.toSensorResponse(output.Sensor),
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
	json.NewEncoder(w).Encode(h.toSensorResponse(a))
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
		items[i] = h.toSensorResponse(a)
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

// SensorStatsResponse is the fleet summary for the tenant's sensors. It
// counts the same sensors GET /sensors lists.
type SensorStatsResponse struct {
	Total           int            `json:"total"`
	ByStatus        map[string]int `json:"by_status"`
	ByHealth        map[string]int `json:"by_health"`
	ByType          map[string]int `json:"by_type"`
	ByExecutionMode map[string]int `json:"by_execution_mode"`
	ActiveJobs      int            `json:"active_jobs"`
	OnlineActive    int            `json:"online_active"`

	// ByState counts sensors per computed state (every state is present,
	// zeros included); the same state GET /sensors returns per sensor.
	ByState map[string]int `json:"by_state"`
	// ByVersionStatus counts sensors per version status.
	ByVersionStatus map[string]int `json:"by_version_status"`
	// NeedsAttention counts enabled sensors with at least one health reason.
	NeedsAttention int `json:"needs_attention"`
	// CanTakeJobs counts sensors that can be dispatched work now: enabled,
	// long-running (not one-shot CI) and online or degraded.
	CanTakeJobs int `json:"can_take_jobs"`
	// JobsRunning is the sum of current jobs on those sensors, JobSlots the
	// sum of their max concurrent jobs.
	JobsRunning int `json:"jobs_running"`
	JobSlots    int `json:"job_slots"`
	// LatestVersion and MinVersion are the release channel
	// (SENSOR_LATEST_VERSION, SENSOR_MIN_VERSION); "" when not configured.
	LatestVersion string `json:"latest_version"`
	MinVersion    string `json:"min_version"`
	// OnlineWindowSeconds and OfflineAfterSeconds are the thresholds of the
	// state ladder: a heartbeat at most online_window_seconds old is online,
	// one older than offline_after_seconds is offline, stale in between.
	OnlineWindowSeconds int `json:"online_window_seconds"`
	OfflineAfterSeconds int `json:"offline_after_seconds"`
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

	sensors, err := h.service.ListAllSensors(r.Context(), tenantID)
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
	h.addFleetSummary(&resp, sensors)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// addFleetSummary fills the per-sensor breakdowns of the stats response.
func (h *SensorHandler) addFleetSummary(resp *SensorStatsResponse, sensors []*sensor.Sensor) {
	p := h.healthPolicy
	now := h.now()
	resp.ByState = make(map[string]int, len(sensor.AllStates()))
	for _, st := range sensor.AllStates() {
		resp.ByState[string(st)] = 0
	}
	resp.ByVersionStatus = map[string]int{
		string(sensor.VersionLatest): 0, string(sensor.VersionUpdateAvailable): 0,
		string(sensor.VersionUnsupported): 0, string(sensor.VersionUnknown): 0,
	}
	for _, a := range sensors {
		hl := a.AssessHealth(now, p)
		resp.ByState[string(hl.State)]++
		resp.ByVersionStatus[string(hl.VersionStatus)]++
		enabled := hl.State != sensor.StateDisabled && hl.State != sensor.StateRevoked
		if enabled && len(hl.Reasons) > 0 {
			resp.NeedsAttention++
		}
		if (hl.State == sensor.StateOnline || hl.State == sensor.StateDegraded) && !a.IsOneShot() {
			resp.CanTakeJobs++
			resp.JobsRunning += a.CurrentJobs
			resp.JobSlots += a.MaxConcurrentJobs
		}
	}
	resp.LatestVersion = p.LatestVersion
	resp.MinVersion = p.MinVersion
	resp.OnlineWindowSeconds = int(p.OnlineWindow / time.Second)
	resp.OfflineAfterSeconds = int(p.OfflineAfter / time.Second)
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
		AuditContext:      h.buildAuditContext(r),
	}

	a, err := h.service.UpdateSensor(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(h.toSensorResponse(a))
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
	json.NewEncoder(w).Encode(h.toSensorResponse(a))
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
	json.NewEncoder(w).Encode(h.toSensorResponse(a))
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
	json.NewEncoder(w).Encode(h.toSensorResponse(a))
}

// toSensorResponse converts a sensor entity to response, with the state,
// health reasons and version status computed now under the handler's policy.
func (h *SensorHandler) toSensorResponse(a *sensor.Sensor) *SensorResponse {
	return sensorResponseAt(a, h.healthPolicy, h.now())
}

// sensorResponseAt converts a sensor entity to response at a given time.
func sensorResponseAt(a *sensor.Sensor, policy sensor.HealthPolicy, now time.Time) *SensorResponse {
	health := a.AssessHealth(now, policy)
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
		Version:       health.Version, // one form: "v0.4.2"
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
		// Computed fleet health
		State:            string(health.State),
		HealthReasons:    make([]SensorHealthReasonResponse, 0, len(health.Reasons)),
		VersionStatus:    string(health.VersionStatus),
		KeyExpiresAt:     rfc3339Ptr(a.KeyExpiresAt),
		LastOfflineAt:    rfc3339Ptr(a.LastOfflineAt),
		LastErrorAt:      rfc3339Ptr(a.LastErrorAt),
		StartedAt:        rfc3339Ptr(a.StartedAt),
		UptimeSeconds:    health.UptimeSeconds,
		IsPlatformSensor: a.IsPlatformSensor,
	}
	for _, r := range health.Reasons {
		resp.HealthReasons = append(resp.HealthReasons, SensorHealthReasonResponse{
			Code: string(r.Code), Severity: r.Severity, Message: r.Message,
		})
	}

	if a.IPAddress != nil {
		resp.IPAddress = a.IPAddress.String()
	}

	if a.LastSeenAt != nil {
		ts := a.LastSeenAt.Format("2006-01-02T15:04:05Z07:00")
		resp.LastSeenAt = &ts
	}

	if ob := a.Outbox; ob != nil {
		resp.Outbox = &SensorOutboxResponse{
			PendingCount:     ob.PendingCount,
			PendingBytes:     ob.PendingBytes,
			OldestAgeSeconds: ob.OldestAgeSeconds,
			DeadLetterCount:  ob.DeadLetterCount,
			EvictedCount:     ob.EvictedCount,
			ReportedAt:       ob.ReportedAt.UTC().Format(time.RFC3339),
		}
		resp.OutboxWarning = ob.Warning()
	}

	if p := a.Protocol; p != nil {
		resp.Protocol = &SensorProtocolResponse{
			Version:    p.Version,
			UserAgent:  p.UserAgent,
			SeenAt:     p.SeenAt.UTC().Format(time.RFC3339),
			Deprecated: p.Deprecated(),
		}
	}

	return resp
}

// rfc3339Ptr formats an optional time as RFC 3339 UTC, or nil.
func rfc3339Ptr(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := t.UTC().Format(time.RFC3339)
	return &s
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
	// Forwarding headers count only from a trusted proxy (S-4); a client
	// must not be able to write any IP it likes into the audit log.
	clientIP := getClientIP(r)

	return &app.AuditContext{
		TenantID:   middleware.GetTenantID(r.Context()),
		ActorID:    middleware.GetUserID(r.Context()),
		ActorEmail: auditActorEmail(r.Context()),
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

// SensorConfigTemplatesResponse holds the rendered install and configuration
// snippets for one sensor, and what they were rendered with.
type SensorConfigTemplatesResponse struct {
	YAML   string `json:"yaml"`
	Env    string `json:"env"`
	Docker string `json:"docker"`
	CLI    string `json:"cli"`
	// Compose is a compose.yaml for the sensor; Kubernetes a Secret, PVC and
	// Deployment (a Job for a one-shot sensor); Helm the commands that turn
	// on the sensor bundled with the openctem chart.
	Compose    string `json:"compose"`
	Kubernetes string `json:"kubernetes"`
	Helm       string `json:"helm"`
	// Image is the sensor image the snippets run, with its pinned tag.
	Image string `json:"image"`
	// APIURL is the platform URL the snippets point the sensor at.
	APIURL string `json:"api_url"`
	// APIKeyIncluded is true when the snippets carry the key passed in
	// X-Sensor-API-Key; otherwise they read it from OPENCTEM_API_KEY.
	APIKeyIncluded bool `json:"api_key_included"`
	// CACertificate is the PEM of the platform's private CA the snippets
	// install (SENSOR_CA_CERT_FILE); "" when none is configured.
	CACertificate string `json:"ca_certificate"`
	// CAFingerprintSHA256 is the SHA-256 fingerprint of that CA, colon hex.
	CAFingerprintSHA256 string `json:"ca_fingerprint_sha256"`
}

// sensorAPIKeyHeaderRegexp is the shape of a sensor API key. The header value
// is embedded in shell snippets, so anything else is refused.
var sensorAPIKeyHeaderRegexp = regexp.MustCompile(`^[A-Za-z0-9_-]{8,256}$`)

// DefaultSensorImage is the install snippets' image when none is configured.
const DefaultSensorImage = "ghcr.io/openctemio/sensor:v0.4.2"

// GetConfigTemplates handles GET /api/v1/sensors/{id}/config-templates
// Returns rendered install and configuration snippets (docker run, Compose,
// Kubernetes, Helm, YAML, env, CLI) for a sensor.
// Templates are loaded from configs/sensor-templates/*.tmpl on the API host
// and can be edited without rebuilding the frontend.
//
// @Summary Get sensor configuration templates
// @Description Returns the install and configuration snippets for a sensor: docker run, Compose, Kubernetes, Helm, YAML, env and CLI, pinned to the sensor image of SENSOR_LATEST_VERSION, pointed at the public platform URL, and installing the platform's private CA when SENSOR_CA_CERT_FILE is set.
// @Tags Sensors
// @Produce json
// @Param id path string true "Sensor ID"
// @Param X-Sensor-API-Key header string false "Optional API key to embed in templates (only available right after creation/regeneration). MUST be sent as header, not query parameter."
// @Success 200 {object} SensorConfigTemplatesResponse
// @Failure 400 {object} apierror.Error "X-Sensor-API-Key is malformed"
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
	// in the X-Sensor-API-Key header. If absent, the snippets read the key
	// from $OPENCTEM_API_KEY.
	apiKey := strings.TrimSpace(r.Header.Get("X-Sensor-API-Key"))
	if apiKey != "" && !sensorAPIKeyHeaderRegexp.MatchString(apiKey) {
		apierror.BadRequest("X-Sensor-API-Key is not a sensor API key").WriteJSON(w)
		return
	}

	baseURL := h.publicAPIURL
	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}
	image := h.sensorImage
	if image == "" {
		image = DefaultSensorImage
	}

	caPEM, caFingerprint, caErr := app.LoadSensorCACertificate(h.caCertFile)
	if caErr != nil {
		// Not fatal: the snippets then assume a publicly trusted certificate.
		h.logger.Warn("sensor CA certificate not usable; install snippets omit it",
			"path", h.caCertFile, "error", caErr)
	}

	rendered, err := h.templateService.Render(app.SensorTemplateData{
		Sensor:  a,
		APIKey:  apiKey,
		BaseURL: baseURL,
		Image:   image,
		CACert:  caPEM,
	})
	if err != nil {
		h.logger.Error("failed to render sensor config templates", "error", err, "sensor_id", sensorID)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	resp := SensorConfigTemplatesResponse{
		YAML:                rendered.YAML,
		Env:                 rendered.Env,
		Docker:              rendered.Docker,
		CLI:                 rendered.CLI,
		Compose:             rendered.Compose,
		Kubernetes:          rendered.Kubernetes,
		Helm:                rendered.Helm,
		Image:               image,
		APIURL:              baseURL,
		APIKeyIncluded:      apiKey != "",
		CACertificate:       caPEM,
		CAFingerprintSHA256: caFingerprint,
	}
	// The response can carry a freshly issued key: never cache it.
	w.Header().Set("Cache-Control", "no-store")

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
