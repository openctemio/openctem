package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/agent"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/validator"
)

// AgentHandler handles HTTP requests for agents.
type AgentHandler struct {
	service   *app.AgentService
	validator *validator.Validator
	logger    *logger.Logger
}

// NewAgentHandler creates a new AgentHandler.
func NewAgentHandler(service *app.AgentService, v *validator.Validator, log *logger.Logger) *AgentHandler {
	return &AgentHandler{
		service:   service,
		validator: v,
		logger:    log.With("handler", "agent"),
	}
}

// CreateAgentRequest represents the request body for creating an agent.
type CreateAgentRequest struct {
	Name              string   `json:"name" validate:"required,min=1,max=255"`
	Type              string   `json:"type" validate:"required,oneof=runner worker collector sensor"`
	Description       string   `json:"description" validate:"max=1000"`
	Capabilities      []string `json:"capabilities" validate:"max=20,dive,max=50"`
	Tools             []string `json:"tools" validate:"max=20,dive,max=50"`
	ExecutionMode     string   `json:"execution_mode" validate:"omitempty,oneof=standalone daemon"`
	MaxConcurrentJobs int      `json:"max_concurrent_jobs" validate:"omitempty,min=1,max=100"`
}

// AgentResponse represents the response for an agent.
type AgentResponse struct {
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

// CreateAgentResponse includes the API key (only shown once).
type CreateAgentResponse struct {
	Agent  *AgentResponse `json:"agent"`
	APIKey string         `json:"api_key"`
}

// Create handles POST /api/v1/agents
// @Summary      Create agent
// @Description  Create a new agent and receive its API key
// @Tags         Agents
// @Accept       json
// @Produce      json
// @Param        body  body      CreateAgentRequest  true  "Agent data"
// @Success      201   {object}  CreateAgentResponse
// @Failure      400   {object}  apierror.Error
// @Failure      409   {object}  apierror.Error
// @Failure      500   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /agents [post]
func (h *AgentHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req CreateAgentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	tenantID := middleware.GetTenantID(r.Context())

	input := app.CreateAgentInput{
		TenantID:          tenantID,
		Name:              req.Name,
		Type:              req.Type,
		Description:       req.Description,
		Capabilities:      req.Capabilities,
		Tools:             req.Tools,
		ExecutionMode:     req.ExecutionMode,
		MaxConcurrentJobs: req.MaxConcurrentJobs,
	}

	output, err := h.service.CreateAgent(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	response := &CreateAgentResponse{
		Agent:  toAgentResponse(output.Agent),
		APIKey: output.APIKey,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

// Get handles GET /api/v1/agents/{id}
// @Summary      Get agent
// @Description  Get a single agent by ID
// @Tags         Agents
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Agent ID"
// @Success      200  {object}  AgentResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /agents/{id} [get]
func (h *AgentHandler) Get(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())

	a, err := h.service.GetAgent(r.Context(), tenantID, agentID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toAgentResponse(a))
}

// List handles GET /api/v1/agents
// @Summary      List agents
// @Description  Get a paginated list of agents for the current tenant
// @Tags         Agents
// @Accept       json
// @Produce      json
// @Param        type            query     string  false  "Filter by type (runner, worker, collector, sensor)"
// @Param        status          query     string  false  "Filter by admin-controlled status (active, disabled, revoked)"
// @Param        health          query     string  false  "Filter by automatic health (unknown, online, offline, error)"
// @Param        execution_mode  query     string  false  "Filter by execution mode (standalone, daemon)"
// @Param        capabilities    query     string  false  "Filter by capabilities (comma-separated)"
// @Param        tools           query     string  false  "Filter by tools (comma-separated)"
// @Param        has_capacity    query     bool    false  "Filter by agents with available capacity"
// @Param        search          query     string  false  "Search by name or description"
// @Param        page            query     int     false  "Page number" default(1)
// @Param        per_page        query     int     false  "Items per page" default(20)
// @Success      200  {object}  ListResponse[AgentResponse]
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /agents [get]
func (h *AgentHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())

	input := app.ListAgentsInput{
		TenantID:      tenantID,
		Type:          r.URL.Query().Get("type"),
		Status:        r.URL.Query().Get("status"),
		Health:        r.URL.Query().Get("health"),
		ExecutionMode: r.URL.Query().Get("execution_mode"),
		Search:        r.URL.Query().Get("search"),
		Page:          parseQueryInt(r.URL.Query().Get("page"), 1),
		PerPage:       parseQueryInt(r.URL.Query().Get("per_page"), 20),
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

	result, err := h.service.ListAgents(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	items := make([]*AgentResponse, len(result.Data))
	for i, a := range result.Data {
		items[i] = toAgentResponse(a)
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

// UpdateAgentRequest represents the request body for updating an agent.
type UpdateAgentRequest struct {
	Name              string   `json:"name" validate:"omitempty,min=1,max=255"`
	Description       string   `json:"description" validate:"max=1000"`
	Capabilities      []string `json:"capabilities" validate:"max=20,dive,max=50"`
	Tools             []string `json:"tools" validate:"max=20,dive,max=50"`
	Status            string   `json:"status" validate:"omitempty,oneof=active disabled revoked"` // Admin-controlled
	MaxConcurrentJobs *int     `json:"max_concurrent_jobs" validate:"omitempty,min=1,max=100"`
}

// Update handles PUT /api/v1/agents/{id}
// @Summary      Update agent
// @Description  Update an existing agent
// @Tags         Agents
// @Accept       json
// @Produce      json
// @Param        id    path      string              true  "Agent ID"
// @Param        body  body      UpdateAgentRequest  true  "Update data"
// @Success      200   {object}  AgentResponse
// @Failure      400   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Failure      500   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /agents/{id} [put]
func (h *AgentHandler) Update(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())

	var req UpdateAgentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := app.UpdateAgentInput{
		TenantID:          tenantID,
		AgentID:           agentID,
		Name:              req.Name,
		Description:       req.Description,
		Capabilities:      req.Capabilities,
		Tools:             req.Tools,
		Status:            req.Status,
		MaxConcurrentJobs: req.MaxConcurrentJobs,
	}

	a, err := h.service.UpdateAgent(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toAgentResponse(a))
}

// Delete handles DELETE /api/v1/agents/{id}
// @Summary      Delete agent
// @Description  Delete an agent and revoke its API key
// @Tags         Agents
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Agent ID"
// @Success      204  "No Content"
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /agents/{id} [delete]
func (h *AgentHandler) Delete(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())
	auditCtx := h.buildAuditContext(r)

	if err := h.service.DeleteAgent(r.Context(), tenantID, agentID, auditCtx); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// AgentRegenerateAPIKeyResponse represents the response for regenerating an API key.
type AgentRegenerateAPIKeyResponse struct {
	APIKey string `json:"api_key"`
}

// RegenerateAPIKey handles POST /api/v1/agents/{id}/regenerate-key
// @Summary      Regenerate API key
// @Description  Regenerate the API key for an agent. The old key will be invalidated.
// @Tags         Agents
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Agent ID"
// @Success      200  {object}  AgentRegenerateAPIKeyResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /agents/{id}/regenerate-key [post]
func (h *AgentHandler) RegenerateAPIKey(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())
	auditCtx := h.buildAuditContext(r)

	apiKey, err := h.service.RegenerateAPIKey(r.Context(), tenantID, agentID, auditCtx)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(&AgentRegenerateAPIKeyResponse{APIKey: apiKey})
}

// Activate handles POST /api/v1/agents/{id}/activate
// @Summary      Activate agent
// @Description  Activate an agent (admin action). Allows the agent to authenticate.
// @Tags         Agents
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Agent ID"
// @Success      200  {object}  AgentResponse
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /agents/{id}/activate [post]
func (h *AgentHandler) Activate(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())
	auditCtx := h.buildAuditContext(r)

	a, err := h.service.ActivateAgent(r.Context(), tenantID, agentID, auditCtx)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toAgentResponse(a))
}

// AgentDisableRequest represents the request body for disabling an agent.
type AgentDisableRequest struct {
	Reason string `json:"reason" validate:"max=500"`
}

// Disable handles POST /api/v1/agents/{id}/disable
// @Summary      Disable agent
// @Description  Disable an agent (admin action). Prevents the agent from authenticating.
// @Tags         Agents
// @Accept       json
// @Produce      json
// @Param        id    path      string              true  "Agent ID"
// @Param        body  body      AgentDisableRequest false "Disable reason"
// @Success      200   {object}  AgentResponse
// @Failure      400   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Failure      500   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /agents/{id}/disable [post]
func (h *AgentHandler) Disable(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())
	auditCtx := h.buildAuditContext(r)

	var req AgentDisableRequest
	if r.Body != nil && r.ContentLength > 0 {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}

	a, err := h.service.DisableAgent(r.Context(), tenantID, agentID, req.Reason, auditCtx)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toAgentResponse(a))
}

// AgentRevokeRequest represents the request body for revoking an agent.
type AgentRevokeRequest struct {
	Reason string `json:"reason" validate:"max=500"`
}

// Revoke handles POST /api/v1/agents/{id}/revoke
// @Summary      Revoke agent
// @Description  Permanently revoke an agent's access (admin action). Cannot be undone.
// @Tags         Agents
// @Accept       json
// @Produce      json
// @Param        id    path      string             true  "Agent ID"
// @Param        body  body      AgentRevokeRequest false "Revoke reason"
// @Success      200   {object}  AgentResponse
// @Failure      400   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Failure      500   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /agents/{id}/revoke [post]
func (h *AgentHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())
	auditCtx := h.buildAuditContext(r)

	var req AgentRevokeRequest
	if r.Body != nil && r.ContentLength > 0 {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}

	a, err := h.service.RevokeAgent(r.Context(), tenantID, agentID, req.Reason, auditCtx)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toAgentResponse(a))
}

// toAgentResponse converts an agent entity to response.
func toAgentResponse(a *agent.Agent) *AgentResponse {
	resp := &AgentResponse{
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
func (h *AgentHandler) handleValidationError(w http.ResponseWriter, err error) {
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
func (h *AgentHandler) handleServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Agent").WriteJSON(w)
	case errors.Is(err, shared.ErrAlreadyExists):
		apierror.Conflict("Agent already exists").WriteJSON(w)
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
func (h *AgentHandler) buildAuditContext(r *http.Request) *app.AuditContext {
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
// GET /api/v1/agents/available-capabilities
// @Summary Get available capabilities
// @Description Returns all unique capability names from all agents accessible to the tenant
// @Tags agents
// @Produce json
// @Success 200 {object} AvailableCapabilitiesResponse
// @Failure 401 {object} apierror.Error "Unauthorized"
// @Failure 500 {object} apierror.Error "Internal server error"
// @Router /api/v1/agents/available-capabilities [get]
func (h *AgentHandler) GetAvailableCapabilities(w http.ResponseWriter, r *http.Request) {
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
