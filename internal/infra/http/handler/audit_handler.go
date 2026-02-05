package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/audit"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/validator"
)

// AuditHandler handles audit log-related HTTP requests.
type AuditHandler struct {
	service   *app.AuditService
	validator *validator.Validator
	logger    *logger.Logger
}

// NewAuditHandler creates a new audit handler.
func NewAuditHandler(svc *app.AuditService, v *validator.Validator, log *logger.Logger) *AuditHandler {
	return &AuditHandler{
		service:   svc,
		validator: v,
		logger:    log,
	}
}

// =============================================================================
// Response Types
// =============================================================================

// AuditLogResponse represents an audit log in API responses.
type AuditLogResponse struct {
	ID           string         `json:"id"`
	TenantID     string         `json:"tenant_id,omitempty"`
	ActorID      string         `json:"actor_id,omitempty"`
	ActorEmail   string         `json:"actor_email"`
	ActorIP      string         `json:"actor_ip,omitempty"`
	Action       string         `json:"action"`
	ResourceType string         `json:"resource_type"`
	ResourceID   string         `json:"resource_id"`
	ResourceName string         `json:"resource_name,omitempty"`
	Changes      *audit.Changes `json:"changes,omitempty"`
	Result       string         `json:"result"`
	Severity     string         `json:"severity"`
	Message      string         `json:"message"`
	Metadata     map[string]any `json:"metadata,omitempty"`
	RequestID    string         `json:"request_id,omitempty"`
	Timestamp    time.Time      `json:"timestamp"`
}

// AuditLogListResponse represents a paginated list of audit logs.
type AuditLogListResponse struct {
	Data       []AuditLogResponse `json:"data"`
	Total      int64              `json:"total"`
	Page       int                `json:"page"`
	PerPage    int                `json:"per_page"`
	TotalPages int                `json:"total_pages"`
}

// =============================================================================
// Response Converters
// =============================================================================

func toAuditLogResponse(log *audit.AuditLog) AuditLogResponse {
	resp := AuditLogResponse{
		ID:           log.ID().String(),
		ActorEmail:   log.ActorEmail(),
		ActorIP:      log.ActorIP(),
		Action:       log.Action().String(),
		ResourceType: log.ResourceType().String(),
		ResourceID:   log.ResourceID(),
		ResourceName: log.ResourceName(),
		Changes:      log.Changes(),
		Result:       log.Result().String(),
		Severity:     log.Severity().String(),
		Message:      log.Message(),
		Metadata:     log.Metadata(),
		RequestID:    log.RequestID(),
		Timestamp:    log.Timestamp(),
	}

	if log.TenantID() != nil {
		resp.TenantID = log.TenantID().String()
	}
	if log.ActorID() != nil {
		resp.ActorID = log.ActorID().String()
	}

	// Generate message if empty
	if resp.Message == "" {
		resp.Message = log.GenerateMessage()
	}

	return resp
}

// =============================================================================
// Error Handlers
// =============================================================================

func (h *AuditHandler) handleServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Audit log").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	default:
		h.logger.Error("audit service error", "error", err)
		apierror.InternalError(err).WriteJSON(w)
	}
}

// =============================================================================
// Handlers
// =============================================================================

// List handles GET /api/v1/audit-logs
// @Summary      List audit logs
// @Description  Returns paginated audit logs for the current tenant
// @Tags         Audit Logs
// @Produce      json
// @Security     BearerAuth
// @Param        page          query     int     false  "Page number"
// @Param        per_page      query     int     false  "Items per page"  default(20)
// @Param        actor_id      query     string  false  "Filter by actor ID"
// @Param        action        query     string  false  "Filter by action"
// @Param        resource_type query     string  false  "Filter by resource type"
// @Param        resource_id   query     string  false  "Filter by resource ID"
// @Param        result        query     string  false  "Filter by result"
// @Param        severity      query     string  false  "Filter by severity"
// @Param        since         query     string  false  "Filter since (RFC3339)"
// @Param        until         query     string  false  "Filter until (RFC3339)"
// @Param        search        query     string  false  "Search term"
// @Success      200  {object}  AuditLogListResponse
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Router       /audit-logs [get]
func (h *AuditHandler) List(w http.ResponseWriter, r *http.Request) {
	// Get tenant ID from context (required for tenant-scoped logs)
	tenantID := middleware.GetTenantID(r.Context())
	if tenantID == "" {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}

	// Parse query parameters
	query := r.URL.Query()

	input := app.ListAuditLogsInput{
		TenantID: tenantID,
	}

	// Parse pagination
	if page := query.Get("page"); page != "" {
		if p, err := strconv.Atoi(page); err == nil {
			input.Page = p
		}
	}
	if perPage := query.Get("per_page"); perPage != "" {
		if pp, err := strconv.Atoi(perPage); err == nil {
			input.PerPage = pp
		}
	}
	if input.PerPage == 0 {
		input.PerPage = 20 // Default
	}

	// Parse filters
	if actorID := query.Get("actor_id"); actorID != "" {
		input.ActorID = actorID
	}

	if actions := query["action"]; len(actions) > 0 {
		input.Actions = actions
	}

	if resourceTypes := query["resource_type"]; len(resourceTypes) > 0 {
		input.ResourceTypes = resourceTypes
	}

	if resourceID := query.Get("resource_id"); resourceID != "" {
		input.ResourceID = resourceID
	}

	if results := query["result"]; len(results) > 0 {
		input.Results = results
	}

	if severities := query["severity"]; len(severities) > 0 {
		input.Severities = severities
	}

	if requestID := query.Get("request_id"); requestID != "" {
		input.RequestID = requestID
	}

	if since := query.Get("since"); since != "" {
		if t, err := time.Parse(time.RFC3339, since); err == nil {
			input.Since = &t
		}
	}

	if until := query.Get("until"); until != "" {
		if t, err := time.Parse(time.RFC3339, until); err == nil {
			input.Until = &t
		}
	}

	if search := query.Get("search"); search != "" {
		input.SearchTerm = search
	}

	if sortBy := query.Get("sort_by"); sortBy != "" {
		input.SortBy = sortBy
	}

	if sortOrder := query.Get("sort_order"); sortOrder != "" {
		input.SortOrder = sortOrder
	}

	if excludeSystem := query.Get("exclude_system"); excludeSystem == queryParamTrue {
		input.ExcludeSystem = true
	}

	// Execute query
	result, err := h.service.ListAuditLogs(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// Convert to response
	data := make([]AuditLogResponse, len(result.Data))
	for i, log := range result.Data {
		data[i] = toAuditLogResponse(log)
	}

	totalPages := int(result.Total) / input.PerPage
	if int(result.Total)%input.PerPage > 0 {
		totalPages++
	}

	response := AuditLogListResponse{
		Data:       data,
		Total:      result.Total,
		Page:       input.Page,
		PerPage:    input.PerPage,
		TotalPages: totalPages,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

// Get handles GET /api/v1/audit-logs/{id}
// @Summary      Get audit log
// @Description  Returns a single audit log by ID
// @Tags         Audit Logs
// @Produce      json
// @Security     BearerAuth
// @Param        id   path      string  true  "Audit Log ID"
// @Success      200  {object}  AuditLogResponse
// @Failure      400  {object}  map[string]string
// @Failure      403  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /audit-logs/{id} [get]
func (h *AuditHandler) Get(w http.ResponseWriter, r *http.Request) {
	auditLogID := r.PathValue("id")
	if auditLogID == "" {
		apierror.BadRequest("Audit log ID is required").WriteJSON(w)
		return
	}

	log, err := h.service.GetAuditLog(r.Context(), auditLogID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// Verify tenant access
	tenantID := middleware.GetTenantID(r.Context())
	if tenantID != "" {
		tid, err := shared.IDFromString(tenantID)
		if err != nil {
			apierror.Unauthorized("Invalid tenant token").WriteJSON(w)
			return
		}
		if log.TenantID() != nil && *log.TenantID() != tid {
			apierror.Forbidden("Access denied to this audit log").WriteJSON(w)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toAuditLogResponse(log))
}

// GetResourceHistory handles GET /api/v1/audit-logs/resource/{type}/{id}
// @Summary      Get resource history
// @Description  Returns audit history for a specific resource
// @Tags         Audit Logs
// @Produce      json
// @Security     BearerAuth
// @Param        type      path      string  true   "Resource type"
// @Param        id        path      string  true   "Resource ID"
// @Param        page      query     int     false  "Page number"
// @Param        per_page  query     int     false  "Items per page"  default(20)
// @Success      200  {object}  AuditLogListResponse
// @Failure      400  {object}  map[string]string
// @Router       /audit-logs/resource/{type}/{id} [get]
func (h *AuditHandler) GetResourceHistory(w http.ResponseWriter, r *http.Request) {
	resourceType := r.PathValue("type")
	resourceID := r.PathValue("id")

	if resourceType == "" || resourceID == "" {
		apierror.BadRequest("Resource type and ID are required").WriteJSON(w)
		return
	}

	// Parse pagination
	query := r.URL.Query()
	page := 0
	perPage := 20

	if p := query.Get("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil {
			page = parsed
		}
	}
	if pp := query.Get("per_page"); pp != "" {
		if parsed, err := strconv.Atoi(pp); err == nil {
			perPage = parsed
		}
	}

	result, err := h.service.GetResourceHistory(r.Context(), resourceType, resourceID, page, perPage)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// Convert to response
	data := make([]AuditLogResponse, len(result.Data))
	for i, log := range result.Data {
		data[i] = toAuditLogResponse(log)
	}

	totalPages := int(result.Total) / perPage
	if int(result.Total)%perPage > 0 {
		totalPages++
	}

	response := AuditLogListResponse{
		Data:       data,
		Total:      result.Total,
		Page:       page,
		PerPage:    perPage,
		TotalPages: totalPages,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

// GetUserActivity handles GET /api/v1/audit-logs/user/{id}
// @Summary      Get user activity
// @Description  Returns audit logs for a specific user
// @Tags         Audit Logs
// @Produce      json
// @Security     BearerAuth
// @Param        id        path      string  true   "User ID"
// @Param        page      query     int     false  "Page number"
// @Param        per_page  query     int     false  "Items per page"  default(20)
// @Success      200  {object}  AuditLogListResponse
// @Failure      400  {object}  map[string]string
// @Router       /audit-logs/user/{id} [get]
func (h *AuditHandler) GetUserActivity(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")
	if userID == "" {
		apierror.BadRequest("User ID is required").WriteJSON(w)
		return
	}

	// Parse pagination
	query := r.URL.Query()
	page := 0
	perPage := 20

	if p := query.Get("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil {
			page = parsed
		}
	}
	if pp := query.Get("per_page"); pp != "" {
		if parsed, err := strconv.Atoi(pp); err == nil {
			perPage = parsed
		}
	}

	result, err := h.service.GetUserActivity(r.Context(), userID, page, perPage)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// Convert to response
	data := make([]AuditLogResponse, len(result.Data))
	for i, log := range result.Data {
		data[i] = toAuditLogResponse(log)
	}

	totalPages := int(result.Total) / perPage
	if int(result.Total)%perPage > 0 {
		totalPages++
	}

	response := AuditLogListResponse{
		Data:       data,
		Total:      result.Total,
		Page:       page,
		PerPage:    perPage,
		TotalPages: totalPages,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

// GetStats handles GET /api/v1/audit-logs/stats
// Returns audit log statistics.
type AuditStatsResponse struct {
	TotalLogs     int64              `json:"total_logs"`
	LogsByAction  map[string]int64   `json:"logs_by_action"`
	LogsByResult  map[string]int64   `json:"logs_by_result"`
	RecentActions []AuditLogResponse `json:"recent_actions"`
}

// GetStats handles GET /api/v1/audit-logs/stats
// @Summary      Get audit stats
// @Description  Returns audit log statistics for the last 7 days
// @Tags         Audit Logs
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  AuditStatsResponse
// @Failure      400  {object}  map[string]string
// @Router       /audit-logs/stats [get]
func (h *AuditHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())
	if tenantID == "" {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}

	// Get recent logs for stats
	input := app.ListAuditLogsInput{
		TenantID: tenantID,
		Page:     0,
		PerPage:  100,
	}

	// Last 7 days
	since := time.Now().AddDate(0, 0, -7)
	input.Since = &since

	result, err := h.service.ListAuditLogs(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// Calculate stats
	logsByAction := make(map[string]int64)
	logsByResult := make(map[string]int64)

	for _, log := range result.Data {
		logsByAction[log.Action().String()]++
		logsByResult[log.Result().String()]++
	}

	// Get recent 5 actions for display
	recentLimit := 5
	if len(result.Data) < recentLimit {
		recentLimit = len(result.Data)
	}
	recentActions := make([]AuditLogResponse, recentLimit)
	for i := 0; i < recentLimit; i++ {
		recentActions[i] = toAuditLogResponse(result.Data[i])
	}

	response := AuditStatsResponse{
		TotalLogs:     result.Total,
		LogsByAction:  logsByAction,
		LogsByResult:  logsByResult,
		RecentActions: recentActions,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}
