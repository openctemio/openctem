// Package handler provides HTTP handlers for the API server.
// This file implements admin audit log endpoints.
package handler

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/api/internal/infra/postgres"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/admin"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// AdminAuditHandler handles admin audit log endpoints.
type AdminAuditHandler struct {
	repo   *postgres.AuditLogRepository
	logger *logger.Logger
}

// NewAdminAuditHandler creates a new AdminAuditHandler.
func NewAdminAuditHandler(repo *postgres.AuditLogRepository, log *logger.Logger) *AdminAuditHandler {
	return &AdminAuditHandler{
		repo:   repo,
		logger: log.With("handler", "admin_audit"),
	}
}

// =============================================================================
// Response Types
// =============================================================================

// AdminAuditLogResponse represents an admin audit log in API responses.
type AdminAuditLogResponse struct {
	ID             string                 `json:"id"`
	AdminID        *string                `json:"admin_id,omitempty"`
	AdminEmail     string                 `json:"admin_email"`
	Action         string                 `json:"action"`
	ResourceType   string                 `json:"resource_type,omitempty"`
	ResourceID     *string                `json:"resource_id,omitempty"`
	ResourceName   string                 `json:"resource_name,omitempty"`
	RequestMethod  string                 `json:"request_method,omitempty"`
	RequestPath    string                 `json:"request_path,omitempty"`
	RequestBody    map[string]interface{} `json:"request_body,omitempty"`
	ResponseStatus int                    `json:"response_status,omitempty"`
	IPAddress      string                 `json:"ip_address,omitempty"`
	UserAgent      string                 `json:"user_agent,omitempty"`
	Success        bool                   `json:"success"`
	ErrorMessage   string                 `json:"error_message,omitempty"`
	CreatedAt      string                 `json:"created_at"`
}

// AdminAuditLogListResponse represents a paginated list of admin audit logs.
type AdminAuditLogListResponse struct {
	Data       []AdminAuditLogResponse `json:"data"`
	Total      int64                   `json:"total"`
	Page       int                     `json:"page"`
	PerPage    int                     `json:"per_page"`
	TotalPages int                     `json:"total_pages"`
}

// =============================================================================
// Handlers
// =============================================================================

// List lists audit logs with filtering and pagination.
// @Summary List admin audit logs
// @Description Returns a paginated list of audit logs. Requires Admin API Key.
// @Tags Admin Audit Logs
// @Accept json
// @Produce json
// @Param page query int false "Page number"
// @Param per_page query int false "Items per page"
// @Param admin_email query string false "Filter by admin email"
// @Param action query string false "Filter by action"
// @Param resource_type query string false "Filter by resource type"
// @Param search query string false "Search term"
// @Param admin_id query string false "Filter by admin ID"
// @Param resource_id query string false "Filter by resource ID"
// @Param success query boolean false "Filter by success status"
// @Param from query string false "Start time (RFC3339)"
// @Param to query string false "End time (RFC3339)"
// @Success 200 {object} AdminAuditLogListResponse
// @Failure 401 {object} apierror.Error "Unauthorized"
// @Failure 500 {object} apierror.Error "Internal Server Error"
// @Router /admin/audit-logs [get]
func (h *AdminAuditHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse pagination
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if perPage < 1 || perPage > 100 {
		perPage = 20
	}

	// Parse filters
	filter := admin.AuditLogFilter{
		AdminEmail:   r.URL.Query().Get("admin_email"),
		Action:       r.URL.Query().Get("action"),
		ResourceType: r.URL.Query().Get("resource_type"),
		Search:       r.URL.Query().Get("search"),
	}

	// Parse admin_id filter
	if adminIDStr := r.URL.Query().Get("admin_id"); adminIDStr != "" {
		adminID, err := shared.IDFromString(adminIDStr)
		if err == nil {
			filter.AdminID = &adminID
		}
	}

	// Parse resource_id filter
	if resourceIDStr := r.URL.Query().Get("resource_id"); resourceIDStr != "" {
		resourceID, err := shared.IDFromString(resourceIDStr)
		if err == nil {
			filter.ResourceID = &resourceID
		}
	}

	// Parse success filter
	if successStr := r.URL.Query().Get("success"); successStr != "" {
		success := successStr == queryParamTrue || successStr == "1"
		filter.Success = &success
	}

	// Parse time range filters
	if fromStr := r.URL.Query().Get("from"); fromStr != "" {
		if t, err := time.Parse(time.RFC3339, fromStr); err == nil {
			filter.StartTime = &t
		}
	}
	if toStr := r.URL.Query().Get("to"); toStr != "" {
		if t, err := time.Parse(time.RFC3339, toStr); err == nil {
			filter.EndTime = &t
		}
	}

	// Fetch audit logs
	result, err := h.repo.List(ctx, filter, pagination.Pagination{Page: page, PerPage: perPage})
	if err != nil {
		h.logger.Error("failed to list audit logs", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	// Build response
	logs := make([]AdminAuditLogResponse, 0, len(result.Data))
	for _, log := range result.Data {
		logs = append(logs, toAdminAuditLogResponse(log))
	}

	response := AdminAuditLogListResponse{
		Data:       logs,
		Total:      result.Total,
		Page:       result.Page,
		PerPage:    result.PerPage,
		TotalPages: result.TotalPages,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

// Get retrieves a single audit log.
// @Summary Get audit log
// @Description Returns a single audit log by ID. Requires Admin API Key.
// @Tags Admin Audit Logs
// @Accept json
// @Produce json
// @Param id path string true "Audit Log ID"
// @Success 200 {object} AdminAuditLogResponse
// @Failure 401 {object} apierror.Error "Unauthorized"
// @Failure 404 {object} apierror.Error "Not Found"
// @Failure 500 {object} apierror.Error "Internal Server Error"
// @Router /admin/audit-logs/{id} [get]
func (h *AdminAuditHandler) Get(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := chi.URLParam(r, "id")

	id, err := shared.IDFromString(idStr)
	if err != nil {
		apierror.BadRequest("invalid audit log id").WriteJSON(w)
		return
	}

	log, err := h.repo.GetByID(ctx, id)
	if err != nil {
		if admin.IsAuditLogNotFound(err) {
			apierror.NotFound("AuditLog").WriteJSON(w)
			return
		}
		h.logger.Error("failed to get audit log", "error", err, "id", idStr)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toAdminAuditLogResponse(log))
}

// GetStats returns audit log statistics.
// @Summary Get audit log statistics
// @Description Returns statistics about audit logs (total, failed actions). Requires Admin API Key.
// @Tags Admin Audit Logs
// @Accept json
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Failure 401 {object} apierror.Error "Unauthorized"
// @Failure 500 {object} apierror.Error "Internal Server Error"
// @Router /admin/audit-logs/stats [get]
func (h *AdminAuditHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get total count
	totalCount, err := h.repo.Count(ctx, admin.AuditLogFilter{})
	if err != nil {
		h.logger.Error("failed to count audit logs", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	// Get failed actions count (last 24h)
	oneDayAgo := time.Now().Add(-24 * time.Hour)
	failedFilter := admin.AuditLogFilter{
		StartTime: &oneDayAgo,
	}
	success := false
	failedFilter.Success = &success

	failedCount, err := h.repo.Count(ctx, failedFilter)
	if err != nil {
		h.logger.Error("failed to count failed actions", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	// Get recent actions
	recentActions, err := h.repo.GetRecentActions(ctx, 10)
	if err != nil {
		h.logger.Error("failed to get recent actions", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	recent := make([]AdminAuditLogResponse, 0, len(recentActions))
	for _, log := range recentActions {
		recent = append(recent, toAdminAuditLogResponse(log))
	}

	response := map[string]interface{}{
		"total":          totalCount,
		"failed_24h":     failedCount,
		"recent_actions": recent,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

// =============================================================================
// Helpers
// =============================================================================

func toAdminAuditLogResponse(log *admin.AuditLog) AdminAuditLogResponse {
	resp := AdminAuditLogResponse{
		ID:             log.ID.String(),
		AdminEmail:     log.AdminEmail,
		Action:         log.Action,
		ResourceType:   log.ResourceType,
		ResourceName:   log.ResourceName,
		RequestMethod:  log.RequestMethod,
		RequestPath:    log.RequestPath,
		RequestBody:    log.RequestBody,
		ResponseStatus: log.ResponseStatus,
		IPAddress:      log.IPAddress,
		UserAgent:      log.UserAgent,
		Success:        log.Success,
		ErrorMessage:   log.ErrorMessage,
		CreatedAt:      log.CreatedAt.Format(time.RFC3339),
	}

	if log.AdminID != nil {
		s := log.AdminID.String()
		resp.AdminID = &s
	}
	if log.ResourceID != nil {
		s := log.ResourceID.String()
		resp.ResourceID = &s
	}

	return resp
}
