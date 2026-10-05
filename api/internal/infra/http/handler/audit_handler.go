package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/openctemio/openctem/api/internal/app"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
	"github.com/openctemio/openctem/api/pkg/validator"
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

// VerifyChain walks the tenant's audit hash-chain and reports any
// tamper evidence. Tenant-admin scoped; returns JSON with OK + breaks.
//
// GET /api/v1/audit/verify[?limit=10000]
func (h *AuditHandler) VerifyChain(w http.ResponseWriter, r *http.Request) {
	tenantIDStr := middleware.GetTenantID(r.Context())
	if tenantIDStr == "" {
		apierror.Unauthorized("tenant required").WriteJSON(w)
		return
	}
	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		apierror.BadRequest("invalid tenant id").WriteJSON(w)
		return
	}

	// Cap at the handler boundary so CodeQL's data-flow analysis sees the
	// bound at the first sink; service + repo re-cap as defense in depth.
	const maxVerifyChainLimit = 10_000
	limit := parseQueryIntBounded(r.URL.Query().Get("limit"), 0, 0, maxVerifyChainLimit)

	result, err := h.service.VerifyChain(r.Context(), tenantID, limit)
	if err != nil {
		h.logger.Error("audit chain verify failed",
			"tenant_id", tenantIDStr, "error", err)
		apierror.InternalServerError("verify failed").WriteJSON(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if !result.OK {
		// 409 signals "state is inconsistent"; body carries details.
		w.WriteHeader(http.StatusConflict)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	_ = json.NewEncoder(w).Encode(result)
}

// RebaselineChain handles POST /api/v1/audit-logs/rebaseline. Admin-only. It
// re-signs the tenant's audit hash-chain from current data — used to clear breaks
// from a known-benign hashing change (e.g. the timestamp-precision fix). This
// overwrites the tamper-evident chain, so the old hashes are archived and the
// action is recorded as a critical audit.chain_rebaselined event.
//
// 200 {ok, rebaseline_id, entries_total, entries_rewritten}; 409 when the chain
// cannot be rebaselined as it stands (a source audit log is missing, or the
// chain changed while the rebaseline ran) — nothing is rewritten in that case.
func (h *AuditHandler) RebaselineChain(w http.ResponseWriter, r *http.Request) {
	tenantIDStr := middleware.GetTenantID(r.Context())
	if tenantIDStr == "" {
		apierror.Unauthorized("tenant required").WriteJSON(w)
		return
	}
	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		apierror.BadRequest("invalid tenant id").WriteJSON(w)
		return
	}

	actx := app.AuditContext{
		TenantID:   tenantIDStr,
		ActorID:    middleware.GetUserID(r.Context()),
		ActorEmail: auditActorEmail(r.Context()),
		ActorIP:    getClientIP(r),
		UserAgent:  r.UserAgent(),
		RequestID:  middleware.GetRequestID(r.Context()),
	}
	result, err := h.service.RebaselineChain(r.Context(), tenantID, actx)
	if err != nil {
		h.logger.Error("audit chain rebaseline failed", "tenant_id", tenantIDStr, "error", err)
		if errors.Is(err, shared.ErrConflict) {
			apierror.Conflict("audit chain cannot be rebaselined as it stands; nothing was changed — run verify and chainaudit").WriteJSON(w)
			return
		}
		apierror.InternalServerError("rebaseline failed").WriteJSON(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(RebaselineChainResponse{
		OK:               true,
		RebaselineID:     result.RebaselineID,
		EntriesTotal:     result.EntriesTotal,
		EntriesRewritten: result.EntriesRewritten,
	})
}

// RebaselineChainResponse is the body of a successful POST /audit-logs/rebaseline.
type RebaselineChainResponse struct {
	OK bool `json:"ok"`
	// RebaselineID keys the archive of overwritten hashes
	// (audit_chain_rebaselines / audit_chain_rebaseline_entries).
	RebaselineID     string `json:"rebaseline_id"`
	EntriesTotal     int    `json:"entries_total"`
	EntriesRewritten int    `json:"entries_rewritten"`
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
// @Param        page          query     int     false  "Page number (1-based; 0 or missing means 1)"
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

	response := newAuditLogListResponse(data, result.Total, input.Page, input.PerPage)

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

	// This is the tenant-facing getter: it never exposes a system row
	// (tenant_id IS NULL) or another tenant's row. The lookup is scoped to
	// the caller's tenant, so either one is a 404. Fail closed on a missing
	// tenant.
	tenantID := middleware.GetTenantID(r.Context())
	if tenantID == "" {
		apierror.Unauthorized("tenant context required").WriteJSON(w)
		return
	}
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		apierror.Unauthorized("Invalid tenant token").WriteJSON(w)
		return
	}

	log, err := h.service.GetAuditLog(r.Context(), tid, auditLogID)
	if err != nil {
		h.handleServiceError(w, err)
		return
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
// @Param        page      query     int     false  "Page number (1-based; 0 or missing means 1)"
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

	// F-2: tenant scope is mandatory for resource audit history.
	tenantID, ok := middleware.GetTenantIDFromContext(r.Context())
	if !ok {
		apierror.Unauthorized("tenant context required").WriteJSON(w)
		return
	}

	// Parse pagination
	query := r.URL.Query()
	page := 1
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
	if perPage <= 0 {
		perPage = 20 // guard: ?per_page=0 → int(Total)/perPage divide-by-zero panic below
	}

	result, err := h.service.GetResourceHistory(r.Context(), tenantID, resourceType, resourceID, page, perPage)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// Convert to response
	data := make([]AuditLogResponse, len(result.Data))
	for i, log := range result.Data {
		data[i] = toAuditLogResponse(log)
	}

	response := newAuditLogListResponse(data, result.Total, page, perPage)

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
// @Param        page      query     int     false  "Page number (1-based; 0 or missing means 1)"
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

	// Tenant scope is mandatory: without it ListByActor would return the
	// actor's activity across every tenant (cross-tenant audit-log read).
	tenantID, ok := middleware.GetTenantIDFromContext(r.Context())
	if !ok {
		apierror.Unauthorized("tenant context required").WriteJSON(w)
		return
	}

	// Parse pagination
	query := r.URL.Query()
	page := 1
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
	if perPage <= 0 {
		perPage = 20 // guard: ?per_page=0 → int(Total)/perPage divide-by-zero panic below
	}

	result, err := h.service.GetUserActivity(r.Context(), tenantID, userID, page, perPage)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// Convert to response
	data := make([]AuditLogResponse, len(result.Data))
	for i, log := range result.Data {
		data[i] = toAuditLogResponse(log)
	}

	response := newAuditLogListResponse(data, result.Total, page, perPage)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

// newAuditLogListResponse builds a list response that reports the page the
// query actually used. Pages are 1-based on the wire: pagination.New clamps a
// missing or zero page to 1 and per_page to [1,100], and the response echoes
// those values, not the raw query, so a client that trusts "page" cannot
// drift off by one.
func newAuditLogListResponse(data []AuditLogResponse, total int64, page, perPage int) AuditLogListResponse {
	p := pagination.New(page, perPage)
	totalPages := int(total) / p.PerPage
	if int(total)%p.PerPage > 0 {
		totalPages++
	}
	return AuditLogListResponse{
		Data:       data,
		Total:      total,
		Page:       p.Page,
		PerPage:    p.PerPage,
		TotalPages: totalPages,
	}
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
