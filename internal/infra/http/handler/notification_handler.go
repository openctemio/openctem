package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/notification"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// NotificationHandler handles user notification endpoints.
type NotificationHandler struct {
	service *app.NotificationService
	logger  *logger.Logger
}

// NewNotificationHandler creates a new NotificationHandler.
func NewNotificationHandler(svc *app.NotificationService, log *logger.Logger) *NotificationHandler {
	return &NotificationHandler{
		service: svc,
		logger:  log.With("handler", "notification"),
	}
}

// =============================================================================
// Request / Response Types
// =============================================================================

// NotificationResponse represents a notification in API responses.
type NotificationResponse struct {
	ID        string `json:"id"`
	TenantID  string `json:"tenant_id"`
	Audience  string `json:"audience"`
	Severity  string `json:"severity"`
	Type      string `json:"type"`
	Title     string `json:"title"`
	Body      string `json:"body"`
	Link      string `json:"link,omitempty"`
	ActorID   string `json:"actor_id,omitempty"`
	IsRead    bool   `json:"is_read"`
	CreatedAt string `json:"created_at"`
}

// UnreadCountResponse represents the unread notification count.
type UnreadCountResponse struct {
	Count int `json:"count"`
}

// PreferencesResponse represents notification preferences in API responses.
type PreferencesResponse struct {
	InAppEnabled bool     `json:"in_app_enabled"`
	EmailDigest  string   `json:"email_digest"`
	MutedTypes   []string `json:"muted_types"`
	MinSeverity  string   `json:"min_severity"`
	UpdatedAt    string   `json:"updated_at"`
}

// NotificationPreferencesRequest represents the request body for updating preferences.
type NotificationPreferencesRequest struct {
	InAppEnabled *bool    `json:"in_app_enabled"`
	EmailDigest  *string  `json:"email_digest"`
	MutedTypes   []string `json:"muted_types"`
	MinSeverity  *string  `json:"min_severity"`
}

// =============================================================================
// Handlers
// =============================================================================

// List godoc
// @Summary List notifications
// @Description List notifications for the current user with filtering and pagination
// @Tags notifications
// @Accept json
// @Produce json
// @Param page query int false "Page number" default(1)
// @Param per_page query int false "Items per page" default(20)
// @Param severity query string false "Filter by severity"
// @Param type query string false "Filter by notification type"
// @Param is_read query string false "Filter by read status (true/false)"
// @Success 200 {object} pagination.Result[NotificationResponse]
// @Failure 401 {object} apierror.Response
// @Failure 500 {object} apierror.Response
// @Router /notifications [get]
// @Security BearerAuth
func (h *NotificationHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	tenantID, userID, ok := h.extractTenantAndUser(w, r)
	if !ok {
		return
	}

	// Parse pagination
	page := 1
	perPage := 20
	if p := r.URL.Query().Get("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			page = parsed
		}
	}
	if ps := r.URL.Query().Get("per_page"); ps != "" {
		if parsed, err := strconv.Atoi(ps); err == nil && parsed > 0 && parsed <= 100 {
			perPage = parsed
		}
	}

	// Build filter
	filter := notification.ListFilter{
		Severity: r.URL.Query().Get("severity"),
		Type:     r.URL.Query().Get("type"),
	}
	if isReadStr := r.URL.Query().Get("is_read"); isReadStr != "" {
		isRead := isReadStr == "true"
		filter.IsRead = &isRead
	}

	pag := pagination.New(page, perPage)
	result, err := h.service.ListNotifications(ctx, tenantID, userID, filter, pag)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// Convert to response
	items := make([]NotificationResponse, 0, len(result.Data))
	for _, n := range result.Data {
		items = append(items, toNotificationResponse(n))
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(pagination.Result[NotificationResponse]{
		Data:       items,
		Total:      result.Total,
		Page:       result.Page,
		PerPage:    result.PerPage,
		TotalPages: result.TotalPages,
	})
}

// GetUnreadCount godoc
// @Summary Get unread notification count
// @Description Get the number of unread notifications for the current user
// @Tags notifications
// @Accept json
// @Produce json
// @Success 200 {object} UnreadCountResponse
// @Failure 401 {object} apierror.Response
// @Failure 500 {object} apierror.Response
// @Router /notifications/unread-count [get]
// @Security BearerAuth
func (h *NotificationHandler) GetUnreadCount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	tenantID, userID, ok := h.extractTenantAndUser(w, r)
	if !ok {
		return
	}

	count, err := h.service.GetUnreadCount(ctx, tenantID, userID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(UnreadCountResponse{Count: count})
}

// MarkAsRead godoc
// @Summary Mark notification as read
// @Description Mark a single notification as read for the current user
// @Tags notifications
// @Accept json
// @Produce json
// @Param id path string true "Notification ID"
// @Success 204 "No Content"
// @Failure 400 {object} apierror.Response
// @Failure 401 {object} apierror.Response
// @Failure 404 {object} apierror.Response
// @Failure 500 {object} apierror.Response
// @Router /notifications/{id}/read [patch]
// @Security BearerAuth
func (h *NotificationHandler) MarkAsRead(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	_, userID, ok := h.extractTenantAndUser(w, r)
	if !ok {
		return
	}

	id := chi.URLParam(r, "id")
	notificationID, err := notification.ParseID(id)
	if err != nil {
		apierror.BadRequest("invalid notification id").WriteJSON(w)
		return
	}

	if err := h.service.MarkAsRead(ctx, notificationID, userID); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// MarkAllAsRead godoc
// @Summary Mark all notifications as read
// @Description Mark all notifications as read for the current user in the current tenant
// @Tags notifications
// @Accept json
// @Produce json
// @Success 204 "No Content"
// @Failure 401 {object} apierror.Response
// @Failure 500 {object} apierror.Response
// @Router /notifications/read-all [post]
// @Security BearerAuth
func (h *NotificationHandler) MarkAllAsRead(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	tenantID, userID, ok := h.extractTenantAndUser(w, r)
	if !ok {
		return
	}

	if err := h.service.MarkAllAsRead(ctx, tenantID, userID); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GetPreferences godoc
// @Summary Get notification preferences
// @Description Get notification preferences for the current user
// @Tags notifications
// @Accept json
// @Produce json
// @Success 200 {object} PreferencesResponse
// @Failure 401 {object} apierror.Response
// @Failure 500 {object} apierror.Response
// @Router /notifications/preferences [get]
// @Security BearerAuth
func (h *NotificationHandler) GetPreferences(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	tenantID, userID, ok := h.extractTenantAndUser(w, r)
	if !ok {
		return
	}

	prefs, err := h.service.GetPreferences(ctx, tenantID, userID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toPreferencesResponse(prefs))
}

// UpdatePreferences godoc
// @Summary Update notification preferences
// @Description Update notification preferences for the current user
// @Tags notifications
// @Accept json
// @Produce json
// @Param body body NotificationPreferencesRequest true "Updated preferences"
// @Success 200 {object} PreferencesResponse
// @Failure 400 {object} apierror.Response
// @Failure 401 {object} apierror.Response
// @Failure 422 {object} apierror.Response
// @Failure 500 {object} apierror.Response
// @Router /notifications/preferences [put]
// @Security BearerAuth
func (h *NotificationHandler) UpdatePreferences(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	tenantID, userID, ok := h.extractTenantAndUser(w, r)
	if !ok {
		return
	}

	var req NotificationPreferencesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}

	input := app.UpdatePreferencesInput{
		InAppEnabled: req.InAppEnabled,
		EmailDigest:  req.EmailDigest,
		MutedTypes:   req.MutedTypes,
		MinSeverity:  req.MinSeverity,
	}

	prefs, err := h.service.UpdatePreferences(ctx, tenantID, userID, input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toPreferencesResponse(prefs))
}

// =============================================================================
// Helpers
// =============================================================================

// extractTenantAndUser extracts tenant and user IDs from the request context.
// Returns false if extraction fails (error response is already written).
func (h *NotificationHandler) extractTenantAndUser(w http.ResponseWriter, r *http.Request) (shared.ID, shared.ID, bool) {
	tenantIDStr := middleware.GetTenantID(r.Context())
	if tenantIDStr == "" {
		apierror.Unauthorized("tenant context required").WriteJSON(w)
		return shared.ID{}, shared.ID{}, false
	}

	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		apierror.BadRequest("invalid tenant id").WriteJSON(w)
		return shared.ID{}, shared.ID{}, false
	}

	userIDStr := middleware.GetUserID(r.Context())
	if userIDStr == "" {
		apierror.Unauthorized("user context required").WriteJSON(w)
		return shared.ID{}, shared.ID{}, false
	}

	userID, err := shared.IDFromString(userIDStr)
	if err != nil {
		apierror.BadRequest("invalid user id").WriteJSON(w)
		return shared.ID{}, shared.ID{}, false
	}

	return tenantID, userID, true
}

// handleServiceError maps domain/service errors to HTTP error responses.
func (h *NotificationHandler) handleServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, notification.ErrNotificationNotFound):
		apierror.NotFound("notification").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.ValidationFailed(err.Error(), nil).WriteJSON(w)
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("resource").WriteJSON(w)
	default:
		h.logger.Error("notification handler error", "error", err)
		apierror.InternalError(err).WriteJSON(w)
	}
}

// toNotificationResponse converts a domain notification to an API response.
func toNotificationResponse(n *notification.Notification) NotificationResponse {
	resp := NotificationResponse{
		ID:        n.ID().String(),
		TenantID:  n.TenantID().String(),
		Audience:  n.Audience(),
		Severity:  n.Severity(),
		Type:      n.NotificationType(),
		Title:     n.Title(),
		Body:      n.Body(),
		Link:      n.URL(),
		IsRead:    n.IsRead(),
		CreatedAt: n.CreatedAt().Format("2006-01-02T15:04:05Z07:00"),
	}

	if n.ActorID() != nil {
		resp.ActorID = n.ActorID().String()
	}

	return resp
}

// toPreferencesResponse converts domain preferences to an API response.
func toPreferencesResponse(p *notification.Preferences) PreferencesResponse {
	mutedTypes := p.MutedTypes()
	if mutedTypes == nil {
		mutedTypes = []string{}
	}

	return PreferencesResponse{
		InAppEnabled: p.InAppEnabled(),
		EmailDigest:  p.EmailDigest(),
		MutedTypes:   mutedTypes,
		MinSeverity:  p.MinSeverity(),
		UpdatedAt:    p.UpdatedAt().Format("2006-01-02T15:04:05Z07:00"),
	}
}
