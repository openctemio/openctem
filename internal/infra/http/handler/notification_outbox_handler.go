package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/notification"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
	"github.com/go-chi/chi/v5"
)

// NotificationOutboxHandler handles notification outbox operations for tenants.
type NotificationOutboxHandler struct {
	repo   notification.OutboxRepository
	logger *logger.Logger
}

// NewNotificationOutboxHandler creates a new NotificationOutboxHandler.
func NewNotificationOutboxHandler(repo notification.OutboxRepository, log *logger.Logger) *NotificationOutboxHandler {
	return &NotificationOutboxHandler{
		repo:   repo,
		logger: log.With("handler", "notification_outbox"),
	}
}

// OutboxEntryResponse represents an outbox entry in API responses.
type OutboxEntryResponse struct {
	ID            string         `json:"id"`
	EventType     string         `json:"event_type"`
	AggregateType string         `json:"aggregate_type"`
	AggregateID   *string        `json:"aggregate_id,omitempty"`
	Title         string         `json:"title"`
	Body          string         `json:"body,omitempty"`
	Severity      string         `json:"severity"`
	URL           string         `json:"url,omitempty"`
	Status        string         `json:"status"`
	RetryCount    int            `json:"retry_count"`
	MaxRetries    int            `json:"max_retries"`
	LastError     string         `json:"last_error,omitempty"`
	ScheduledAt   string         `json:"scheduled_at"`
	LockedAt      *string        `json:"locked_at,omitempty"`
	ProcessedAt   *string        `json:"processed_at,omitempty"`
	CreatedAt     string         `json:"created_at"`
	UpdatedAt     string         `json:"updated_at"`
	Metadata      map[string]any `json:"metadata,omitempty"`
}

func outboxToResponse(o *notification.Outbox) OutboxEntryResponse {
	resp := OutboxEntryResponse{
		ID:            o.ID().String(),
		EventType:     o.EventType(),
		AggregateType: o.AggregateType(),
		Title:         o.Title(),
		Body:          o.Body(),
		Severity:      o.Severity().String(),
		URL:           o.URL(),
		Status:        o.Status().String(),
		RetryCount:    o.RetryCount(),
		MaxRetries:    o.MaxRetries(),
		LastError:     o.LastError(),
		ScheduledAt:   o.ScheduledAt().Format("2006-01-02T15:04:05Z07:00"),
		CreatedAt:     o.CreatedAt().Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:     o.UpdatedAt().Format("2006-01-02T15:04:05Z07:00"),
		Metadata:      o.Metadata(),
	}

	if o.AggregateID() != nil {
		aggID := o.AggregateID().String()
		resp.AggregateID = &aggID
	}

	if o.LockedAt() != nil {
		lockedAt := o.LockedAt().Format("2006-01-02T15:04:05Z07:00")
		resp.LockedAt = &lockedAt
	}

	if o.ProcessedAt() != nil {
		processedAt := o.ProcessedAt().Format("2006-01-02T15:04:05Z07:00")
		resp.ProcessedAt = &processedAt
	}

	return resp
}

// OutboxStatsResponse represents outbox statistics.
type OutboxStatsResponse struct {
	Pending    int64 `json:"pending"`
	Processing int64 `json:"processing"`
	Completed  int64 `json:"completed"`
	Failed     int64 `json:"failed"`
	Dead       int64 `json:"dead"`
	Total      int64 `json:"total"`
}

// List godoc
// @Summary List notification outbox entries
// @Description List notification outbox entries for the current tenant with filtering and pagination
// @Tags notification-outbox
// @Accept json
// @Produce json
// @Param status query string false "Filter by status (pending, processing, completed, failed, dead)"
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Page size" default(20)
// @Success 200 {object} pagination.Result[OutboxEntryResponse]
// @Failure 500 {object} apierror.Response
// @Router /notification-outbox [get]
// @Security BearerAuth
func (h *NotificationOutboxHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get tenant ID from context (set by auth middleware)
	tenantIDStr := middleware.GetTenantID(ctx)
	if tenantIDStr == "" {
		apierror.Unauthorized("tenant context required").WriteJSON(w)
		return
	}

	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		apierror.BadRequest("invalid tenant id").WriteJSON(w)
		return
	}

	// Parse pagination
	page := 1
	pageSize := 20
	if p := r.URL.Query().Get("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			page = parsed
		}
	}
	if ps := r.URL.Query().Get("page_size"); ps != "" {
		if parsed, err := strconv.Atoi(ps); err == nil && parsed > 0 && parsed <= 100 {
			pageSize = parsed
		}
	}

	// Build filter - always scoped to current tenant
	filter := notification.OutboxFilter{
		TenantID: &tenantID,
	}
	if status := r.URL.Query().Get("status"); status != "" {
		s := notification.OutboxStatus(status)
		filter.Status = &s
	}

	// List entries
	pag := pagination.New(page, pageSize)
	result, err := h.repo.List(ctx, filter, pag)
	if err != nil {
		h.logger.Error("failed to list outbox entries", "error", err, "tenant_id", tenantIDStr)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	// Convert to response
	items := make([]OutboxEntryResponse, 0, len(result.Data))
	for _, o := range result.Data {
		items = append(items, outboxToResponse(o))
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(pagination.Result[OutboxEntryResponse]{
		Data:       items,
		Total:      result.Total,
		Page:       result.Page,
		PerPage:    result.PerPage,
		TotalPages: result.TotalPages,
	})
}

// GetStats godoc
// @Summary Get notification outbox statistics
// @Description Get counts of outbox entries by status for the current tenant
// @Tags notification-outbox
// @Accept json
// @Produce json
// @Success 200 {object} OutboxStatsResponse
// @Failure 500 {object} apierror.Response
// @Router /notification-outbox/stats [get]
// @Security BearerAuth
func (h *NotificationOutboxHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get tenant ID from context
	tenantIDStr := middleware.GetTenantID(ctx)
	if tenantIDStr == "" {
		apierror.Unauthorized("tenant context required").WriteJSON(w)
		return
	}

	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		apierror.BadRequest("invalid tenant id").WriteJSON(w)
		return
	}

	stats, err := h.repo.GetStats(ctx, &tenantID)
	if err != nil {
		h.logger.Error("failed to get outbox stats", "error", err, "tenant_id", tenantIDStr)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(OutboxStatsResponse{
		Pending:    stats.Pending,
		Processing: stats.Processing,
		Completed:  stats.Completed,
		Failed:     stats.Failed,
		Dead:       stats.Dead,
		Total:      stats.Total,
	})
}

// Get godoc
// @Summary Get notification outbox entry
// @Description Get a specific outbox entry by ID (must belong to current tenant)
// @Tags notification-outbox
// @Accept json
// @Produce json
// @Param id path string true "Outbox entry ID"
// @Success 200 {object} OutboxEntryResponse
// @Failure 404 {object} apierror.Response
// @Failure 500 {object} apierror.Response
// @Router /notification-outbox/{id} [get]
// @Security BearerAuth
func (h *NotificationOutboxHandler) Get(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get tenant ID from context
	tenantIDStr := middleware.GetTenantID(ctx)
	if tenantIDStr == "" {
		apierror.Unauthorized("tenant context required").WriteJSON(w)
		return
	}

	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		apierror.BadRequest("invalid tenant id").WriteJSON(w)
		return
	}

	id := chi.URLParam(r, "id")
	outboxID, err := notification.ParseID(id)
	if err != nil {
		apierror.BadRequest("invalid outbox id").WriteJSON(w)
		return
	}

	entry, err := h.repo.GetByID(ctx, outboxID)
	if err != nil {
		if errors.Is(err, notification.ErrOutboxNotFound) {
			apierror.NotFound("outbox entry").WriteJSON(w)
			return
		}
		h.logger.Error("failed to get outbox entry", "error", err, "id", id)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	// Verify entry belongs to current tenant
	if entry.TenantID().String() != tenantID.String() {
		apierror.NotFound("outbox entry").WriteJSON(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(outboxToResponse(entry))
}

// Retry godoc
// @Summary Retry failed outbox entry
// @Description Reset a failed/dead outbox entry to pending for retry (must belong to current tenant)
// @Tags notification-outbox
// @Accept json
// @Produce json
// @Param id path string true "Outbox entry ID"
// @Success 200 {object} OutboxEntryResponse
// @Failure 400 {object} apierror.Response
// @Failure 404 {object} apierror.Response
// @Failure 500 {object} apierror.Response
// @Router /notification-outbox/{id}/retry [post]
// @Security BearerAuth
func (h *NotificationOutboxHandler) Retry(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get tenant ID from context
	tenantIDStr := middleware.GetTenantID(ctx)
	if tenantIDStr == "" {
		apierror.Unauthorized("tenant context required").WriteJSON(w)
		return
	}

	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		apierror.BadRequest("invalid tenant id").WriteJSON(w)
		return
	}

	id := chi.URLParam(r, "id")
	outboxID, err := notification.ParseID(id)
	if err != nil {
		apierror.BadRequest("invalid outbox id").WriteJSON(w)
		return
	}

	entry, err := h.repo.GetByID(ctx, outboxID)
	if err != nil {
		if errors.Is(err, notification.ErrOutboxNotFound) {
			apierror.NotFound("outbox entry").WriteJSON(w)
			return
		}
		h.logger.Error("failed to get outbox entry", "error", err, "id", id)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	// Verify entry belongs to current tenant
	if entry.TenantID().String() != tenantID.String() {
		apierror.NotFound("outbox entry").WriteJSON(w)
		return
	}

	// Only allow retry for failed or dead entries
	if entry.Status() != notification.OutboxStatusFailed && entry.Status() != notification.OutboxStatusDead {
		apierror.BadRequest("can only retry failed or dead entries").WriteJSON(w)
		return
	}

	// Reset for retry
	entry.ResetForRetry()

	if err := h.repo.Update(ctx, entry); err != nil {
		h.logger.Error("failed to update outbox entry", "error", err, "id", id)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	h.logger.Info("outbox entry reset for retry", "id", id, "tenant_id", tenantIDStr)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(outboxToResponse(entry))
}

// Delete godoc
// @Summary Delete outbox entry
// @Description Delete a specific outbox entry (must belong to current tenant)
// @Tags notification-outbox
// @Accept json
// @Produce json
// @Param id path string true "Outbox entry ID"
// @Success 204 "No Content"
// @Failure 404 {object} apierror.Response
// @Failure 500 {object} apierror.Response
// @Router /notification-outbox/{id} [delete]
// @Security BearerAuth
func (h *NotificationOutboxHandler) Delete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get tenant ID from context
	tenantIDStr := middleware.GetTenantID(ctx)
	if tenantIDStr == "" {
		apierror.Unauthorized("tenant context required").WriteJSON(w)
		return
	}

	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		apierror.BadRequest("invalid tenant id").WriteJSON(w)
		return
	}

	id := chi.URLParam(r, "id")
	outboxID, err := notification.ParseID(id)
	if err != nil {
		apierror.BadRequest("invalid outbox id").WriteJSON(w)
		return
	}

	// First get the entry to verify tenant ownership
	entry, err := h.repo.GetByID(ctx, outboxID)
	if err != nil {
		if errors.Is(err, notification.ErrOutboxNotFound) {
			apierror.NotFound("outbox entry").WriteJSON(w)
			return
		}
		h.logger.Error("failed to get outbox entry", "error", err, "id", id)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	// Verify entry belongs to current tenant
	if entry.TenantID().String() != tenantID.String() {
		apierror.NotFound("outbox entry").WriteJSON(w)
		return
	}

	if err := h.repo.Delete(ctx, outboxID); err != nil {
		if errors.Is(err, notification.ErrOutboxNotFound) {
			apierror.NotFound("outbox entry").WriteJSON(w)
			return
		}
		h.logger.Error("failed to delete outbox entry", "error", err, "id", id)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	h.logger.Info("outbox entry deleted", "id", id, "tenant_id", tenantIDStr)
	w.WriteHeader(http.StatusNoContent)
}
