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
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/webhook"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/validator"
)

// WebhookHandler handles HTTP requests for webhook management.
type WebhookHandler struct {
	service   *app.WebhookService
	validator *validator.Validator
	logger    *logger.Logger
}

// NewWebhookHandler creates a new WebhookHandler.
func NewWebhookHandler(svc *app.WebhookService, v *validator.Validator, log *logger.Logger) *WebhookHandler {
	return &WebhookHandler{
		service:   svc,
		validator: v,
		logger:    log,
	}
}

// --- Request/Response Types ---

// CreateWebhookRequest represents the request to create a webhook.
type CreateWebhookRequest struct {
	Name              string   `json:"name" validate:"required,min=1,max=255"`
	Description       string   `json:"description" validate:"max=1000"`
	URL               string   `json:"url" validate:"required,url,max=1000"`
	Secret            string   `json:"secret" validate:"max=500"`
	EventTypes        []string `json:"event_types" validate:"required,min=1,max=20"`
	SeverityThreshold string   `json:"severity_threshold" validate:"omitempty,oneof=critical high medium low info"`
	MaxRetries        int      `json:"max_retries" validate:"min=0,max=10"`
	RetryInterval     int      `json:"retry_interval_seconds" validate:"min=0,max=3600"`
}

// UpdateWebhookRequest represents the request to update a webhook.
type UpdateWebhookRequest struct {
	Name              *string  `json:"name" validate:"omitempty,min=1,max=255"`
	Description       *string  `json:"description" validate:"omitempty,max=1000"`
	URL               *string  `json:"url" validate:"omitempty,url,max=1000"`
	Secret            *string  `json:"secret" validate:"omitempty,max=500"`
	EventTypes        []string `json:"event_types" validate:"omitempty,min=1,max=20"`
	SeverityThreshold *string  `json:"severity_threshold" validate:"omitempty,oneof=critical high medium low info"`
	MaxRetries        *int     `json:"max_retries" validate:"omitempty,min=0,max=10"`
	RetryInterval     *int     `json:"retry_interval_seconds" validate:"omitempty,min=0,max=3600"`
}

// WebhookResponse represents a webhook in the response.
type WebhookResponse struct {
	ID                   string     `json:"id"`
	TenantID             string     `json:"tenant_id"`
	Name                 string     `json:"name"`
	Description          string     `json:"description,omitempty"`
	URL                  string     `json:"url"`
	HasSecret            bool       `json:"has_secret"`
	EventTypes           []string   `json:"event_types"`
	SeverityThreshold    string     `json:"severity_threshold"`
	Status               string     `json:"status"`
	MaxRetries           int        `json:"max_retries"`
	RetryIntervalSeconds int        `json:"retry_interval_seconds"`
	TotalSent            int        `json:"total_sent"`
	TotalFailed          int        `json:"total_failed"`
	LastSentAt           *time.Time `json:"last_sent_at,omitempty"`
	LastError            string     `json:"last_error,omitempty"`
	LastErrorAt          *time.Time `json:"last_error_at,omitempty"`
	CreatedBy            string     `json:"created_by,omitempty"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
}

// DeliveryResponse represents a webhook delivery in the response.
type DeliveryResponse struct {
	ID              string         `json:"id"`
	WebhookID       string         `json:"webhook_id"`
	EventID         string         `json:"event_id,omitempty"`
	EventType       string         `json:"event_type"`
	Payload         map[string]any `json:"payload,omitempty"`
	Status          string         `json:"status"`
	ResponseCode    *int           `json:"response_code,omitempty"`
	ResponseBody    string         `json:"response_body,omitempty"`
	Attempt         int            `json:"attempt"`
	NextRetryAt     *time.Time     `json:"next_retry_at,omitempty"`
	ErrorMessage    string         `json:"error_message,omitempty"`
	CreatedAt       time.Time      `json:"created_at"`
	DeliveredAt     *time.Time     `json:"delivered_at,omitempty"`
	DurationMs      *int           `json:"duration_ms,omitempty"`
}

// --- Handlers ---

// Create handles POST /api/v1/webhooks
func (h *WebhookHandler) Create(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())

	var req CreateWebhookRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := app.CreateWebhookInput{
		TenantID:          tenantID,
		Name:              req.Name,
		Description:       req.Description,
		URL:               req.URL,
		Secret:            req.Secret,
		EventTypes:        req.EventTypes,
		SeverityThreshold: req.SeverityThreshold,
		MaxRetries:        req.MaxRetries,
		RetryInterval:     req.RetryInterval,
		CreatedBy:         userID,
	}

	wh, err := h.service.CreateWebhook(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(toWebhookResponse(wh))
}

// List handles GET /api/v1/webhooks
func (h *WebhookHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	query := r.URL.Query()
	input := app.ListWebhooksInput{
		TenantID:  tenantID,
		Status:    query.Get("status"),
		EventType: query.Get("event_type"),
		Search:    query.Get("search"),
		Page:      parseQueryInt(query.Get("page"), 1),
		PerPage:   parseQueryInt(query.Get("per_page"), 20),
		SortBy:    query.Get("sort"),
		SortOrder: query.Get("order"),
	}

	result, err := h.service.ListWebhooks(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	data := make([]WebhookResponse, len(result.Data))
	for i, wh := range result.Data {
		data[i] = toWebhookResponse(wh)
	}

	response := ListResponse[WebhookResponse]{
		Data:       data,
		Total:      result.Total,
		Page:       result.Page,
		PerPage:    result.PerPage,
		TotalPages: result.TotalPages,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

// Get handles GET /api/v1/webhooks/{id}
func (h *WebhookHandler) Get(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	id := chi.URLParam(r, "id")

	wh, err := h.service.GetWebhook(r.Context(), id, tenantID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toWebhookResponse(wh))
}

// Update handles PUT /api/v1/webhooks/{id}
func (h *WebhookHandler) Update(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	id := chi.URLParam(r, "id")

	var req UpdateWebhookRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := app.UpdateWebhookInput{
		Name:              req.Name,
		Description:       req.Description,
		URL:               req.URL,
		Secret:            req.Secret,
		EventTypes:        req.EventTypes,
		SeverityThreshold: req.SeverityThreshold,
		MaxRetries:        req.MaxRetries,
		RetryInterval:     req.RetryInterval,
	}

	wh, err := h.service.UpdateWebhook(r.Context(), id, tenantID, input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toWebhookResponse(wh))
}

// Delete handles DELETE /api/v1/webhooks/{id}
func (h *WebhookHandler) Delete(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	id := chi.URLParam(r, "id")

	if err := h.service.DeleteWebhook(r.Context(), id, tenantID); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Enable handles POST /api/v1/webhooks/{id}/enable
func (h *WebhookHandler) Enable(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	id := chi.URLParam(r, "id")

	wh, err := h.service.EnableWebhook(r.Context(), id, tenantID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toWebhookResponse(wh))
}

// Disable handles POST /api/v1/webhooks/{id}/disable
func (h *WebhookHandler) Disable(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	id := chi.URLParam(r, "id")

	wh, err := h.service.DisableWebhook(r.Context(), id, tenantID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toWebhookResponse(wh))
}

// ListDeliveries handles GET /api/v1/webhooks/{id}/deliveries
func (h *WebhookHandler) ListDeliveries(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	id := chi.URLParam(r, "id")

	query := r.URL.Query()
	input := app.ListDeliveriesInput{
		WebhookID: id,
		TenantID:  tenantID,
		Status:    query.Get("status"),
		Page:      parseQueryInt(query.Get("page"), 1),
		PerPage:   parseQueryInt(query.Get("per_page"), 20),
	}

	result, err := h.service.ListDeliveries(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	data := make([]DeliveryResponse, len(result.Data))
	for i, d := range result.Data {
		data[i] = toDeliveryResponse(d)
	}

	response := ListResponse[DeliveryResponse]{
		Data:       data,
		Total:      result.Total,
		Page:       result.Page,
		PerPage:    result.PerPage,
		TotalPages: result.TotalPages,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

// --- Helpers ---

func toWebhookResponse(w *webhook.Webhook) WebhookResponse {
	resp := WebhookResponse{
		ID:                   w.ID().String(),
		TenantID:             w.TenantID().String(),
		Name:                 w.Name(),
		Description:          w.Description(),
		URL:                  w.URL(),
		HasSecret:            len(w.SecretEncrypted()) > 0,
		EventTypes:           w.EventTypes(),
		SeverityThreshold:    w.SeverityThreshold(),
		Status:               string(w.Status()),
		MaxRetries:           w.MaxRetries(),
		RetryIntervalSeconds: w.RetryIntervalSeconds(),
		TotalSent:            w.TotalSent(),
		TotalFailed:          w.TotalFailed(),
		LastSentAt:           w.LastSentAt(),
		LastError:            w.LastError(),
		LastErrorAt:          w.LastErrorAt(),
		CreatedAt:            w.CreatedAt(),
		UpdatedAt:            w.UpdatedAt(),
	}

	if w.CreatedBy() != nil {
		resp.CreatedBy = w.CreatedBy().String()
	}

	return resp
}

func toDeliveryResponse(d *webhook.Delivery) DeliveryResponse {
	resp := DeliveryResponse{
		ID:           d.ID.String(),
		WebhookID:    d.WebhookID.String(),
		EventType:    d.EventType,
		Payload:      d.Payload,
		Status:       string(d.Status),
		ResponseCode: d.ResponseCode,
		ResponseBody: d.ResponseBody,
		Attempt:      d.Attempt,
		NextRetryAt:  d.NextRetryAt,
		ErrorMessage: d.ErrorMessage,
		CreatedAt:    d.CreatedAt,
		DeliveredAt:  d.DeliveredAt,
		DurationMs:   d.DurationMs,
	}

	if d.EventID != nil {
		resp.EventID = d.EventID.String()
	}

	return resp
}

func (h *WebhookHandler) handleValidationError(w http.ResponseWriter, err error) {
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

func (h *WebhookHandler) handleServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, webhook.ErrWebhookNotFound):
		apierror.NotFound("Webhook").WriteJSON(w)
	case errors.Is(err, webhook.ErrWebhookNameExists):
		apierror.Conflict("Webhook name already exists").WriteJSON(w)
	case shared.IsValidation(err):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	default:
		h.logger.Error("webhook service error", "error", err)
		apierror.InternalServerError("Internal server error").WriteJSON(w)
	}
}
