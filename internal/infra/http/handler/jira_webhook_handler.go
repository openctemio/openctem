package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/api/internal/app/jira"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// JiraWebhookHandler handles Jira bidirectional ticket sync endpoints.
//
// Endpoints:
//   - POST /api/v1/findings/{id}/link-ticket      — link a Jira ticket to a finding
//   - DELETE /api/v1/findings/{id}/link-ticket     — unlink a Jira ticket from a finding
//   - POST /api/v1/webhooks/incoming/jira          — receive Jira status-change webhooks
type JiraWebhookHandler struct {
	service *jira.SyncService
	logger  *logger.Logger
}

// NewJiraWebhookHandler creates a new JiraWebhookHandler.
func NewJiraWebhookHandler(svc *jira.SyncService, log *logger.Logger) *JiraWebhookHandler {
	return &JiraWebhookHandler{service: svc, logger: log}
}

// LinkTicketRequest is the request body for POST /api/v1/findings/{id}/link-ticket.
type LinkTicketRequest struct {
	TicketKey string `json:"ticket_key" validate:"required,min=1,max=255"`
	TicketURL string `json:"ticket_url" validate:"required,url,max=1000"`
}

// UnlinkTicketRequest is the request body for DELETE /api/v1/findings/{id}/link-ticket.
type UnlinkTicketRequest struct {
	TicketURL string `json:"ticket_url" validate:"required,url,max=1000"`
}

// LinkTicket handles POST /api/v1/findings/{id}/link-ticket.
// Links a Jira ticket to a finding by storing its URL in work_item_uris.
func (h *JiraWebhookHandler) LinkTicket(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	findingID := chi.URLParam(r, "id")
	if findingID == "" {
		apierror.BadRequest("finding id is required").WriteJSON(w)
		return
	}

	var req LinkTicketRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}

	if req.TicketKey == "" {
		apierror.BadRequest("ticket_key is required").WriteJSON(w)
		return
	}
	if req.TicketURL == "" {
		apierror.BadRequest("ticket_url is required").WriteJSON(w)
		return
	}

	input := jira.LinkTicketInput{
		TenantID:  tenantID,
		FindingID: findingID,
		TicketKey: req.TicketKey,
		TicketURL: req.TicketURL,
	}

	if err := h.service.LinkTicket(r.Context(), input); err != nil {
		h.handleError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"finding_id": findingID,
		"ticket_key": req.TicketKey,
		"ticket_url": req.TicketURL,
		"message":    "ticket linked successfully",
	})
}

// UnlinkTicket handles DELETE /api/v1/findings/{id}/link-ticket.
// Removes a Jira ticket reference from a finding's work_item_uris.
func (h *JiraWebhookHandler) UnlinkTicket(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	findingID := chi.URLParam(r, "id")
	if findingID == "" {
		apierror.BadRequest("finding id is required").WriteJSON(w)
		return
	}

	var req UnlinkTicketRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	if req.TicketURL == "" {
		apierror.BadRequest("ticket_url is required").WriteJSON(w)
		return
	}

	if err := h.service.UnlinkTicket(r.Context(), tenantID, findingID, req.TicketURL); err != nil {
		h.handleError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// CreateTicketRequest is the request body for POST /api/v1/findings/{id}/create-ticket.
type CreateTicketRequest struct {
	ProjectKey string `json:"project_key"`
	IssueType  string `json:"issue_type,omitempty"`
}

// CreateTicket handles POST /api/v1/findings/{id}/create-ticket.
// Auto-creates a Jira ticket from a finding and links it.
func (h *JiraWebhookHandler) CreateTicket(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	findingID := chi.URLParam(r, "id")
	if findingID == "" {
		apierror.BadRequest("finding id is required").WriteJSON(w)
		return
	}

	var req CreateTicketRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}

	result, err := h.service.CreateTicketFromFinding(r.Context(), jira.CreateTicketInput{
		TenantID:   tenantID,
		FindingID:  findingID,
		ProjectKey: req.ProjectKey,
		IssueType:  req.IssueType,
	})
	if err != nil {
		h.handleError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(result)
}

// IncomingJiraWebhook handles POST /api/v1/webhooks/incoming/jira.
// This is a PUBLIC endpoint (no JWT) intended to receive Jira webhook deliveries.
// Tenant routing is via the ?tenant= query param — each Jira project configures one endpoint per tenant.
func (h *JiraWebhookHandler) IncomingJiraWebhook(w http.ResponseWriter, r *http.Request) {
	tenantIDStr := r.URL.Query().Get("tenant")
	if tenantIDStr == "" {
		apierror.BadRequest("tenant query parameter is required").WriteJSON(w)
		return
	}

	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		apierror.BadRequest("invalid tenant id").WriteJSON(w)
		return
	}

	var payload jira.WebhookPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		apierror.BadRequest("invalid jira webhook payload").WriteJSON(w)
		return
	}

	if err := h.service.HandleJiraWebhook(r.Context(), tenantID, payload); err != nil {
		h.logger.Error("jira webhook processing failed",
			"tenant_id", tenantIDStr,
			"error", err,
		)
		apierror.InternalServerError("webhook processing failed").WriteJSON(w)
		return
	}

	// Always return 200 — Jira expects a 2xx or it will retry.
	w.WriteHeader(http.StatusOK)
}

// handleError maps domain errors to HTTP responses.
func (h *JiraWebhookHandler) handleError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("finding not found").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	default:
		h.logger.Error("jira handler error", "error", err)
		apierror.InternalServerError("internal server error").WriteJSON(w)
	}
}
