package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/app/jira"
	"github.com/openctemio/openctem/api/internal/app/ticketing"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// JiraWebhookHandler handles Jira bidirectional ticket sync endpoints.
//
// Endpoints:
//   - POST /api/v1/findings/{id}/link-ticket      — link a Jira ticket to a finding
//   - DELETE /api/v1/findings/{id}/link-ticket     — unlink a Jira ticket from a finding
//   - POST /hooks/jira-integrations/{integration_id} — receive Jira status-change webhooks
type JiraWebhookHandler struct {
	service   *jira.SyncService
	validator *validator.Validator
	logger    *logger.Logger

	// github is the optional GitHub Issues ticket provider. Nil unless wired
	// via SetGitHubTicketService — when nil, requests with provider=github are
	// rejected with 400.
	github *ticketing.GitHubTicketService
	// verifier authenticates inbound deliveries; nil refuses them all.
	verifier JiraDeliveryVerifier
	// deliveries remembers delivery ids (replay protection).
	deliveries WebhookDeliveryGuard
}

// NewJiraWebhookHandler creates a new JiraWebhookHandler.
func NewJiraWebhookHandler(svc *jira.SyncService, v *validator.Validator, log *logger.Logger) *JiraWebhookHandler {
	return &JiraWebhookHandler{service: svc, validator: v, logger: log}
}

// decodeAndValidate reads the JSON body into dst and runs struct validation so
// the `validate:` tags on the request structs are actually enforced (they were
// previously declared but never run). On failure it writes a 400 and returns
// false, so callers do `if !h.decodeAndValidate(w, r, &req) { return }`.
func (h *JiraWebhookHandler) decodeAndValidate(w http.ResponseWriter, r *http.Request, dst any) bool {
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return false
	}
	if h.validator != nil {
		if err := h.validator.Validate(dst); err != nil {
			apierror.BadRequest(err.Error()).WriteJSON(w)
			return false
		}
	}
	return true
}

// SetGitHubTicketService wires the optional GitHub Issues ticket provider.
// Safe to call after construction; a nil value leaves GitHub ticketing
// disabled.
func (h *JiraWebhookHandler) SetGitHubTicketService(svc *ticketing.GitHubTicketService) {
	h.github = svc
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

// CreateTicketRequest is the request body for POST /api/v1/findings/{id}/create-ticket.
type CreateTicketRequest struct {
	// Provider selects the ticket backend: "jira" (default) or "github".
	Provider string `json:"provider,omitempty" validate:"omitempty,oneof=jira github"`

	// Jira fields.
	ProjectKey string `json:"project_key,omitempty" validate:"omitempty,max=255"`
	IssueType  string `json:"issue_type,omitempty" validate:"omitempty,max=255"`

	// GitHub fields (required when provider=github).
	Owner string `json:"owner,omitempty" validate:"omitempty,max=255"`
	Repo  string `json:"repo,omitempty" validate:"omitempty,max=255"`
}

// CreateTicket handles POST /api/v1/findings/{id}/create-ticket.
// Auto-creates a ticket (Jira by default, or a GitHub issue) from a finding
// and links it.
func (h *JiraWebhookHandler) CreateTicket(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	findingID := chi.URLParam(r, "id")
	if findingID == "" {
		apierror.BadRequest("finding id is required").WriteJSON(w)
		return
	}

	var req CreateTicketRequest
	if !h.decodeAndValidate(w, r, &req) {
		return
	}

	if strings.EqualFold(req.Provider, "github") {
		h.createGitHubTicket(w, r, tenantID, findingID, req)
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

// createGitHubTicket handles the provider=github branch of CreateTicket.
func (h *JiraWebhookHandler) createGitHubTicket(w http.ResponseWriter, r *http.Request, tenantID, findingID string, req CreateTicketRequest) {
	if h.github == nil {
		apierror.BadRequest("github ticketing not configured").WriteJSON(w)
		return
	}

	result, err := h.github.CreateTicketFromFinding(r.Context(), ticketing.GitHubTicketInput{
		TenantID:  tenantID,
		FindingID: findingID,
		Owner:     req.Owner,
		Repo:      req.Repo,
	})
	if err != nil {
		h.handleError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(result)
}

// ListJiraProjects handles GET /api/v1/integrations/jira/projects.
// Returns the Jira projects visible to the tenant's connected ticketing
// integration, for the admin destination-project picker (so an operator
// selects the default project from a list rather than typing a raw key).
func (h *JiraWebhookHandler) ListJiraProjects(w http.ResponseWriter, r *http.Request) {
	tid, err := shared.IDFromString(middleware.MustGetTenantID(r.Context()))
	if err != nil {
		apierror.Unauthorized("invalid tenant context").WriteJSON(w)
		return
	}

	projects, err := h.service.ListProjects(r.Context(), tid)
	if err != nil {
		if errors.Is(err, jira.ErrNoTicketingIntegration) {
			apierror.NotFound("no connected Jira integration").WriteJSON(w)
			return
		}
		h.logger.Error("list jira projects failed", "error", err)
		apierror.InternalServerError("failed to list Jira projects").WriteJSON(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"projects": projects})
}

// JiraDeliveryVerifier authenticates an inbound Jira delivery by the
// integration named in its URL and returns that integration's tenant
// (integration.IntegrationService.VerifyJiraDelivery).
type JiraDeliveryVerifier interface {
	VerifyJiraDelivery(ctx context.Context, integrationID shared.ID, body []byte, signature string) (shared.ID, error)
}

// Inbound Jira delivery limits.
const (
	jiraWebhookMaxBody = 2 * 1024 * 1024 // 2 MiB
	// JiraDeliveryMaxAge refuses a delivery whose payload timestamp is older:
	// Jira retries a failed delivery for a short while, and a replay after
	// the dedup window falls outside this age as well.
	JiraDeliveryMaxAge = time.Hour
	// jiraDeliveryMaxSkew allows a sender clock slightly ahead of ours.
	jiraDeliveryMaxSkew = 5 * time.Minute
	// JiraDeliveryWindow is how long a delivery id is remembered (longer
	// than JiraDeliveryMaxAge, so every replay is caught by one or the other).
	JiraDeliveryWindow = 24 * time.Hour
)

// jiraDeliveryID is the shape of Jira's X-Atlassian-Webhook-Identifier.
var jiraDeliveryID = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

// SetDeliveryVerifier wires inbound authentication (required for the route).
func (h *JiraWebhookHandler) SetDeliveryVerifier(v JiraDeliveryVerifier) { h.verifier = v }

// SetDeliveryGuard wires replay protection by delivery id.
func (h *JiraWebhookHandler) SetDeliveryGuard(g WebhookDeliveryGuard) { h.deliveries = g }

// IncomingJiraWebhook handles POST /hooks/jira-integrations/{integration_id}.
// Public (no JWT): the integration id in the URL names one integration and so
// one tenant, and the delivery must be signed with that integration's own
// secret in X-Hub-Signature (sha256=<hex HMAC of the raw body>), the header
// Jira sends for a webhook with a secret. Replays are refused by delivery id
// (X-Atlassian-Webhook-Identifier, or the body hash when absent) and by the
// payload timestamp's age.
func (h *JiraWebhookHandler) IncomingJiraWebhook(w http.ResponseWriter, r *http.Request) {
	integrationID, err := shared.IDFromString(chi.URLParam(r, "integration_id"))
	if err != nil || h.verifier == nil {
		apierror.Unauthorized("invalid webhook signature").WriteJSON(w)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, jiraWebhookMaxBody+1))
	if err != nil || len(body) > jiraWebhookMaxBody {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	tenantID, err := h.verifier.VerifyJiraDelivery(r.Context(), integrationID, body, r.Header.Get("X-Hub-Signature"))
	if err != nil {
		h.logger.Warn("jira webhook rejected", "integration_id", integrationID.String(), "remote_ip", middleware.ClientIPKey(r))
		apierror.Unauthorized("invalid webhook signature").WriteJSON(w)
		return
	}

	var payload jira.WebhookPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		apierror.BadRequest("invalid jira webhook payload").WriteJSON(w)
		return
	}
	if !jiraDeliveryFresh(payload.Timestamp, time.Now()) {
		h.logger.Warn("SECURITY: jira webhook refused: stale or missing timestamp", "integration_id", integrationID.String())
		apierror.Unauthorized("webhook delivery is too old").WriteJSON(w)
		return
	}
	if h.deliveries != nil {
		delivery := r.Header.Get("X-Atlassian-Webhook-Identifier")
		if !jiraDeliveryID.MatchString(delivery) {
			sum := sha256.Sum256(body)
			delivery = "body-" + hex.EncodeToString(sum[:])
		}
		first, derr := h.deliveries.FirstDelivery(r.Context(), "jira:"+integrationID.String()+":"+delivery, JiraDeliveryWindow)
		if derr != nil {
			h.logger.Error("jira webhook: delivery store unavailable", "integration_id", integrationID.String(), "error", derr)
			apierror.ServiceUnavailable("webhook temporarily unavailable").WriteJSON(w)
			return
		}
		if !first {
			h.logger.Warn("SECURITY: jira webhook replay ignored", "integration_id", integrationID.String())
			w.WriteHeader(http.StatusOK)
			return
		}
	}

	if err := h.service.HandleJiraWebhook(r.Context(), tenantID, payload); err != nil {
		h.logger.Error("jira webhook processing failed",
			"tenant_id", tenantID.String(),
			"integration_id", integrationID.String(),
			"error", err,
		)
		apierror.InternalServerError("webhook processing failed").WriteJSON(w)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// jiraDeliveryFresh reports whether a payload timestamp (milliseconds since
// the epoch, as Jira sends it) is recent: not older than JiraDeliveryMaxAge
// and not far in the future. A missing timestamp is not fresh.
func jiraDeliveryFresh(tsMillis int64, now time.Time) bool {
	if tsMillis <= 0 {
		return false
	}
	ts := time.UnixMilli(tsMillis)
	return now.Sub(ts) <= JiraDeliveryMaxAge && ts.Sub(now) <= jiraDeliveryMaxSkew
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
