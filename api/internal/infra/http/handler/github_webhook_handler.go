package handler

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"time"

	"github.com/openctemio/openctem/api/internal/app/integration"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// GitHubIssueSink applies an inbound GitHub issue state change (closed/reopened)
// to the linked finding. Implemented by *ticketing.GitHubTicketService. nil →
// inbound issue→finding sync is inert.
type GitHubIssueSink interface {
	HandleIssueEvent(ctx context.Context, tenantID shared.ID, issueHTMLURL, action string) error
}

// githubWebhookMaxBody bounds the raw body read before signature verification.
const githubWebhookMaxBody = 5 * 1024 * 1024 // 5 MiB

// GitHubDeliveryWindow is how long a verified delivery id is remembered: a
// replay of the same signed delivery inside it is acknowledged and ignored.
const GitHubDeliveryWindow = 24 * time.Hour

// githubDeliveryID is the shape of X-GitHub-Delivery (a GUID); anything else
// is refused before it becomes a cache key.
var githubDeliveryID = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

// WebhookDeliveryGuard records a delivery key and reports whether it is new.
// Implemented by redis.WebhookDeliveryStore (shared by every API replica).
type WebhookDeliveryGuard interface {
	FirstDelivery(ctx context.Context, key string, ttl time.Duration) (bool, error)
}

// githubWebhookService is what the handler needs from the integration
// service (*integration.IntegrationService).
type githubWebhookService interface {
	ListGitHubWebhookSecrets(ctx context.Context, tenantID shared.ID) ([]string, error)
	HandleGitHubPush(ctx context.Context, tenantID shared.ID, ev *integration.GitHubPushEvent) (bool, error)
}

// GitHubWebhookHandler receives inbound GitHub webhooks (push events) and
// refreshes the pushed branch's metadata. Public endpoint (no JWT) — verified by
// GitHub's X-Hub-Signature-256 HMAC against the tenant's per-tenant secret.
type GitHubWebhookHandler struct {
	service   githubWebhookService
	issueSink GitHubIssueSink // nil → issue events are acked but not synced
	// deliveries refuses replays of a verified delivery; nil (no Redis, tests)
	// turns replay protection off.
	deliveries WebhookDeliveryGuard
	// orgs refuses deliveries for a suspended organization
	// (docs/architecture/organization-suspension.md); nil admits all.
	orgs   tenantdom.AccessGate
	logger *logger.Logger
}

// SetOrganizationGate wires the organization access gate.
func (h *GitHubWebhookHandler) SetOrganizationGate(g tenantdom.AccessGate) { h.orgs = g }

// NewGitHubWebhookHandler creates a new GitHubWebhookHandler.
func NewGitHubWebhookHandler(svc *integration.IntegrationService, log *logger.Logger) *GitHubWebhookHandler {
	return &GitHubWebhookHandler{service: svc, logger: log}
}

// SetIssueSink wires inbound GitHub issue → finding status sync. Safe after
// construction; nil disables it (issue events are still ack'd).
func (h *GitHubWebhookHandler) SetIssueSink(sink GitHubIssueSink) {
	h.issueSink = sink
}

// SetDeliveryGuard wires delivery-id replay protection.
func (h *GitHubWebhookHandler) SetDeliveryGuard(g WebhookDeliveryGuard) {
	h.deliveries = g
}

// IncomingGitHubWebhook handles POST /api/v1/webhooks/incoming/github?tenant=.
// Tenant routing is via ?tenant=. The body is HMAC-verified with the GitHub
// X-Hub-Signature-256 scheme against the tenant's GitHub webhook secret(s).
func (h *GitHubWebhookHandler) IncomingGitHubWebhook(w http.ResponseWriter, r *http.Request) {
	tenantIDStr := r.URL.Query().Get("tenant")
	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		apierror.BadRequest("invalid or missing tenant query parameter").WriteJSON(w)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, githubWebhookMaxBody+1))
	if err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	if len(body) > githubWebhookMaxBody {
		apierror.BadRequest("request body too large").WriteJSON(w)
		return
	}

	// Verify the GitHub signature against the tenant's candidate secrets. A
	// tenant only ever holds its own secrets, so one tenant cannot spoof another.
	secrets, err := h.service.ListGitHubWebhookSecrets(r.Context(), tenantID)
	if err != nil || len(secrets) == 0 {
		h.logger.Warn("github webhook rejected: no secret configured", "tenant_id", tenantIDStr)
		apierror.Unauthorized("webhook not configured").WriteJSON(w)
		return
	}
	sig := r.Header.Get("X-Hub-Signature-256")
	verified := false
	for _, secret := range secrets {
		if integration.VerifyGitHubSignature(body, sig, secret) {
			verified = true
			break
		}
	}
	if !verified {
		h.logger.Warn("github webhook rejected: bad signature", "tenant_id", tenantIDStr, "remote_ip", r.RemoteAddr)
		apierror.Unauthorized("invalid webhook signature").WriteJSON(w)
		return
	}
	// A suspended organization takes no deliveries (checked after the
	// signature, so only the secret holder learns the status).
	if h.orgs != nil {
		if gerr := h.orgs.CheckAccess(r.Context(), tenantID); gerr != nil {
			middleware.WriteOrganizationGateError(w, gerr, h.logger)
			return
		}
	}

	// Replay protection: the signature covers the body only, so a captured
	// delivery verifies forever. Each delivery id is accepted once per
	// organization inside the window; a replay is acknowledged and ignored.
	if h.deliveries != nil {
		delivery := r.Header.Get("X-GitHub-Delivery")
		if !githubDeliveryID.MatchString(delivery) {
			apierror.BadRequest("missing or invalid X-GitHub-Delivery header").WriteJSON(w)
			return
		}
		first, derr := h.deliveries.FirstDelivery(r.Context(), "github:"+tenantID.String()+":"+delivery, GitHubDeliveryWindow)
		if derr != nil {
			// Fail closed: without the store a replay cannot be told apart.
			h.logger.Error("github webhook: delivery store unavailable", "tenant_id", tenantID.String(), "error", derr)
			apierror.ServiceUnavailable("webhook temporarily unavailable").WriteJSON(w)
			return
		}
		if !first {
			h.logger.Warn("SECURITY: github webhook replay ignored", "tenant_id", tenantID.String(), "delivery", sanitizeLogField(delivery))
			w.WriteHeader(http.StatusOK)
			return
		}
	}

	event := r.Header.Get("X-GitHub-Event")

	// issues events (closed/reopened) sync the linked finding's status — the
	// reverse of create-ticket. Ack regardless so GitHub doesn't retry-storm.
	if event == "issues" {
		if h.issueSink != nil {
			var payload struct {
				Action string `json:"action"`
				Issue  struct {
					HTMLURL string `json:"html_url"`
				} `json:"issue"`
			}
			if jerr := json.Unmarshal(body, &payload); jerr == nil && payload.Issue.HTMLURL != "" {
				if serr := h.issueSink.HandleIssueEvent(r.Context(), tenantID, payload.Issue.HTMLURL, payload.Action); serr != nil {
					h.logger.Error("github issue event sync failed", "tenant_id", tenantIDStr, "error", serr)
				}
			}
		}
		w.WriteHeader(http.StatusOK)
		return
	}

	// Only push events drive branch updates; ack everything else (incl. ping).
	if event != "push" {
		w.WriteHeader(http.StatusOK)
		return
	}

	ev, err := integration.ParseGitHubPush(body)
	if err != nil {
		apierror.BadRequest("invalid push payload").WriteJSON(w)
		return
	}
	if _, err := h.service.HandleGitHubPush(r.Context(), tenantID, ev); err != nil {
		h.logger.Error("github push processing failed", "tenant_id", tenantIDStr, "error", err)
		// Still 2xx so GitHub does not retry-storm on a transient DB error.
	}

	w.WriteHeader(http.StatusOK)
}
