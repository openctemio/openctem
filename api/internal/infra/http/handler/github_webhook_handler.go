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
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/app/integration"
	"github.com/openctemio/openctem/api/internal/app/ticketing"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// GitHubIssueSink applies a verified GitHub issues delivery (closed,
// reopened) to the findings linked to the issue, through the finding
// service rules. Implemented by *ticketing.GitHubTicketService. nil makes
// inbound issue sync inert.
type GitHubIssueSink interface {
	HandleIssueEvent(ctx context.Context, tenantID shared.ID, ev ticketing.GitHubIssueEvent) error
}

// githubWebhookMaxBody bounds the raw body read before signature verification.
const githubWebhookMaxBody = 5 * 1024 * 1024 // 5 MiB

// GitHubDeliveryWindow is how long a verified delivery is remembered (by its
// body hash and its delivery id): a replay inside it is acknowledged and
// ignored.
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
	VerifyGitHubDelivery(ctx context.Context, integrationID shared.ID, body []byte, signature string) (integration.GitHubDelivery, error)
	HandleGitHubPush(ctx context.Context, tenantID shared.ID, ev *integration.GitHubPushEvent) (bool, error)
}

// GitHubWebhookHandler receives inbound GitHub webhooks of one GitHub
// integration (push and issues events). Public endpoint (no JWT): verified by
// GitHub's X-Hub-Signature-256 HMAC against that integration's own secret.
type GitHubWebhookHandler struct {
	service   githubWebhookService
	issueSink GitHubIssueSink // nil → issue events are acked but not synced
	// deliveries refuses replays; required (nil refuses every delivery).
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

// SetDeliveryGuard wires replay protection (required for the route).
func (h *GitHubWebhookHandler) SetDeliveryGuard(g WebhookDeliveryGuard) {
	h.deliveries = g
}

// githubEventPayload is the part of a push or issues payload the handler
// reads before dispatching.
type githubEventPayload struct {
	Action string `json:"action"`
	Issue  struct {
		HTMLURL     string `json:"html_url"`
		StateReason string `json:"state_reason"`
	} `json:"issue"`
	Repository struct {
		FullName string `json:"full_name"`
	} `json:"repository"`
	Sender struct {
		Login string `json:"login"`
	} `json:"sender"`
}

// IncomingGitHubWebhook handles POST /hooks/github-integrations/{integration_id}.
// The integration id in the URL names one GitHub integration and so one
// tenant; the delivery must be signed with that integration's own secret
// (X-Hub-Signature-256). Replays are refused by the body hash (the delivery
// id header is not covered by the signature) and by the delivery id. An
// event for a repository outside the integration's organization is
// refused.
func (h *GitHubWebhookHandler) IncomingGitHubWebhook(w http.ResponseWriter, r *http.Request) {
	integrationID, err := shared.IDFromString(chi.URLParam(r, "integration_id"))
	if err != nil {
		apierror.Unauthorized("invalid webhook signature").WriteJSON(w)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, githubWebhookMaxBody+1))
	if err != nil || len(body) > githubWebhookMaxBody {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	src, err := h.service.VerifyGitHubDelivery(r.Context(), integrationID, body, r.Header.Get("X-Hub-Signature-256"))
	if err != nil {
		if errors.Is(err, integration.ErrGitHubWebhookUnauthorized) {
			h.logger.Warn("github webhook rejected", "integration_id", integrationID.String(), "remote_ip", middleware.ClientIPKey(r))
			apierror.Unauthorized("invalid webhook signature").WriteJSON(w)
			return
		}
		h.logger.Error("github webhook: verification unavailable", "integration_id", integrationID.String(), "error", err)
		apierror.ServiceUnavailable("webhook temporarily unavailable").WriteJSON(w)
		return
	}
	tenantID := src.TenantID
	// A suspended organization takes no deliveries (checked after the
	// signature, so only the secret holder learns the status).
	if h.orgs != nil {
		if gerr := h.orgs.CheckAccess(r.Context(), tenantID); gerr != nil {
			middleware.WriteOrganizationGateError(w, gerr, h.logger)
			return
		}
	}

	// Replay protection is mandatory: without a delivery store nothing is
	// processed (production always has one; Redis is required at startup).
	if h.deliveries == nil {
		h.logger.Error("github webhook: no delivery store; refusing", "integration_id", integrationID.String())
		apierror.ServiceUnavailable("webhook temporarily unavailable").WriteJSON(w)
		return
	}
	delivery := r.Header.Get("X-GitHub-Delivery")
	if !githubDeliveryID.MatchString(delivery) {
		apierror.BadRequest("missing or invalid X-GitHub-Delivery header").WriteJSON(w)
		return
	}
	event := r.Header.Get("X-GitHub-Event")
	var payload githubEventPayload
	if event == "push" || event == "issues" {
		if jerr := json.Unmarshal(body, &payload); jerr != nil {
			apierror.BadRequest("invalid webhook payload").WriteJSON(w)
			return
		}
		// The event's repository must belong to the integration.
		if payload.Repository.FullName == "" || !src.RepositoryAllowed(payload.Repository.FullName) {
			h.logger.Warn("SECURITY: github webhook refused: repository outside the integration",
				"integration_id", integrationID.String(), "repository", sanitizeLogField(payload.Repository.FullName))
			apierror.Forbidden("repository is not covered by this integration").WriteJSON(w)
			return
		}
	}

	// Two keys, both must be new: the body hash (the signature covers the
	// body only, so a captured body with a fresh delivery id is still a
	// replay) and GitHub's delivery id.
	sum := sha256.Sum256(body)
	prefix := "github:" + integrationID.String() + ":"
	keys := []string{prefix + "body-" + hex.EncodeToString(sum[:]), prefix + "id-" + delivery}
	claimed := make([]string, 0, len(keys))
	release := func() {
		if rel, ok := h.deliveries.(WebhookDeliveryReleaser); ok {
			// Not the request context: a client that disconnects mid-request
			// must not leave the keys held, or a redelivery would be dropped.
			ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
			defer cancel()
			for _, k := range claimed {
				if rerr := rel.ReleaseDelivery(ctx, k); rerr != nil {
					h.logger.Warn("github webhook: could not release delivery key", "error", rerr)
				}
			}
		}
	}
	for _, k := range keys {
		first, derr := h.deliveries.FirstDelivery(r.Context(), k, GitHubDeliveryWindow)
		if derr != nil {
			release()
			// Fail closed: without the store a replay cannot be told apart.
			h.logger.Error("github webhook: delivery store unavailable", "integration_id", integrationID.String(), "error", derr)
			apierror.ServiceUnavailable("webhook temporarily unavailable").WriteJSON(w)
			return
		}
		if !first {
			release()
			h.logger.Warn("SECURITY: github webhook replay ignored", "integration_id", integrationID.String(), "delivery", sanitizeLogField(delivery))
			w.WriteHeader(http.StatusOK)
			return
		}
		claimed = append(claimed, k)
	}

	var perr error
	switch event {
	case "issues":
		// closed/reopened move the linked findings through the finding
		// service rules (the reverse of create-ticket).
		if h.issueSink != nil && payload.Issue.HTMLURL != "" {
			perr = h.issueSink.HandleIssueEvent(r.Context(), tenantID, ticketing.GitHubIssueEvent{
				Action:      payload.Action,
				IssueURL:    payload.Issue.HTMLURL,
				StateReason: payload.Issue.StateReason,
				Sender:      payload.Sender.Login,
			})
		}
	case "push":
		ev, err := integration.ParseGitHubPush(body)
		if err != nil {
			release()
			apierror.BadRequest("invalid push payload").WriteJSON(w)
			return
		}
		_, perr = h.service.HandleGitHubPush(r.Context(), tenantID, ev)
	}
	// Everything else (ping included) is acknowledged.
	if perr != nil {
		// Released, so a redelivery from GitHub is processed.
		release()
		h.logger.Error("github webhook processing failed",
			"tenant_id", tenantID.String(), "integration_id", integrationID.String(), "event", sanitizeLogField(event), "error", perr)
		apierror.InternalServerError("webhook processing failed").WriteJSON(w)
		return
	}
	w.WriteHeader(http.StatusOK)
}
