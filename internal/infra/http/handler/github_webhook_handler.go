package handler

import (
	"io"
	"net/http"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// githubWebhookMaxBody bounds the raw body read before signature verification.
const githubWebhookMaxBody = 5 * 1024 * 1024 // 5 MiB

// GitHubWebhookHandler receives inbound GitHub webhooks (push events) and
// refreshes the pushed branch's metadata. Public endpoint (no JWT) — verified by
// GitHub's X-Hub-Signature-256 HMAC against the tenant's per-tenant secret.
type GitHubWebhookHandler struct {
	service *app.IntegrationService
	logger  *logger.Logger
}

// NewGitHubWebhookHandler creates a new GitHubWebhookHandler.
func NewGitHubWebhookHandler(svc *app.IntegrationService, log *logger.Logger) *GitHubWebhookHandler {
	return &GitHubWebhookHandler{service: svc, logger: log}
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
		if app.VerifyGitHubSignature(body, sig, secret) {
			verified = true
			break
		}
	}
	if !verified {
		h.logger.Warn("github webhook rejected: bad signature", "tenant_id", tenantIDStr, "remote_ip", r.RemoteAddr)
		apierror.Unauthorized("invalid webhook signature").WriteJSON(w)
		return
	}

	// Only push events drive branch updates; ack everything else (incl. ping).
	if r.Header.Get("X-GitHub-Event") != "push" {
		w.WriteHeader(http.StatusOK)
		return
	}

	ev, err := app.ParseGitHubPush(body)
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
