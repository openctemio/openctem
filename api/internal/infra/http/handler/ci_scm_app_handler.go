package handler

// SCM app installations for CI checks and pull request comments
// (docs/rfcs/RFC-077-ci-enforced-gate-and-pr-feedback.md, section 3.3).

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	scmappsvc "github.com/openctemio/openctem/api/internal/app/scmapp"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/scm/githubapp"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/scmapp"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// SCMAppService is what the handler needs from the installation service.
type SCMAppService interface {
	GitHubConfigured() bool
	GitHubSlug() string
	GitHubInstallURL(tenantID shared.ID, userID string) (string, error)
	CompleteGitHubInstall(ctx context.Context, tenantID shared.ID, in scmappsvc.CompleteGitHubInput, a scmappsvc.Actor) (*scmapp.Installation, error)
	List(ctx context.Context, tenantID shared.ID) ([]scmapp.Installation, error)
	Remove(ctx context.Context, tenantID, id shared.ID, a scmappsvc.Actor) error
	HandleGitHubWebhook(ctx context.Context, event, signature string, body []byte) error
	ConnectGitLab(ctx context.Context, tenantID shared.ID, in scmappsvc.ConnectGitLabInput, a scmappsvc.Actor) (*scmapp.GitLabConnection, error)
	ListGitLab(ctx context.Context, tenantID shared.ID) ([]scmapp.GitLabConnection, error)
	RemoveGitLab(ctx context.Context, tenantID, id shared.ID, a scmappsvc.Actor) error
}

// SCMAppHandler serves the installation routes and the GitHub App webhook.
type SCMAppHandler struct {
	svc    SCMAppService
	logger *logger.Logger
}

// NewSCMAppHandler creates the handler.
func NewSCMAppHandler(svc SCMAppService, log *logger.Logger) *SCMAppHandler {
	return &SCMAppHandler{svc: svc, logger: log.With("handler", "scm_app")}
}

// SCMAppInstallationResponse is a bound installation.
type SCMAppInstallationResponse struct {
	ID                  string    `json:"id"`
	Provider            string    `json:"provider"`
	InstallationID      int64     `json:"installation_id"`
	AccountLogin        string    `json:"account_login"`
	AccountType         string    `json:"account_type"`
	RepositorySelection string    `json:"repository_selection"`
	Status              string    `json:"status"`
	CreatedAt           time.Time `json:"created_at"`
}

// SCMAppListResponse is the organization's code-host apps.
type SCMAppListResponse struct {
	GitHub SCMAppGitHubStatus           `json:"github"`
	Data   []SCMAppInstallationResponse `json:"data"`
	// GitLab are the organization's GitLab group connections (never the token).
	GitLab []SCMGitLabConnectionResponse `json:"gitlab"`
}

// SCMGitLabConnectionResponse is a GitLab group connection without its token.
type SCMGitLabConnectionResponse struct {
	ID             string     `json:"id"`
	Host           string     `json:"host"`
	GroupPath      string     `json:"group_path"`
	Status         string     `json:"status"`
	TokenExpiresAt *time.Time `json:"token_expires_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
}

func toGitLabResponse(c *scmapp.GitLabConnection) SCMGitLabConnectionResponse {
	return SCMGitLabConnectionResponse{ID: c.ID.String(), Host: c.Host, GroupPath: c.GroupPath, Status: c.Status,
		TokenExpiresAt: c.TokenExpiresAt, CreatedAt: c.CreatedAt}
}

// SCMAppGitHubStatus says whether the deployment has a GitHub App.
type SCMAppGitHubStatus struct {
	Configured bool   `json:"configured"`
	Slug       string `json:"slug,omitempty"`
}

func (h *SCMAppHandler) actor(r *http.Request) scmappsvc.Actor {
	ctx := r.Context()
	return scmappsvc.Actor{UserID: middleware.GetUserID(ctx), Email: auditActorEmail(ctx), IP: getClientIP(r), UserAgent: r.UserAgent()}
}

func (h *SCMAppHandler) tenant(w http.ResponseWriter, r *http.Request) (shared.ID, bool) {
	tid, err := shared.IDFromString(middleware.GetTenantID(r.Context()))
	if err != nil || tid.IsZero() {
		apierror.Unauthorized("Tenant context is required").WriteJSON(w)
		return shared.ID{}, false
	}
	return tid, true
}

// List handles GET /api/v1/ci/scm-apps
// @Summary      List the organization's code-host app installations
// @Description  Installations that post CI checks and pull request comments, and whether this deployment has a GitHub App.
// @Tags         CI
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  SCMAppListResponse
// @Router       /ci/scm-apps [get]
func (h *SCMAppHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	list, err := h.svc.List(r.Context(), tenantID)
	if err != nil {
		h.writeErr(w, "list SCM apps", err)
		return
	}
	out := SCMAppListResponse{GitHub: SCMAppGitHubStatus{Configured: h.svc.GitHubConfigured(), Slug: h.svc.GitHubSlug()},
		Data: make([]SCMAppInstallationResponse, 0, len(list))}
	for _, i := range list {
		out.Data = append(out.Data, toSCMAppResponse(&i))
	}
	gl, err := h.svc.ListGitLab(r.Context(), tenantID)
	if err != nil {
		h.writeErr(w, "list GitLab connections", err)
		return
	}
	out.GitLab = make([]SCMGitLabConnectionResponse, 0, len(gl))
	for _, c := range gl {
		out.GitLab = append(out.GitLab, toGitLabResponse(&c))
	}
	ciWriteJSON(w, http.StatusOK, out)
}

func toSCMAppResponse(i *scmapp.Installation) SCMAppInstallationResponse {
	return SCMAppInstallationResponse{ID: i.ID.String(), Provider: i.Provider, InstallationID: i.InstallationID,
		AccountLogin: i.AccountLogin, AccountType: i.AccountType, RepositorySelection: i.RepositorySelection,
		Status: i.Status, CreatedAt: i.CreatedAt}
}

// SCMAppInstallURLResponse is the link that installs the GitHub App.
type SCMAppInstallURLResponse struct {
	URL string `json:"url"`
}

// GitHubInstallURL handles POST /api/v1/ci/scm-apps/github/install-url
// @Summary      Start installing the GitHub App
// @Description  Returns the GitHub install link with a state bound to the caller and the organization, valid 15 minutes.
// @Tags         CI
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  SCMAppInstallURLResponse
// @Failure      409  {object}  apierror.Error "GITHUB_APP_NOT_CONFIGURED"
// @Router       /ci/scm-apps/github/install-url [post]
func (h *SCMAppHandler) GitHubInstallURL(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	u, err := h.svc.GitHubInstallURL(tenantID, middleware.GetUserID(r.Context()))
	if err != nil {
		h.writeErr(w, "start GitHub App install", err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	ciWriteJSON(w, http.StatusOK, SCMAppInstallURLResponse{URL: u})
}

// SCMAppCompleteGitHubRequest carries GitHub's setup redirect.
type SCMAppCompleteGitHubRequest struct {
	InstallationID int64  `json:"installation_id"`
	Code           string `json:"code"`
	State          string `json:"state"`
}

// CompleteGitHubInstall handles POST /api/v1/ci/scm-apps/github/installations
// @Summary      Bind a GitHub App installation
// @Description  Posted by the console with the setup redirect's installation_id, code and state. The state must be the caller's for this organization, and the caller's own GitHub authorization must reach the installation. An installation bound to another organization is refused. Audited.
// @Tags         CI
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body body SCMAppCompleteGitHubRequest true "Setup redirect"
// @Success      201  {object}  SCMAppInstallationResponse
// @Failure      403  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Router       /ci/scm-apps/github/installations [post]
func (h *SCMAppHandler) CompleteGitHubInstall(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	limitBody(w, r)
	var req SCMAppCompleteGitHubRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	inst, err := h.svc.CompleteGitHubInstall(r.Context(), tenantID,
		scmappsvc.CompleteGitHubInput{InstallationID: req.InstallationID, Code: req.Code, State: req.State}, h.actor(r))
	if err != nil {
		h.writeErr(w, "bind GitHub App installation", err)
		return
	}
	ciWriteJSON(w, http.StatusCreated, toSCMAppResponse(inst))
}

// Remove handles DELETE /api/v1/ci/scm-apps/installations/{id}
// @Summary      Unbind a code-host app installation
// @Tags         CI
// @Security     BearerAuth
// @Param        id path string true "Installation ID"
// @Success      204
// @Failure      404  {object}  apierror.Error
// @Router       /ci/scm-apps/installations/{id} [delete]
func (h *SCMAppHandler) Remove(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	id, ok := pathID(w, r, "SCM app installation")
	if !ok {
		return
	}
	if err := h.svc.Remove(r.Context(), tenantID, id, h.actor(r)); err != nil {
		h.writeErr(w, "unbind SCM app installation", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// SCMGitLabConnectRequest is a GitLab group access token to store.
type SCMGitLabConnectRequest struct {
	// Host is the GitLab host (default gitlab.com).
	Host  string `json:"host"`
	Group string `json:"group"`
	// Token is a group access token with the api scope (Developer role or
	// higher). Stored encrypted, never returned.
	Token string `json:"token"`
}

// ConnectGitLab handles POST /api/v1/ci/scm-apps/gitlab
// @Summary      Connect a GitLab group for CI statuses and merge request notes
// @Description  Checks with GitLab that the token is active, has the api scope and belongs to a direct member of the group (a group access token's bot), then stores it encrypted. The token is never returned. Audited.
// @Tags         CI
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body body SCMGitLabConnectRequest true "Group and token"
// @Success      201  {object}  SCMGitLabConnectionResponse
// @Failure      400  {object}  apierror.Error
// @Router       /ci/scm-apps/gitlab [post]
func (h *SCMAppHandler) ConnectGitLab(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	limitBody(w, r)
	var req SCMGitLabConnectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	c, err := h.svc.ConnectGitLab(r.Context(), tenantID, scmappsvc.ConnectGitLabInput{Host: req.Host, Group: req.Group, Token: req.Token}, h.actor(r))
	if err != nil {
		h.writeErr(w, "connect GitLab group", err)
		return
	}
	ciWriteJSON(w, http.StatusCreated, toGitLabResponse(c))
}

// RemoveGitLab handles DELETE /api/v1/ci/scm-apps/gitlab/{id}
// @Summary      Disconnect a GitLab group (its token is deleted)
// @Tags         CI
// @Security     BearerAuth
// @Param        id path string true "Connection ID"
// @Success      204
// @Failure      404  {object}  apierror.Error
// @Router       /ci/scm-apps/gitlab/{id} [delete]
func (h *SCMAppHandler) RemoveGitLab(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	id, ok := pathID(w, r, "GitLab connection")
	if !ok {
		return
	}
	if err := h.svc.RemoveGitLab(r.Context(), tenantID, id, h.actor(r)); err != nil {
		h.writeErr(w, "disconnect GitLab group", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GitHubWebhook handles POST /api/v1/webhooks/incoming/github-app
// @Summary      GitHub App webhook
// @Description  Installation events from GitHub, verified with the app's webhook secret (X-Hub-Signature-256) before anything is read.
// @Tags         CI
// @Accept       json
// @Success      204
// @Failure      401  {object}  apierror.Error
// @Router       /webhooks/incoming/github-app [post]
func (h *SCMAppHandler) GitHubWebhook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, scmappsvc.MaxWebhookBody+1))
	if err != nil || len(body) > scmappsvc.MaxWebhookBody {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	err = h.svc.HandleGitHubWebhook(r.Context(), r.Header.Get("X-GitHub-Event"), r.Header.Get("X-Hub-Signature-256"), body)
	switch {
	case errors.Is(err, scmappsvc.ErrBadSignature), errors.Is(err, githubapp.ErrNotConfigured):
		apierror.Unauthorized("Invalid webhook signature").WriteJSON(w)
	case err != nil:
		h.logger.Error("github app webhook failed", "error", logger.SanitizeError(err))
		apierror.InternalServerError("webhook failed").WriteJSON(w)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func (h *SCMAppHandler) writeErr(w http.ResponseWriter, what string, err error) {
	switch {
	case errors.Is(err, githubapp.ErrNotConfigured):
		apierror.New(http.StatusConflict, "GITHUB_APP_NOT_CONFIGURED", "This deployment has no GitHub App.").WriteJSON(w)
	case errors.Is(err, scmapp.ErrNotAuthorized):
		apierror.Forbidden("The installation could not be verified for you. Start the install again from the console.").WriteJSON(w)
	case errors.Is(err, scmapp.ErrBoundElsewhere):
		apierror.Conflict("This GitHub App installation is already bound to an organization.").WriteJSON(w)
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("SCM app installation").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(sanitizeLogField(err.Error())).WriteJSON(w)
	default:
		h.logger.Error(what+" failed", "error", logger.SanitizeError(err))
		apierror.InternalServerError(what + " failed").WriteJSON(w)
	}
}
