package handler

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/jira"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/ticketlink"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Ticket links of a finding: list, link an existing issue, unlink
// (research 157 K4). The finding routes' data-scope guard covers
// /findings/{id}/**; the tenant comes from the token.

// SetAuditService wires the audit log for link changes.
func (h *JiraWebhookHandler) SetAuditService(a *auditapp.AuditService) { h.audit = a }

// TicketLinkResponse is one link as the API returns it.
type TicketLinkResponse struct {
	ID            string  `json:"id"`
	IntegrationID string  `json:"integration_id"`
	Key           string  `json:"key"`
	URL           string  `json:"url"`
	Role          string  `json:"role"`
	State         string  `json:"state"`
	Source        string  `json:"source"`
	LastStatus    string  `json:"last_status,omitempty"`
	LastSyncedAt  *string `json:"last_synced_at,omitempty"`
	SyncError     string  `json:"sync_error,omitempty"`
	CreatedAt     string  `json:"created_at"`
}

func toTicketLinkResponse(l *ticketlink.Link) TicketLinkResponse {
	out := TicketLinkResponse{ID: l.ID.String(), IntegrationID: l.IntegrationID.String(), Key: l.ExternalKey, URL: l.URL,
		Role: l.Role, State: l.State, Source: l.Source, LastStatus: l.LastStatus, SyncError: l.SyncError,
		CreatedAt: l.CreatedAt.UTC().Format("2006-01-02T15:04:05Z07:00")}
	if l.LastSyncedAt != nil {
		s := l.LastSyncedAt.UTC().Format("2006-01-02T15:04:05Z07:00")
		out.LastSyncedAt = &s
	}
	return out
}

func (h *JiraWebhookHandler) linkIDs(w http.ResponseWriter, r *http.Request) (tenantID, findingID shared.ID, ok bool) {
	tid, err := shared.IDFromString(middleware.MustGetTenantID(r.Context()))
	if err != nil {
		apierror.Unauthorized("invalid tenant context").WriteJSON(w)
		return tid, findingID, false
	}
	fid, err := shared.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		apierror.NotFound("finding").WriteJSON(w)
		return tid, fid, false
	}
	return tid, fid, true
}

func (h *JiraWebhookHandler) linkError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("finding or link").WriteJSON(w)
	case errors.Is(err, shared.ErrConflict):
		apierror.Conflict("the issue is already linked to this finding").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		// The validation messages are the platform's own (no request text).
		apierror.BadRequest(err.Error()).WriteJSON(w)
	default:
		h.logger.Error("ticket link request failed", "error", logger.SanitizeValue(err.Error()))
		apierror.BadGateway("the tracker request failed").WriteJSON(w)
	}
}

func (h *JiraWebhookHandler) auditLink(r *http.Request, action auditdom.Action, findingID string, l *ticketlink.Link, msg string) {
	if h.audit == nil || l == nil {
		return
	}
	ev := auditapp.NewSuccessEvent(action, auditdom.ResourceTypeFinding, findingID).
		WithResourceName(findingID).
		WithMessage(msg).
		WithMetadata("issue_key", l.ExternalKey).
		WithMetadata("integration_id", l.IntegrationID.String()).
		WithMetadata("link_id", l.ID.String()).
		WithSeverity(auditdom.SeverityLow)
	recordConfigAudit(r.Context(), h.audit, h.logger, configAuditContext(r), ev)
}

// ListTicketLinks handles GET /api/v1/findings/{id}/ticket-links.
//
//	@Summary		List a finding's ticket links
//	@Tags			Findings
//	@Produce		json
//	@Security		BearerAuth
//	@Param			id	path		string	true	"Finding ID"
//	@Success		200	{object}	map[string]any
//	@Failure		404	{object}	apierror.Error
//	@Router			/findings/{id}/ticket-links [get]
func (h *JiraWebhookHandler) ListTicketLinks(w http.ResponseWriter, r *http.Request) {
	tid, fid, ok := h.linkIDs(w, r)
	if !ok {
		return
	}
	ls, err := h.service.FindingLinks(r.Context(), tid, fid)
	if err != nil {
		h.linkError(w, err)
		return
	}
	out := make([]TicketLinkResponse, 0, len(ls))
	for _, l := range ls {
		out = append(out, toTicketLinkResponse(l))
	}
	writeJSON(w, http.StatusOK, map[string]any{"links": out})
}

// LinkTicketIssueRequest names the issue to link: a key (SEC-123) or its
// browse URL on the integration's site.
type LinkTicketIssueRequest struct {
	Issue string `json:"issue"`
}

// LinkTicketIssue handles POST /api/v1/findings/{id}/ticket-links.
//
//	@Summary		Link an existing Jira issue to a finding
//	@Description	The issue must exist on the organization's Jira site and be visible to the integration. A key or a browse URL on that site.
//	@Tags			Findings
//	@Accept			json
//	@Produce		json
//	@Security		BearerAuth
//	@Param			id		path		string					true	"Finding ID"
//	@Param			body	body		LinkTicketIssueRequest	true	"Issue"
//	@Success		201		{object}	TicketLinkResponse
//	@Failure		400		{object}	apierror.Error
//	@Failure		404		{object}	apierror.Error
//	@Failure		409		{object}	apierror.Error
//	@Router			/findings/{id}/ticket-links [post]
func (h *JiraWebhookHandler) LinkTicketIssue(w http.ResponseWriter, r *http.Request) {
	tid, fid, ok := h.linkIDs(w, r)
	if !ok {
		return
	}
	var req LinkTicketIssueRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 8*1024)).Decode(&req); err != nil || req.Issue == "" || len(req.Issue) > 2048 {
		apierror.BadRequest("give an issue key or URL").WriteJSON(w)
		return
	}
	var by *shared.ID
	if u := middleware.GetLocalUserID(r.Context()); !u.IsZero() {
		by = &u
	}
	l, err := h.service.LinkExistingIssue(r.Context(), tid, fid, req.Issue, by)
	if err != nil {
		h.linkError(w, err)
		return
	}
	h.auditLink(r, auditdom.ActionFindingTicketLinked, fid.String(), l, "Jira issue linked to the finding")
	writeJSON(w, http.StatusCreated, toTicketLinkResponse(l))
}

// UnlinkTicketIssue handles DELETE /api/v1/findings/{id}/ticket-links/{link_id}.
//
//	@Summary		Unlink a Jira issue from a finding
//	@Description	Removes the link only; the issue is left alone.
//	@Tags			Findings
//	@Security		BearerAuth
//	@Param			id		path	string	true	"Finding ID"
//	@Param			link_id	path	string	true	"Link ID"
//	@Success		204
//	@Failure		404	{object}	apierror.Error
//	@Router			/findings/{id}/ticket-links/{link_id} [delete]
func (h *JiraWebhookHandler) UnlinkTicketIssue(w http.ResponseWriter, r *http.Request) {
	tid, fid, ok := h.linkIDs(w, r)
	if !ok {
		return
	}
	lid, err := shared.IDFromString(chi.URLParam(r, "link_id"))
	if err != nil {
		apierror.NotFound("link").WriteJSON(w)
		return
	}
	l, err := h.service.UnlinkIssue(r.Context(), tid, fid, lid)
	if err != nil {
		h.linkError(w, err)
		return
	}
	h.auditLink(r, auditdom.ActionFindingTicketUnlinked, fid.String(), l, "Jira issue unlinked from the finding")
	w.WriteHeader(http.StatusNoContent)
}

// Task issues (one issue per remediation task): the task routes; the service
// checks the caller's data scope over the task's members.

func (h *JiraWebhookHandler) taskIDs(w http.ResponseWriter, r *http.Request) (tenantID, taskID shared.ID, ok bool) {
	tid, err := shared.IDFromString(middleware.MustGetTenantID(r.Context()))
	if err != nil {
		apierror.Unauthorized("invalid tenant context").WriteJSON(w)
		return tid, taskID, false
	}
	id, err := shared.IDFromString(chi.URLParam(r, "task_id"))
	if err != nil {
		apierror.NotFound("task").WriteJSON(w)
		return tid, id, false
	}
	return tid, id, true
}

// ListTaskTicketLinks handles GET /api/v1/remediation/tasks/{task_id}/ticket-links.
//
//	@Summary		List a remediation task's ticket links
//	@Tags			Remediation
//	@Produce		json
//	@Security		BearerAuth
//	@Param			task_id	path		string	true	"Task ID"
//	@Success		200		{object}	map[string]any
//	@Failure		404		{object}	apierror.Error
//	@Router			/remediation/tasks/{task_id}/ticket-links [get]
func (h *JiraWebhookHandler) ListTaskTicketLinks(w http.ResponseWriter, r *http.Request) {
	tid, taskID, ok := h.taskIDs(w, r)
	if !ok {
		return
	}
	if _, err := h.service.TaskVisible(r.Context(), tid, taskID); err != nil {
		h.taskIssueError(w, err)
		return
	}
	ls, err := h.service.TaskLinks(r.Context(), tid, taskID)
	if err != nil {
		h.taskIssueError(w, err)
		return
	}
	out := make([]TicketLinkResponse, 0, len(ls))
	for _, l := range ls {
		out = append(out, toTicketLinkResponse(l))
	}
	writeJSON(w, http.StatusOK, map[string]any{"links": out})
}

// CreateTaskIssueRequest asks for a task's issue; project_key empty = the
// integration's default project.
type CreateTaskIssueRequest struct {
	ProjectKey string `json:"project_key"`
}

// CreateTaskIssue handles POST /api/v1/remediation/tasks/{task_id}/ticket-links.
//
//	@Summary		Create a remediation task's Jira issue
//	@Description	One issue per task, in a project configured for ticketing. The issue carries the task's title, fix, count of findings, deadline and a link back (no finding details); its status then follows the task, with a progress comment on every move. Moving the issue to Done claims the fix of the task's open findings. The caller must be able to change the task (every member in their data scope).
//	@Tags			Remediation
//	@Accept			json
//	@Produce		json
//	@Security		BearerAuth
//	@Param			task_id	path		string					true	"Task ID"
//	@Param			body	body		CreateTaskIssueRequest	false	"Project"
//	@Success		201		{object}	TicketLinkResponse
//	@Failure		400		{object}	apierror.Error
//	@Failure		404		{object}	apierror.Error
//	@Failure		409		{object}	apierror.Error
//	@Router			/remediation/tasks/{task_id}/ticket-links [post]
func (h *JiraWebhookHandler) CreateTaskIssue(w http.ResponseWriter, r *http.Request) {
	tid, taskID, ok := h.taskIDs(w, r)
	if !ok {
		return
	}
	var req CreateTaskIssueRequest
	if r.ContentLength != 0 {
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
			apierror.BadRequest("invalid request body").WriteJSON(w)
			return
		}
	}
	if len(req.ProjectKey) > 32 {
		apierror.BadRequest("project_key is at most 32 characters").WriteJSON(w)
		return
	}
	var by *shared.ID
	if uid, err := shared.IDFromString(middleware.GetUserID(r.Context())); err == nil {
		by = &uid
	}
	l, err := h.service.CreateTaskIssue(r.Context(), jira.CreateTaskIssueInput{TenantID: tid, TaskID: taskID, ProjectKey: req.ProjectKey, By: by})
	if err != nil {
		h.taskIssueError(w, err)
		return
	}
	if h.audit != nil {
		ev := auditapp.NewSuccessEvent(auditdom.ActionRemediationTaskIssueCreated, auditdom.ResourceTypeRemediationTask, taskID.String()).
			WithResourceName(taskID.String()).
			WithMessage("Created the task's tracker issue "+l.ExternalKey).
			WithMetadata("issue_key", l.ExternalKey).
			WithMetadata("integration_id", l.IntegrationID.String()).
			WithMetadata("link_id", l.ID.String()).
			WithSeverity(auditdom.SeverityLow)
		recordConfigAudit(r.Context(), h.audit, h.logger, configAuditContext(r), ev)
	}
	writeJSON(w, http.StatusCreated, toTicketLinkResponse(l))
}

func (h *JiraWebhookHandler) taskIssueError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("task").WriteJSON(w)
	case errors.Is(err, shared.ErrForbidden):
		apierror.Forbidden("you cannot change this task (findings outside your scope)").WriteJSON(w)
	case errors.Is(err, shared.ErrConflict):
		apierror.Conflict("the task already has an issue").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		// The validation messages are the platform's own (no request text).
		apierror.BadRequest(err.Error()).WriteJSON(w)
	default:
		h.logger.Error("task issue request failed", "error", logger.SanitizeValue(err.Error()))
		apierror.BadGateway("the tracker request failed").WriteJSON(w)
	}
}
