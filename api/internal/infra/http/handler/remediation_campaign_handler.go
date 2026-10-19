package handler

// Remediation campaigns: programs of remediation tasks
// (docs/architecture/remediation-campaigns.md). A campaign holds tasks, never
// findings; its summary is derived from its tasks over the caller's scope.

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/exposure"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// RemediationCampaignHandler handles remediation campaign endpoints.
type RemediationCampaignHandler struct {
	service *exposure.RemediationCampaignService
	logger  *logger.Logger
}

// NewRemediationCampaignHandler creates a new handler.
func NewRemediationCampaignHandler(svc *exposure.RemediationCampaignService, log *logger.Logger) *RemediationCampaignHandler {
	return &RemediationCampaignHandler{service: svc, logger: log}
}

// CreateRemCampaignRequest creates a campaign, optionally with tasks.
type CreateRemCampaignRequest struct {
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	Priority     string   `json:"priority"`
	AssignedTo   string   `json:"assigned_to"`
	AssignedTeam string   `json:"assigned_team"`
	StartDate    string   `json:"start_date"`
	DueDate      string   `json:"due_date"`
	Tags         []string `json:"tags"`
	// TaskIDs are tasks to put in the campaign at once.
	TaskIDs []string `json:"task_ids,omitempty"`
	// Move moves tasks that are in another campaign (else 409).
	Move bool `json:"move,omitempty"`
}

// UpdateRemCampaignRequest changes a campaign. Dates take an RFC 3339
// timestamp, a date or null (clear); assignee and team take an id or "".
type UpdateRemCampaignRequest struct {
	Name         *string         `json:"name,omitempty"`
	Description  *string         `json:"description,omitempty"`
	Priority     *string         `json:"priority,omitempty"`
	Tags         []string        `json:"tags,omitempty"`
	StartDate    json.RawMessage `json:"start_date,omitempty" swaggertype:"string"`
	DueDate      json.RawMessage `json:"due_date,omitempty" swaggertype:"string"`
	AssignedTo   *string         `json:"assigned_to,omitempty"`
	AssignedTeam *string         `json:"assigned_team,omitempty"`
	Version      *int            `json:"version,omitempty"`
}

// CampaignStatusRequest moves a campaign.
type CampaignStatusRequest struct {
	Status  string `json:"status" enums:"active,completed,canceled"`
	Version *int   `json:"version,omitempty"`
}

// CampaignTasksRequest adds tasks to a campaign.
type CampaignTasksRequest struct {
	TaskIDs []string `json:"task_ids"`
	Move    bool     `json:"move,omitempty"`
}

// CampaignSummaryResponse is what a campaign holds, as the caller may see it.
type CampaignSummaryResponse struct {
	Tasks            int     `json:"tasks"`
	LiveTasks        int     `json:"live_tasks"`
	DoneTasks        int     `json:"done_tasks"`
	OverdueTasks     int     `json:"overdue_tasks"`
	HiddenTasks      int     `json:"hidden_tasks"`
	Findings         int     `json:"findings"`
	ClosedFindings   int     `json:"closed_findings"`
	VerifiedFindings int     `json:"verified_findings"`
	Progress         float64 `json:"progress"`
}

// RemediationCampaignResponse is a campaign as the caller sees it.
type RemediationCampaignResponse struct {
	ID           string                       `json:"id"`
	Name         string                       `json:"name"`
	Description  string                       `json:"description"`
	Status       string                       `json:"status" enums:"draft,active,completed,canceled"`
	Priority     string                       `json:"priority" enums:"critical,high,medium,low"`
	AssignedTo   string                       `json:"assigned_to,omitempty"`
	AssignedTeam string                       `json:"assigned_team,omitempty"`
	CreatedBy    string                       `json:"created_by,omitempty"`
	IsOverdue    bool                         `json:"is_overdue"`
	CanEdit      bool                         `json:"can_edit"`
	StartDate    *time.Time                   `json:"start_date,omitempty"`
	DueDate      *time.Time                   `json:"due_date,omitempty"`
	CompletedAt  *time.Time                   `json:"completed_at,omitempty"`
	Tags         []string                     `json:"tags"`
	CreatedAt    time.Time                    `json:"created_at"`
	UpdatedAt    time.Time                    `json:"updated_at"`
	Version      int                          `json:"version"`
	Summary      CampaignSummaryResponse      `json:"summary"`
	Ticket       *exposure.CampaignTicketLink `json:"ticket,omitempty"`
}

// RemediationCampaignListResponse is a page of campaigns with the count of
// the caller's campaigns per status.
type RemediationCampaignListResponse struct {
	pagination.Result[RemediationCampaignResponse]
	StatusCounts map[string]int `json:"status_counts"`
}

func toRemediationCampaignResp(v exposure.CampaignView) RemediationCampaignResponse {
	c, s := v.Campaign, v.Summary
	tags := c.Tags()
	if tags == nil {
		tags = []string{}
	}
	return RemediationCampaignResponse{
		ID:           c.ID().String(),
		Name:         c.Name(),
		Description:  c.Description(),
		Status:       string(c.Status()),
		Priority:     string(c.Priority()),
		AssignedTo:   idPtrToString(c.AssignedTo()),
		AssignedTeam: idPtrToString(c.AssignedTeam()),
		CreatedBy:    idPtrToString(c.CreatedBy()),
		IsOverdue:    c.IsOverdue(),
		CanEdit:      v.CanEdit,
		StartDate:    c.StartDate(),
		DueDate:      c.DueDate(),
		CompletedAt:  c.CompletedAt(),
		Tags:         tags,
		CreatedAt:    c.CreatedAt(),
		UpdatedAt:    c.UpdatedAt(),
		Version:      c.Version(),
		Summary: CampaignSummaryResponse{
			Tasks: s.Tasks, LiveTasks: s.LiveTasks, DoneTasks: s.DoneTasks, OverdueTasks: s.OverdueTasks,
			HiddenTasks: s.HiddenTasks, Findings: s.Findings, ClosedFindings: s.ClosedFindings,
			VerifiedFindings: s.VerifiedFindings, Progress: s.Progress(),
		},
	}
}

// List lists remediation campaigns.
// @Summary      List remediation campaigns
// @Description  The campaigns the caller may see (a restricted member: those they created or own, and those with a task holding a finding in their data scope), each with its summary derived from its tasks over the caller's scope, plus the count per status.
// @Tags         Remediation
// @Produce      json
// @Param        status    query  string  false  "draft, active, completed or canceled"
// @Param        priority  query  string  false  "critical, high, medium or low"
// @Param        search    query  string  false  "Name or description search"
// @Param        page      query  int     false  "Page number" default(1)
// @Param        per_page  query  int     false  "Items per page" default(20)
// @Success      200  {object}  RemediationCampaignListResponse
// @Failure      400  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /remediation/campaigns [get]
func (h *RemediationCampaignHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	page, ok := listPageMax(w, r, 20, 100)
	if !ok {
		return
	}
	filter := remediation.CampaignFilter{}
	q := r.URL.Query()
	if s := q.Get("status"); s != "" {
		st := remediation.CampaignStatus(s)
		filter.Status = &st
	}
	if p := q.Get("priority"); p != "" {
		pr := remediation.CampaignPriority(p)
		filter.Priority = &pr
	}
	if s := q.Get("search"); s != "" {
		filter.Search = &s
	}
	result, err := h.service.ListCampaigns(r.Context(), tenantID, filter, page)
	if err != nil {
		h.handleError(w, err)
		return
	}
	counts, err := h.service.CountCampaignsByStatus(r.Context(), tenantID)
	if err != nil {
		h.handleError(w, err)
		return
	}
	// Batch-load linked Jira epics (best effort: a lookup failure omits them).
	var tickets map[string]*exposure.CampaignTicketLink
	if tid, terr := shared.IDFromString(tenantID); terr == nil {
		ids := make([]shared.ID, 0, len(result.Data))
		for _, v := range result.Data {
			ids = append(ids, v.Campaign.ID())
		}
		if m, lerr := h.service.CampaignTicketsFor(r.Context(), tid, ids); lerr == nil {
			tickets = m
		} else {
			h.logger.Warn("failed to load campaign tickets for list", "error", lerr)
		}
	}
	items := make([]RemediationCampaignResponse, 0, len(result.Data))
	for _, v := range result.Data {
		item := toRemediationCampaignResp(v)
		item.Ticket = tickets[item.ID]
		items = append(items, item)
	}
	sc := map[string]int{}
	for _, st := range []remediation.CampaignStatus{remediation.CampaignStatusDraft, remediation.CampaignStatusActive,
		remediation.CampaignStatusCompleted, remediation.CampaignStatusCanceled} {
		sc[string(st)] = counts[st]
	}
	writeJSON(w, http.StatusOK, RemediationCampaignListResponse{Result: pagination.NewResult(items, result.Total, page), StatusCounts: sc})
}

// Create creates a campaign.
// @Summary      Create a remediation campaign
// @Description  Creates a draft campaign, optionally with tasks (each one the caller may change; a task in another campaign needs move, and the caller must be able to change that campaign).
// @Tags         Remediation
// @Accept       json
// @Produce      json
// @Param        body  body  CreateRemCampaignRequest  true  "Campaign"
// @Success      201  {object}  RemediationCampaignResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error  "TASKS_IN_OTHER_CAMPAIGN"
// @Security     BearerAuth
// @Router       /remediation/campaigns [post]
func (h *RemediationCampaignHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req CreateRemCampaignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	v, err := h.service.CreateCampaign(r.Context(), exposure.CreateRemediationCampaignInput{
		TenantID:     middleware.MustGetTenantID(r.Context()),
		Name:         req.Name,
		Description:  req.Description,
		Priority:     req.Priority,
		AssignedTo:   req.AssignedTo,
		AssignedTeam: req.AssignedTeam,
		StartDate:    req.StartDate,
		DueDate:      req.DueDate,
		Tags:         req.Tags,
		TaskIDs:      req.TaskIDs,
		MoveTasks:    req.Move,
		ActorID:      middleware.GetUserID(r.Context()),
	}, h.buildAuditContext(r))
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, toRemediationCampaignResp(*v))
}

// Get retrieves a campaign.
// @Summary      Get a remediation campaign
// @Tags         Remediation
// @Produce      json
// @Param        id  path  string  true  "Campaign ID"
// @Success      200  {object}  RemediationCampaignResponse
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /remediation/campaigns/{id} [get]
func (h *RemediationCampaignHandler) Get(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	v, err := h.service.GetCampaign(r.Context(), tenantID, chi.URLParam(r, "id"))
	if err != nil {
		h.handleError(w, err)
		return
	}
	h.writeCampaign(w, r, http.StatusOK, v)
}

func (h *RemediationCampaignHandler) writeCampaign(w http.ResponseWriter, r *http.Request, status int, v *exposure.CampaignView) {
	resp := toRemediationCampaignResp(*v)
	if link, err := h.service.CampaignTicketFor(r.Context(), v.Campaign.TenantID(), v.Campaign.ID()); err == nil {
		resp.Ticket = link
	} else {
		h.logger.Warn("failed to load campaign ticket", "error", err)
	}
	writeJSON(w, status, resp)
}

// Update changes a campaign.
// @Summary      Update a remediation campaign
// @Description  The due date can only move earlier. version is checked (409 when stale).
// @Tags         Remediation
// @Accept       json
// @Produce      json
// @Param        id    path  string                    true  "Campaign ID"
// @Param        body  body  UpdateRemCampaignRequest  true  "Fields to change"
// @Success      200  {object}  RemediationCampaignResponse
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /remediation/campaigns/{id} [patch]
func (h *RemediationCampaignHandler) Update(w http.ResponseWriter, r *http.Request) {
	var req UpdateRemCampaignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	startDate, ok := optionalDateField(w, "start_date", req.StartDate)
	if !ok {
		return
	}
	dueDate, ok := optionalDateField(w, "due_date", req.DueDate)
	if !ok {
		return
	}
	v, err := h.service.UpdateCampaign(r.Context(), middleware.MustGetTenantID(r.Context()), chi.URLParam(r, "id"), exposure.UpdateRemediationCampaignInput{
		Name:         req.Name,
		Description:  req.Description,
		Priority:     req.Priority,
		Tags:         req.Tags,
		StartDate:    startDate,
		DueDate:      dueDate,
		AssignedTo:   req.AssignedTo,
		AssignedTeam: req.AssignedTeam,
		Version:      req.Version,
	}, h.buildAuditContext(r))
	if err != nil {
		h.handleError(w, err)
		return
	}
	h.writeCampaign(w, r, http.StatusOK, v)
}

// UpdateStatus moves a campaign.
// @Summary      Change a remediation campaign's status
// @Description  active starts a draft or reopens a completed campaign; completed needs every task closed and one done; canceled from draft or active. Tasks are not changed.
// @Tags         Remediation
// @Accept       json
// @Produce      json
// @Param        id    path  string                 true  "Campaign ID"
// @Param        body  body  CampaignStatusRequest  true  "Target status"
// @Success      200  {object}  RemediationCampaignResponse
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /remediation/campaigns/{id}/status [patch]
func (h *RemediationCampaignHandler) UpdateStatus(w http.ResponseWriter, r *http.Request) {
	var req CampaignStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	v, err := h.service.UpdateCampaignStatus(r.Context(), middleware.MustGetTenantID(r.Context()), chi.URLParam(r, "id"),
		req.Status, req.Version, h.buildAuditContext(r))
	if err != nil {
		h.handleError(w, err)
		return
	}
	h.writeCampaign(w, r, http.StatusOK, v)
}

// AddTasks adds tasks to a campaign.
// @Summary      Add tasks to a remediation campaign
// @Description  The campaign must be a draft or active one the caller may change, and so must every task. A task in another campaign answers 409 TASKS_IN_OTHER_CAMPAIGN unless move is set (the caller must be able to change that campaign too).
// @Tags         Remediation
// @Accept       json
// @Produce      json
// @Param        id    path  string                true  "Campaign ID"
// @Param        body  body  CampaignTasksRequest  true  "Tasks"
// @Success      200  {object}  RemediationCampaignResponse
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error  "TASKS_IN_OTHER_CAMPAIGN"
// @Security     BearerAuth
// @Router       /remediation/campaigns/{id}/tasks [post]
func (h *RemediationCampaignHandler) AddTasks(w http.ResponseWriter, r *http.Request) {
	var req CampaignTasksRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	v, err := h.service.AddCampaignTasks(r.Context(), middleware.MustGetTenantID(r.Context()), chi.URLParam(r, "id"),
		req.TaskIDs, req.Move, middleware.GetUserID(r.Context()), h.buildAuditContext(r))
	if err != nil {
		h.handleError(w, err)
		return
	}
	h.writeCampaign(w, r, http.StatusOK, v)
}

// RemoveTask takes a task out of a campaign.
// @Summary      Remove a task from a remediation campaign
// @Description  The task stays; it only leaves the campaign.
// @Tags         Remediation
// @Produce      json
// @Param        id       path  string  true  "Campaign ID"
// @Param        task_id  path  string  true  "Task ID"
// @Success      200  {object}  RemediationCampaignResponse
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /remediation/campaigns/{id}/tasks/{task_id} [delete]
func (h *RemediationCampaignHandler) RemoveTask(w http.ResponseWriter, r *http.Request) {
	v, err := h.service.RemoveCampaignTask(r.Context(), middleware.MustGetTenantID(r.Context()), chi.URLParam(r, "id"),
		chi.URLParam(r, "task_id"), middleware.GetUserID(r.Context()), h.buildAuditContext(r))
	if err != nil {
		h.handleError(w, err)
		return
	}
	h.writeCampaign(w, r, http.StatusOK, v)
}

// CreateTicket creates the campaign's Jira epic.
func (h *RemediationCampaignHandler) CreateTicket(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProjectKey string `json:"project_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	if req.ProjectKey == "" {
		apierror.BadRequest("project_key is required").WriteJSON(w)
		return
	}
	info, err := h.service.CreateTicket(r.Context(), middleware.MustGetTenantID(r.Context()), chi.URLParam(r, "id"), req.ProjectKey)
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, info)
}

// Delete deletes a campaign; its tasks stay.
func (h *RemediationCampaignHandler) Delete(w http.ResponseWriter, r *http.Request) {
	if err := h.service.DeleteCampaign(r.Context(), middleware.MustGetTenantID(r.Context()), chi.URLParam(r, "id"), h.buildAuditContext(r)); err != nil {
		h.handleError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *RemediationCampaignHandler) buildAuditContext(r *http.Request) audit.AuditContext {
	return audit.AuditContext{
		TenantID:   middleware.GetTenantID(r.Context()),
		ActorID:    middleware.GetUserID(r.Context()),
		ActorEmail: auditActorEmail(r.Context()),
		ActorIP:    getClientIP(r),
		UserAgent:  r.UserAgent(),
		RequestID:  r.Header.Get("X-Request-ID"),
	}
}

// codeTasksInOtherCampaign is the 409 code for tasks already in a campaign.
const codeTasksInOtherCampaign apierror.Code = "TASKS_IN_OTHER_CAMPAIGN"

func (h *RemediationCampaignHandler) handleError(w http.ResponseWriter, err error) {
	var other *exposure.TasksInOtherCampaignError
	switch {
	case errors.As(err, &other):
		apierror.New(http.StatusConflict, codeTasksInOtherCampaign, "some tasks are in another campaign; send move to move them").
			WithDetails(map[string]any{"tasks": other.Conflicts}).WriteJSON(w)
	case errors.Is(err, exposure.ErrCampaignTaskNotFound):
		apierror.NotFound("task").WriteJSON(w)
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("campaign").WriteJSON(w)
	case errors.Is(err, remediation.ErrCampaignVersionConflict):
		apierror.Conflict("the campaign was changed by someone else; reload it and try again").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	case errors.Is(err, shared.ErrForbidden):
		apierror.Forbidden(err.Error()).WriteJSON(w)
	default:
		h.logger.Error("remediation campaign error", "error", err)
		apierror.InternalServerError("internal error").WriteJSON(w)
	}
}

// optionalDateField reads a date field that may be absent (nil), null ("",
// clear) or a string.
func optionalDateField(w http.ResponseWriter, field string, raw json.RawMessage) (*string, bool) {
	if len(raw) == 0 {
		return nil, true
	}
	if string(raw) == "null" {
		empty := ""
		return &empty, true
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		apierror.BadRequest(field + " must be an RFC 3339 timestamp, a date (YYYY-MM-DD) or null").WriteJSON(w)
		return nil, false
	}
	return &s, true
}

func idPtrToString(id *shared.ID) string {
	if id == nil {
		return ""
	}
	return id.String()
}
