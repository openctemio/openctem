package handler

// Remediation task endpoints (docs/rfcs/RFC-098-remediation-tasks.md).

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/finding"
	remediationapp "github.com/openctemio/openctem/api/internal/app/remediation"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// RemediationTaskHandler serves remediation tasks.
type RemediationTaskHandler struct {
	service *remediationapp.TaskService
	logger  *logger.Logger
}

// NewRemediationTaskHandler creates the handler.
func NewRemediationTaskHandler(svc *remediationapp.TaskService, log *logger.Logger) *RemediationTaskHandler {
	return &RemediationTaskHandler{service: svc, logger: log}
}

// RemediationTaskResponse is a task.
type RemediationTaskResponse struct {
	ID              string                    `json:"id"`
	ActionID        string                    `json:"action_id"`
	ActionKey       string                    `json:"action_key"`
	ActionKind      string                    `json:"action_kind"`
	ActionTitle     string                    `json:"action_title"`
	CampaignID      *string                   `json:"campaign_id,omitempty"`
	Title           string                    `json:"title"`
	Description     string                    `json:"description"`
	AssigneeUserID  *string                   `json:"assignee_user_id,omitempty"`
	AssigneeGroupID *string                   `json:"assignee_group_id,omitempty"`
	State           string                    `json:"state"`
	StateNote       string                    `json:"state_note,omitempty"`
	Deadline        *time.Time                `json:"deadline,omitempty"`
	DeadlineSource  string                    `json:"deadline_source,omitempty"`
	ManualDeadline  *time.Time                `json:"manual_deadline,omitempty"`
	Counts          RemediationTaskCountsResp `json:"counts"`
	HiddenMembers   int                       `json:"hidden_members"`
	RegressionOf    *string                   `json:"regression_of,omitempty"`
	ArchivedAt      *time.Time                `json:"archived_at,omitempty"`
	ArchivedNote    string                    `json:"archived_note,omitempty"`
	ClosedAt        *time.Time                `json:"closed_at,omitempty"`
	Version         int                       `json:"version"`
	CreatedBy       *string                   `json:"created_by,omitempty"`
	CreatedAt       time.Time                 `json:"created_at"`
	UpdatedAt       time.Time                 `json:"updated_at"`
}

// RemediationTaskCountsResp are a task's member counters.
type RemediationTaskCountsResp struct {
	Total      int `json:"total"`
	Open       int `json:"open"`
	InProgress int `json:"in_progress"`
	FixApplied int `json:"fix_applied"`
	Closed     int `json:"closed"`
	Verified   int `json:"verified"`
	Related    int `json:"related"`
	RiskPoints int `json:"risk_points"`
}

func optIDStr(id *shared.ID) *string {
	if id == nil {
		return nil
	}
	s := id.String()
	return &s
}

func toRemediationTaskResp(t *remediation.Task) RemediationTaskResponse {
	r := RemediationTaskResponse{
		ID: t.ID.String(), ActionID: t.ActionID.String(), ActionKey: t.ActionKey, ActionKind: t.ActionKind,
		ActionTitle: t.ActionTitle, CampaignID: optIDStr(t.CampaignID), Title: t.Title, Description: t.Description,
		AssigneeUserID: optIDStr(t.AssigneeUserID), AssigneeGroupID: optIDStr(t.AssigneeGroupID),
		State: string(t.State), StateNote: t.ManualStateNote, Deadline: t.Deadline, ManualDeadline: t.ManualDeadline,
		Counts: RemediationTaskCountsResp{
			Total: t.Counts.Total, Open: t.Counts.Open, InProgress: t.Counts.InProgress, FixApplied: t.Counts.FixApplied,
			Closed: t.Counts.Closed, Verified: t.Counts.Verified, Related: t.Counts.Related, RiskPoints: t.Counts.RiskPoints,
		},
		HiddenMembers: t.HiddenMembers, RegressionOf: optIDStr(t.RegressionOf), ArchivedAt: t.ArchivedAt,
		ArchivedNote: t.ArchivedNote, ClosedAt: t.ClosedAt, Version: t.Version, CreatedBy: optIDStr(t.CreatedBy),
		CreatedAt: t.CreatedAt, UpdatedAt: t.UpdatedAt,
	}
	if t.DeadlineSource != nil {
		r.DeadlineSource = string(*t.DeadlineSource)
	}
	return r
}

func (h *RemediationTaskHandler) tenant(w http.ResponseWriter, r *http.Request) (shared.ID, bool) {
	tid, err := shared.IDFromString(middleware.MustGetTenantID(r.Context()))
	if err != nil {
		apierror.Unauthorized("invalid tenant").WriteJSON(w)
		return shared.ID{}, false
	}
	return tid, true
}

func callerID(r *http.Request) *shared.ID {
	id, err := shared.IDFromString(middleware.GetUserID(r.Context()))
	if err != nil {
		return nil
	}
	return &id
}

func pathTaskID(w http.ResponseWriter, r *http.Request) (shared.ID, bool) {
	id, err := shared.IDFromString(chi.URLParam(r, "task_id"))
	if err != nil {
		apierror.NotFound("remediation task not found").WriteJSON(w)
		return shared.ID{}, false
	}
	return id, true
}

func parseIDList(field string, ss []string) ([]shared.ID, error) {
	out := make([]shared.ID, 0, len(ss))
	for _, s := range ss {
		id, err := shared.IDFromString(strings.TrimSpace(s))
		if err != nil {
			return nil, fmt.Errorf("%w: %s must hold ids", shared.ErrValidation, field)
		}
		out = append(out, id)
	}
	return out, nil
}

// RemediationConflictsInput says what to do with findings that already
// belong to another active task: skip them all, or move the named ones (with
// a reason; the others are skipped). Without it such findings answer 409
// FINDINGS_IN_OTHER_TASK.
type RemediationConflictsInput struct {
	Skip       bool     `json:"skip,omitempty"`
	Move       []string `json:"move,omitempty"`
	MoveReason string   `json:"move_reason,omitempty"`
}

func parseConflicts(in *RemediationConflictsInput) (remediation.ConflictResolution, error) {
	if in == nil {
		return remediation.ConflictResolution{}, nil
	}
	move, err := parseIDList("conflicts.move", in.Move)
	if err != nil {
		return remediation.ConflictResolution{}, err
	}
	if len(move) > remediation.MaxMembersPerRequest {
		return remediation.ConflictResolution{}, fmt.Errorf("%w: at most %d findings to move", shared.ErrValidation, remediation.MaxMembersPerRequest)
	}
	return remediation.ConflictResolution{Skip: in.Skip, Move: move, MoveReason: in.MoveReason}, nil
}

// RemediationFindingConflictResponse is one finding of a 409
// FINDINGS_IN_OTHER_TASK answer (details.conflicts). task_title and the
// assignee are null when the caller cannot read the task.
type RemediationFindingConflictResponse struct {
	FindingID       string  `json:"finding_id"`
	FindingTitle    string  `json:"finding_title"`
	TaskID          string  `json:"task_id"`
	TaskTitle       *string `json:"task_title"`
	AssigneeUserID  *string `json:"assignee_user_id"`
	AssigneeGroupID *string `json:"assignee_group_id"`
	CanMove         bool    `json:"can_move"`
}

func toConflictResps(cs []remediation.FindingConflict) []RemediationFindingConflictResponse {
	out := make([]RemediationFindingConflictResponse, 0, len(cs))
	for _, c := range cs {
		r := RemediationFindingConflictResponse{FindingID: c.FindingID.String(), FindingTitle: c.FindingTitle,
			TaskID: c.TaskID.String(), TaskTitle: c.TaskTitle, CanMove: c.CanMove}
		if c.AssigneeUserID != nil {
			v := c.AssigneeUserID.String()
			r.AssigneeUserID = &v
		}
		if c.AssigneeGroupID != nil {
			v := c.AssigneeGroupID.String()
			r.AssigneeGroupID = &v
		}
		out = append(out, r)
	}
	return out
}

func parseOptID(field, s string) (*shared.ID, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	id, err := shared.IDFromString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("%w: %s must be an id", shared.ErrValidation, field)
	}
	return &id, nil
}

// List lists tasks. Query: state (comma list), assignee (me or a user id),
// group_id, action_id, action_kind, campaign_id, finding_id, search, sort
// (deadline, risk, updated, created), page, per_page.
// @Summary      List remediation tasks
// @Description  Tasks the caller may see: a restricted member sees tasks with at least one finding in their data scope, with the counters over those findings (hidden_members counts the rest).
// @Tags         Remediation
// @Produce      json
// @Param        state        query  string  false  "Comma list of states (open, in_progress, verifying, done, closed_unverified, on_hold, canceled, archived)"
// @Param        assignee     query  string  false  "me (assigned to the caller or one of their groups) or a user ID"
// @Param        group_id     query  string  false  "Assigned group ID"
// @Param        action_id    query  string  false  "Remediation action ID"
// @Param        action_kind  query  string  false  "Action kind (upgrade, rotate, sol, manual)"
// @Param        campaign_id  query  string  false  "Campaign ID"
// @Param        finding_id   query  string  false  "Tasks this finding is a member of"
// @Param        no_campaign  query  bool    false  "Only tasks in no campaign"
// @Param        search       query  string  false  "Title search"
// @Param        sort         query  string  false  "deadline (default), risk, updated or created"
// @Param        page         query  int     false  "Page number" default(1)
// @Param        per_page     query  int     false  "Items per page" default(25)
// @Success      200  {object}  pagination.Result[RemediationTaskResponse]
// @Failure      400  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /remediation/tasks [get]
func (h *RemediationTaskHandler) List(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(w, r)
	if !ok {
		return
	}
	page, ok := listPageMax(w, r, 25, 100)
	if !ok {
		return
	}
	q := r.URL.Query()
	in := remediationapp.ListTasksInput{TenantID: tid, CallerID: callerID(r)}
	if s := q.Get("state"); s != "" {
		for _, p := range strings.Split(s, ",") {
			st := remediation.TaskState(strings.TrimSpace(p))
			if !st.IsValid() {
				apierror.BadRequest("unknown state: " + string(st)).WriteJSON(w)
				return
			}
			in.Filter.States = append(in.Filter.States, st)
		}
	}
	if a := q.Get("assignee"); a == "me" {
		in.Mine = true
	} else if a != "" {
		id, err := parseOptID("assignee", a)
		if err != nil {
			h.handleError(w, err)
			return
		}
		in.Filter.AssigneeID = id
	}
	in.Filter.NoCampaign = q.Get("no_campaign") == "true"
	for field, dst := range map[string]**shared.ID{
		"group_id": &in.Filter.GroupID, "action_id": &in.Filter.ActionID,
		"campaign_id": &in.Filter.CampaignID, "finding_id": &in.Filter.FindingID,
	} {
		id, err := parseOptID(field, q.Get(field))
		if err != nil {
			h.handleError(w, err)
			return
		}
		*dst = id
	}
	in.Filter.ActionKind = strings.TrimSpace(q.Get("action_kind"))
	if len(in.Filter.ActionKind) > 16 {
		apierror.BadRequest("unknown action_kind").WriteJSON(w)
		return
	}
	in.Filter.Search = strings.TrimSpace(q.Get("search"))
	if len(in.Filter.Search) > 200 {
		apierror.BadRequest("search is longer than 200 characters").WriteJSON(w)
		return
	}
	if s := q.Get("sort"); s != "" {
		in.Filter.Sort = remediation.TaskSort(s)
		if !in.Filter.Sort.IsValid() {
			apierror.BadRequest("sort must be deadline, risk, updated or created").WriteJSON(w)
			return
		}
	}
	res, err := h.service.ListTasks(r.Context(), in, page)
	if err != nil {
		h.handleError(w, err)
		return
	}
	out := make([]RemediationTaskResponse, 0, len(res.Data))
	for _, t := range res.Data {
		out = append(out, toRemediationTaskResp(t))
	}
	writeJSON(w, http.StatusOK, pagination.NewResult(out, res.Total, page))
}

// CreateRemediationTaskRequest creates a task by hand.
type CreateRemediationTaskRequest struct {
	Title             string   `json:"title"`
	Description       string   `json:"description"`
	ActionID          string   `json:"action_id"`
	FindingIDs        []string `json:"finding_ids"`
	RelatedFindingIDs []string `json:"related_finding_ids"`
	AssigneeUserID    string   `json:"assignee_user_id"`
	AssigneeGroupID   string   `json:"assignee_group_id"`
	CampaignID        string   `json:"campaign_id"`
	Deadline          string   `json:"deadline"`
	// Conflicts resolves findings of another active task.
	Conflicts *RemediationConflictsInput `json:"conflicts,omitempty"`
}

// Create creates a task.
// @Summary      Create a remediation task
// @Description  Creates a task from open findings in the caller's data scope. A finding is the primary member of one active task: findings already in another active task answer 409 with code FINDINGS_IN_OTHER_TASK and details.conflicts (finding, holding task, its title and owner when the caller can read it, can_move), unless the request's conflicts says to skip them or to move named ones (needs write access to the holding task, else 403).
// @Tags         Remediation
// @Accept       json
// @Produce      json
// @Param        request  body  CreateRemediationTaskRequest  true  "Task"
// @Success      201  {object}  RemediationTaskResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /remediation/tasks [post]
func (h *RemediationTaskHandler) Create(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(w, r)
	if !ok {
		return
	}
	var req CreateRemediationTaskRequest
	if err := decodeTaskBody(w, r, &req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	in := remediationapp.CreateTaskInput{TenantID: tid, ActorID: callerID(r), Title: req.Title, Description: req.Description}
	var err error
	if in.FindingIDs, err = parseIDList("finding_ids", req.FindingIDs); err != nil {
		h.handleError(w, err)
		return
	}
	if in.RelatedIDs, err = parseIDList("related_finding_ids", req.RelatedFindingIDs); err != nil {
		h.handleError(w, err)
		return
	}
	if in.Conflicts, err = parseConflicts(req.Conflicts); err != nil {
		h.handleError(w, err)
		return
	}
	for _, p := range []struct {
		field string
		val   string
		dst   **shared.ID
	}{
		{"action_id", req.ActionID, &in.ActionID}, {"assignee_user_id", req.AssigneeUserID, &in.AssigneeUserID},
		{"assignee_group_id", req.AssigneeGroupID, &in.AssigneeGroupID}, {"campaign_id", req.CampaignID, &in.CampaignID},
	} {
		if *p.dst, err = parseOptID(p.field, p.val); err != nil {
			h.handleError(w, err)
			return
		}
	}
	if strings.TrimSpace(req.Deadline) != "" {
		d, derr := parseTaskDeadline(req.Deadline)
		if derr != nil {
			h.handleError(w, derr)
			return
		}
		in.Deadline = d
	}
	t, err := h.service.CreateTask(r.Context(), in, h.auditContext(r))
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, toRemediationTaskResp(t))
}

// parseTaskDeadline reads an RFC 3339 timestamp or a date (the end of that
// day, UTC).
func parseTaskDeadline(s string) (*time.Time, error) {
	s = strings.TrimSpace(s)
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		t = t.UTC()
		return &t, nil
	}
	if d, err := time.Parse(time.DateOnly, s); err == nil {
		d = d.Add(24*time.Hour - time.Second)
		return &d, nil
	}
	return nil, fmt.Errorf("%w: deadline must be an RFC 3339 timestamp or a date (YYYY-MM-DD)", shared.ErrValidation)
}

// Get returns a task.
// @Summary      Get a remediation task
// @Tags         Remediation
// @Produce      json
// @Param        task_id  path  string  true  "Task ID"
// @Success      200  {object}  RemediationTaskResponse
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /remediation/tasks/{task_id} [get]
func (h *RemediationTaskHandler) Get(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(w, r)
	if !ok {
		return
	}
	id, ok := pathTaskID(w, r)
	if !ok {
		return
	}
	t, err := h.service.GetTask(r.Context(), tid, id)
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toRemediationTaskResp(t))
}

// Update changes a task. Body: version (required) and any of title,
// description, assignee_user_id, assignee_group_id, deadline, campaign_id
// (null clears the last four), hold (true/false), cancel (true), note.
// @Summary      Change a remediation task
// @Description  Changes the title, description, owner, deadline (the effective deadline is the earliest of it and the open findings' SLA deadlines, so it only tightens), campaign or manual state. version is required (409 when stale). A restricted member may change only a task whose findings are all in their scope.
// @Tags         Remediation
// @Accept       json
// @Produce      json
// @Param        task_id  path  string                        true  "Task ID"
// @Param        request  body  UpdateRemediationTaskRequest  true  "Changes"
// @Success      200  {object}  RemediationTaskResponse
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /remediation/tasks/{task_id} [patch]
func (h *RemediationTaskHandler) Update(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(w, r)
	if !ok {
		return
	}
	id, ok := pathTaskID(w, r)
	if !ok {
		return
	}
	var raw map[string]json.RawMessage
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&raw); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	in, err := parseTaskUpdate(raw)
	if err != nil {
		h.handleError(w, err)
		return
	}
	in.TenantID, in.TaskID, in.ActorID = tid, id, callerID(r)
	t, err := h.service.UpdateTask(r.Context(), in, h.auditContext(r))
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toRemediationTaskResp(t))
}

// UpdateRemediationTaskRequest documents the PATCH body: every field but
// version is optional; null clears assignee_user_id, assignee_group_id,
// deadline and campaign_id.
type UpdateRemediationTaskRequest struct {
	Version         int     `json:"version"`
	Title           *string `json:"title,omitempty"`
	Description     *string `json:"description,omitempty"`
	AssigneeUserID  *string `json:"assignee_user_id,omitempty"`
	AssigneeGroupID *string `json:"assignee_group_id,omitempty"`
	Deadline        *string `json:"deadline,omitempty"`
	CampaignID      *string `json:"campaign_id,omitempty"`
	Hold            *bool   `json:"hold,omitempty"`
	Cancel          *bool   `json:"cancel,omitempty"`
	Note            *string `json:"note,omitempty"`
}

var taskUpdateFields = map[string]bool{
	"version": true, "title": true, "description": true, "assignee_user_id": true, "assignee_group_id": true,
	"deadline": true, "campaign_id": true, "hold": true, "cancel": true, "note": true,
}

func parseTaskUpdate(raw map[string]json.RawMessage) (remediationapp.UpdateTaskInput, error) {
	var in remediationapp.UpdateTaskInput
	bad := func(field string) error {
		return fmt.Errorf("%w: invalid %s", shared.ErrValidation, field)
	}
	for k := range raw {
		if !taskUpdateFields[k] {
			return in, fmt.Errorf("%w: unknown field %s", shared.ErrValidation, k)
		}
	}
	if v, ok := raw["version"]; ok {
		if err := json.Unmarshal(v, &in.Version); err != nil {
			return in, bad("version")
		}
	}
	str := func(field string) (*string, error) {
		v, ok := raw[field]
		if !ok {
			return nil, nil
		}
		var s string
		if err := json.Unmarshal(v, &s); err != nil {
			return nil, bad(field)
		}
		return &s, nil
	}
	var err error
	if in.Title, err = str("title"); err != nil {
		return in, err
	}
	if in.Description, err = str("description"); err != nil {
		return in, err
	}
	nullableID := func(field string) (**shared.ID, error) {
		v, ok := raw[field]
		if !ok {
			return nil, nil
		}
		var p *shared.ID
		if string(v) != "null" {
			var s string
			if err := json.Unmarshal(v, &s); err != nil {
				return nil, bad(field)
			}
			if p, err = parseOptID(field, s); err != nil {
				return nil, err
			}
		}
		return &p, nil
	}
	if in.AssigneeUserID, err = nullableID("assignee_user_id"); err != nil {
		return in, err
	}
	if in.AssigneeGroupID, err = nullableID("assignee_group_id"); err != nil {
		return in, err
	}
	if in.CampaignID, err = nullableID("campaign_id"); err != nil {
		return in, err
	}
	if v, ok := raw["deadline"]; ok {
		var d *time.Time
		if string(v) != "null" {
			var s string
			if err := json.Unmarshal(v, &s); err != nil {
				return in, bad("deadline")
			}
			if strings.TrimSpace(s) != "" {
				if d, err = parseTaskDeadline(s); err != nil {
					return in, err
				}
			}
		}
		in.Deadline = &d
	}
	if v, ok := raw["hold"]; ok {
		var b bool
		if err := json.Unmarshal(v, &b); err != nil {
			return in, bad("hold")
		}
		in.Hold = &b
	}
	if v, ok := raw["cancel"]; ok {
		if err := json.Unmarshal(v, &in.Cancel); err != nil {
			return in, bad("cancel")
		}
	}
	if note, nerr := str("note"); nerr != nil {
		return in, nerr
	} else if note != nil {
		in.StateNote = *note
	}
	if in.Cancel && in.Hold != nil {
		return in, fmt.Errorf("%w: hold and cancel cannot be combined", shared.ErrValidation)
	}
	return in, nil
}

// AddRemediationTaskMembersRequest adds findings to a task.
type AddRemediationTaskMembersRequest struct {
	Version    int      `json:"version"`
	FindingIDs []string `json:"finding_ids"`
	Role       string   `json:"role"`
	// Conflicts resolves primary findings of another active task.
	Conflicts *RemediationConflictsInput `json:"conflicts,omitempty"`
}

// AddMembers adds findings to a task.
// @Summary      Add findings to a remediation task
// @Description  Adds findings as primary members (default) or related links. Primary findings of another active task answer 409 FINDINGS_IN_OTHER_TASK with details.conflicts unless conflicts says to skip or move them; a move out of a task the caller cannot change answers 403.
// @Tags         Remediation
// @Accept       json
// @Produce      json
// @Param        task_id  path  string                            true  "Task ID"
// @Param        request  body  AddRemediationTaskMembersRequest  true  "Findings"
// @Success      200  {object}  RemediationTaskResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /remediation/tasks/{task_id}/members [post]
func (h *RemediationTaskHandler) AddMembers(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(w, r)
	if !ok {
		return
	}
	id, ok := pathTaskID(w, r)
	if !ok {
		return
	}
	var req AddRemediationTaskMembersRequest
	if err := decodeTaskBody(w, r, &req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	ids, err := parseIDList("finding_ids", req.FindingIDs)
	if err != nil {
		h.handleError(w, err)
		return
	}
	conflicts, err := parseConflicts(req.Conflicts)
	if err != nil {
		h.handleError(w, err)
		return
	}
	t, err := h.service.AddMembers(r.Context(), remediationapp.AddMembersInput{
		TenantID: tid, TaskID: id, ActorID: callerID(r), Version: req.Version, FindingIDs: ids,
		Role: remediation.MemberRole(req.Role), Conflicts: conflicts,
	}, h.auditContext(r))
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toRemediationTaskResp(t))
}

// RemediationTaskMemberResponse is one finding of a task.
type RemediationTaskMemberResponse struct {
	FindingID     string     `json:"finding_id"`
	Role          string     `json:"role"`
	JoinSource    string     `json:"join_source"`
	JoinedAt      time.Time  `json:"joined_at"`
	Title         string     `json:"title"`
	Severity      string     `json:"severity"`
	Status        string     `json:"status"`
	PriorityClass string     `json:"priority_class,omitempty"`
	AssetID       *string    `json:"asset_id,omitempty"`
	AssetName     string     `json:"asset_name,omitempty"`
	SLADeadline   *time.Time `json:"sla_deadline,omitempty"`
	Verified      bool       `json:"verified"`
}

// ListMembers lists a task's findings the caller may see. Query: role
// (primary, related), status (open, closed or a finding status), page,
// per_page.
// @Summary      List a remediation task's findings
// @Tags         Remediation
// @Produce      json
// @Param        task_id   path   string  true   "Task ID"
// @Param        role      query  string  false  "primary or related"
// @Param        status    query  string  false  "open, closed or a finding status"
// @Param        page      query  int     false  "Page number" default(1)
// @Param        per_page  query  int     false  "Items per page" default(50)
// @Success      200  {object}  pagination.Result[RemediationTaskMemberResponse]
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /remediation/tasks/{task_id}/members [get]
func (h *RemediationTaskHandler) ListMembers(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(w, r)
	if !ok {
		return
	}
	id, ok := pathTaskID(w, r)
	if !ok {
		return
	}
	page, ok := listPageMax(w, r, 50, 200)
	if !ok {
		return
	}
	f := remediation.MemberFilter{Role: remediation.MemberRole(r.URL.Query().Get("role"))}
	if f.Role != "" && f.Role != remediation.MemberRolePrimary && f.Role != remediation.MemberRoleRelated {
		apierror.BadRequest("role must be primary or related").WriteJSON(w)
		return
	}
	f.Status = strings.TrimSpace(r.URL.Query().Get("status"))
	if len(f.Status) > 30 {
		apierror.BadRequest("unknown status").WriteJSON(w)
		return
	}
	res, err := h.service.ListMembers(r.Context(), tid, id, f, page)
	if err != nil {
		h.handleError(w, err)
		return
	}
	out := make([]RemediationTaskMemberResponse, 0, len(res.Data))
	for _, m := range res.Data {
		out = append(out, RemediationTaskMemberResponse{
			FindingID: m.FindingID.String(), Role: string(m.Role), JoinSource: string(m.JoinSource), JoinedAt: m.JoinedAt,
			Title: m.Title, Severity: m.Severity, Status: m.Status, PriorityClass: m.PriorityClass,
			AssetID: optIDStr(m.AssetID), AssetName: m.AssetName, SLADeadline: m.SLADeadline, Verified: m.Verified,
		})
	}
	writeJSON(w, http.StatusOK, pagination.NewResult(out, res.Total, page))
}

// RemediationTaskEventResponse is one timeline entry.
type RemediationTaskEventResponse struct {
	ID        string         `json:"id"`
	Kind      string         `json:"kind"`
	ActorID   *string        `json:"actor_id,omitempty"`
	ActorType string         `json:"actor_type"`
	Data      map[string]any `json:"data"`
	CreatedAt time.Time      `json:"created_at"`
}

// Timeline lists a task's timeline, newest first.
// @Summary      List a remediation task's timeline
// @Tags         Remediation
// @Produce      json
// @Param        task_id   path   string  true   "Task ID"
// @Param        page      query  int     false  "Page number" default(1)
// @Param        per_page  query  int     false  "Items per page" default(50)
// @Success      200  {object}  pagination.Result[RemediationTaskEventResponse]
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /remediation/tasks/{task_id}/timeline [get]
func (h *RemediationTaskHandler) Timeline(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(w, r)
	if !ok {
		return
	}
	id, ok := pathTaskID(w, r)
	if !ok {
		return
	}
	page, ok := listPageMax(w, r, 50, 200)
	if !ok {
		return
	}
	res, err := h.service.ListEvents(r.Context(), tid, id, page)
	if err != nil {
		h.handleError(w, err)
		return
	}
	out := make([]RemediationTaskEventResponse, 0, len(res.Data))
	for _, e := range res.Data {
		out = append(out, RemediationTaskEventResponse{ID: e.ID.String(), Kind: e.Kind, ActorID: optIDStr(e.ActorID),
			ActorType: e.ActorType, Data: e.Data, CreatedAt: e.CreatedAt})
	}
	writeJSON(w, http.StatusOK, pagination.NewResult(out, res.Total, page))
}

func (h *RemediationTaskHandler) auditContext(r *http.Request) audit.AuditContext {
	return audit.AuditContext{
		TenantID:   middleware.GetTenantID(r.Context()),
		ActorID:    middleware.GetUserID(r.Context()),
		ActorEmail: auditActorEmail(r.Context()),
		ActorIP:    getClientIP(r),
		UserAgent:  r.UserAgent(),
		RequestID:  r.Header.Get("X-Request-ID"),
	}
}

func (h *RemediationTaskHandler) handleError(w http.ResponseWriter, err error) {
	var mc *remediation.MoveNeedsConfirmationError
	if errors.As(err, &mc) {
		ws := warningStrings(mc.Warnings)
		writeJSON(w, http.StatusConflict, map[string]any{
			"code": "MOVE_NEEDS_CONFIRMATION", "message": mc.Error(), "warnings": ws,
			"details": map[string]any{"warnings": ws},
		})
		return
	}
	if e, ok := remediation.AsFindingsInOtherTask(err); ok {
		writeJSON(w, http.StatusConflict, map[string]any{
			"code": "FINDINGS_IN_OTHER_TASK", "message": e.Error(),
			"details": map[string]any{"conflicts": toConflictResps(e.Conflicts)},
		})
		return
	}
	switch {
	case errors.Is(err, finding.ErrBulkTooLarge):
		// Above the bulk ceiling: the caller confirms and sends the request
		// again with "approved": true (the web console asks first).
		writeJSON(w, http.StatusBadRequest, map[string]any{"code": "BULK_TOO_LARGE", "message": err.Error()})
	case errors.Is(err, finding.ErrBulkBudgetExceeded):
		writeJSON(w, http.StatusBadRequest, map[string]any{"code": "BULK_BUDGET_EXCEEDED", "message": err.Error()})
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound(notFoundMessage(err)).WriteJSON(w)
	case errors.Is(err, shared.ErrConflict):
		apierror.Conflict(err.Error()).WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	case errors.Is(err, shared.ErrForbidden):
		apierror.Forbidden(err.Error()).WriteJSON(w)
	default:
		h.logger.Error("remediation task error", "error", logger.SanitizeError(err))
		apierror.InternalServerError("internal error").WriteJSON(w)
	}
}

func notFoundMessage(err error) string {
	if errors.Is(err, remediationapp.ErrTaskFindingNotFound) {
		return "one or more findings were not found"
	}
	return "remediation task not found"
}

// decodeTaskBody reads a JSON body of at most 256 KiB with no unknown fields.
func decodeTaskBody(w http.ResponseWriter, r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}
