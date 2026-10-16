package handler

// Moves, splits and merges of remediation tasks
// (docs/rfcs/RFC-098-remediation-tasks.md §7).

import (
	"net/http"

	"github.com/openctemio/openctem/api/internal/app/finding"
	remediationapp "github.com/openctemio/openctem/api/internal/app/remediation"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// MoveRemediationFindingsRequest moves findings between tasks.
type MoveRemediationFindingsRequest struct {
	FromTaskID  string   `json:"from_task_id"`
	FromVersion int      `json:"from_version"`
	ToTaskID    string   `json:"to_task_id,omitempty"`
	ToVersion   int      `json:"to_version,omitempty"`
	FindingIDs  []string `json:"finding_ids"`
	Confirm     bool     `json:"confirm,omitempty"`
}

// RemediationMovePreviewResponse is what a move would do.
type RemediationMovePreviewResponse struct {
	Warnings []string `json:"warnings"`
	Moving   int      `json:"moving"`
}

// RemediationMoveResponse is what a move did.
type RemediationMoveResponse struct {
	Moved          []string                 `json:"moved"`
	Skipped        []string                 `json:"skipped"`
	SourceArchived bool                     `json:"source_archived"`
	Warnings       []string                 `json:"warnings"`
	Source         *RemediationTaskResponse `json:"source,omitempty"`
	Target         *RemediationTaskResponse `json:"target,omitempty"`
}

func (h *RemediationTaskHandler) moveInput(w http.ResponseWriter, r *http.Request) (remediationapp.MoveInput, bool) {
	tid, ok := h.tenant(w, r)
	if !ok {
		return remediationapp.MoveInput{}, false
	}
	var req MoveRemediationFindingsRequest
	if err := decodeTaskBody(w, r, &req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return remediationapp.MoveInput{}, false
	}
	in := remediationapp.MoveInput{TenantID: tid, FromVersion: req.FromVersion, ToVersion: req.ToVersion,
		Confirm: req.Confirm, ActorID: callerID(r)}
	from, err := shared.IDFromString(req.FromTaskID)
	if err != nil {
		apierror.BadRequest("from_task_id must be an id").WriteJSON(w)
		return remediationapp.MoveInput{}, false
	}
	in.FromTaskID = from
	if in.ToTaskID, err = parseOptID("to_task_id", req.ToTaskID); err != nil {
		h.handleError(w, err)
		return remediationapp.MoveInput{}, false
	}
	if in.FindingIDs, err = parseIDList("finding_ids", req.FindingIDs); err != nil {
		h.handleError(w, err)
		return remediationapp.MoveInput{}, false
	}
	return in, true
}

func warningStrings(ws []remediation.MoveWarning) []string {
	out := make([]string, len(ws))
	for i, w := range ws {
		out[i] = string(w)
	}
	return out
}

func idStrs(ids []shared.ID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.String()
	}
	return out
}

// PreviewMove tells what a move would do (its warnings) without doing it.
// @Summary      Preview moving findings between remediation tasks
// @Description  Warnings the person must confirm: different_fix, different_owner, target_verifying, source_verifying, empties_source. Refusals (another organization, a closed task, findings outside the caller's scope) are errors.
// @Tags         Remediation
// @Accept       json
// @Produce      json
// @Param        request  body  MoveRemediationFindingsRequest  true  "Move"
// @Success      200  {object}  RemediationMovePreviewResponse
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /remediation/moves/preview [post]
func (h *RemediationTaskHandler) PreviewMove(w http.ResponseWriter, r *http.Request) {
	in, ok := h.moveInput(w, r)
	if !ok {
		return
	}
	p, err := h.service.PreviewMove(r.Context(), in)
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, RemediationMovePreviewResponse{Warnings: warningStrings(p.Warnings), Moving: p.Moving})
}

// Move moves findings from one task to another, or out of any task (no
// to_task_id: back to the suggestions pool, not proposed for this fix again).
// @Summary      Move findings between remediation tasks
// @Description  Both tasks are checked at the versions given (409 when stale). A move with warnings needs confirm=true, else 409 with code MOVE_NEEDS_CONFIRMATION and the warnings. A source emptied by the move is archived with a note. Undo is the reverse move with the versions this response returns.
// @Tags         Remediation
// @Accept       json
// @Produce      json
// @Param        request  body  MoveRemediationFindingsRequest  true  "Move"
// @Success      200  {object}  RemediationMoveResponse
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /remediation/moves [post]
func (h *RemediationTaskHandler) Move(w http.ResponseWriter, r *http.Request) {
	in, ok := h.moveInput(w, r)
	if !ok {
		return
	}
	out, err := h.service.Move(r.Context(), in, h.auditContext(r))
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toMoveResp(out))
}

func toMoveResp(out *remediationapp.MoveOutcome) RemediationMoveResponse {
	resp := RemediationMoveResponse{Moved: idStrs(out.Moved), Skipped: idStrs(out.Skipped), SourceArchived: out.SourceArchived,
		Warnings: warningStrings(out.Warnings)}
	if out.Source != nil {
		s := toRemediationTaskResp(out.Source)
		resp.Source = &s
	}
	if out.Target != nil {
		t := toRemediationTaskResp(out.Target)
		resp.Target = &t
	}
	return resp
}

// SplitRemediationTaskRequest splits findings off a task.
type SplitRemediationTaskRequest struct {
	Version         int      `json:"version"`
	FindingIDs      []string `json:"finding_ids"`
	Title           string   `json:"title,omitempty"`
	AssigneeUserID  string   `json:"assignee_user_id,omitempty"`
	AssigneeGroupID string   `json:"assignee_group_id,omitempty"`
}

// Split creates a task of the same fix from some of a task's findings.
// @Summary      Split findings off a remediation task
// @Description  Creates a task of the same fix (campaign and deadline kept; the owner kept unless another is named) and moves the findings there. At least one finding stays.
// @Tags         Remediation
// @Accept       json
// @Produce      json
// @Param        task_id  path  string                       true  "Task ID"
// @Param        request  body  SplitRemediationTaskRequest  true  "Split"
// @Success      201  {object}  RemediationMoveResponse
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /remediation/tasks/{task_id}/splits [post]
func (h *RemediationTaskHandler) Split(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(w, r)
	if !ok {
		return
	}
	id, ok := pathTaskID(w, r)
	if !ok {
		return
	}
	var req SplitRemediationTaskRequest
	if err := decodeTaskBody(w, r, &req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	in := remediationapp.SplitInput{TenantID: tid, TaskID: id, Version: req.Version, Title: req.Title, ActorID: callerID(r)}
	var err error
	if in.FindingIDs, err = parseIDList("finding_ids", req.FindingIDs); err != nil {
		h.handleError(w, err)
		return
	}
	if in.AssigneeUserID, err = parseOptID("assignee_user_id", req.AssigneeUserID); err != nil {
		h.handleError(w, err)
		return
	}
	if in.AssigneeGroupID, err = parseOptID("assignee_group_id", req.AssigneeGroupID); err != nil {
		h.handleError(w, err)
		return
	}
	out, err := h.service.Split(r.Context(), in, h.auditContext(r))
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, toMoveResp(out))
}

// MergeRemediationTasksRequest merges tasks into the path task.
type MergeRemediationTasksRequest struct {
	Version int                         `json:"version"`
	Sources []RemediationTaskVersionRef `json:"sources"`
}

// RemediationTaskVersionRef names a task and the version the caller read.
type RemediationTaskVersionRef struct {
	TaskID  string `json:"task_id"`
	Version int    `json:"version"`
}

// Merge merges tasks of the same fix into this task.
// @Summary      Merge remediation tasks of the same fix
// @Description  Moves every finding of the source tasks (same fix only, at most 20) into this task; the sources are archived with a note.
// @Tags         Remediation
// @Accept       json
// @Produce      json
// @Param        task_id  path  string                        true  "Target task ID"
// @Param        request  body  MergeRemediationTasksRequest  true  "Sources"
// @Success      200  {object}  RemediationTaskResponse
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /remediation/tasks/{task_id}/merges [post]
func (h *RemediationTaskHandler) Merge(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(w, r)
	if !ok {
		return
	}
	id, ok := pathTaskID(w, r)
	if !ok {
		return
	}
	var req MergeRemediationTasksRequest
	if err := decodeTaskBody(w, r, &req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	in := remediationapp.MergeInput{TenantID: tid, TargetID: id, TargetVersion: req.Version, Sources: map[shared.ID]int{}, ActorID: callerID(r)}
	for _, s := range req.Sources {
		sid, err := shared.IDFromString(s.TaskID)
		if err != nil {
			apierror.BadRequest("sources must hold task ids").WriteJSON(w)
			return
		}
		in.Sources[sid] = s.Version
	}
	t, err := h.service.Merge(r.Context(), in, h.auditContext(r))
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toRemediationTaskResp(t))
}

// ResolveRemediationTaskRequest marks a task fixed.
type ResolveRemediationTaskRequest struct {
	Version  int    `json:"version"`
	Note     string `json:"note"`
	Approved bool   `json:"approved,omitempty"`
}

// RemediationMarkFixedResponse is the outcome per finding and the task.
type RemediationMarkFixedResponse struct {
	Updated           int                     `json:"updated"`
	Skipped           int                     `json:"skipped"`
	Failed            int                     `json:"failed"`
	ValidationsQueued int                     `json:"validations_queued"`
	Rows              []finding.BulkRowResult `json:"rows"`
	Task              RemediationTaskResponse `json:"task"`
}

// Resolve marks a task fixed: every open finding is claimed fixed and
// re-checked on its own.
// @Summary      Mark a remediation task fixed
// @Description  A fix claim on every open finding of the task: each goes to fix_applied through the legal steps (a note is required; findings:fix_apply; a person's own findings only) and a proof-of-fix re-check is queued per finding. Nothing closes here: a finding closes on its own evidence; the task is done when every finding is closed and at least one was verified fixed. Rows name each finding not updated and why. The caller must see every finding of the task.
// @Tags         Remediation
// @Accept       json
// @Produce      json
// @Param        task_id  path  string                         true  "Task ID"
// @Param        request  body  ResolveRemediationTaskRequest  true  "Version and note"
// @Success      200  {object}  RemediationMarkFixedResponse
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /remediation/tasks/{task_id}/resolve [post]
func (h *RemediationTaskHandler) Resolve(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(w, r)
	if !ok {
		return
	}
	id, ok := pathTaskID(w, r)
	if !ok {
		return
	}
	var req ResolveRemediationTaskRequest
	if err := decodeTaskBody(w, r, &req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	res, err := h.service.MarkFixed(r.Context(), remediationapp.MarkFixedInput{
		TenantID: tid, TaskID: id, Version: req.Version, Note: req.Note, ActorID: callerID(r), Approved: req.Approved,
		HasFixApplyPermission: middleware.HasPermission(r.Context(), string(permission.FindingsFixApply)),
	}, h.auditContext(r))
	if err != nil {
		h.handleError(w, err)
		return
	}
	rows := res.Rows
	if rows == nil {
		rows = []finding.BulkRowResult{}
	}
	writeJSON(w, http.StatusOK, RemediationMarkFixedResponse{Updated: res.Updated, Skipped: res.Skipped, Failed: res.Failed,
		ValidationsQueued: res.ValidationsQueued, Rows: rows, Task: toRemediationTaskResp(res.Task)})
}
