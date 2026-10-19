package handler

// Remediation tasks created from a custom query
// (docs/rfcs/RFC-098-remediation-tasks.md, "Tasks from a query"). The query
// runs as the caller: the principal, tenant and data scope come from the
// authenticated request (queryCaller), never from the body.

import (
	"errors"
	"net/http"
	"strings"
	"time"

	queryapp "github.com/openctemio/openctem/api/internal/app/query"
	remediationapp "github.com/openctemio/openctem/api/internal/app/remediation"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/querylang"
)

// QueryTaskPreviewRequest is the query to preview.
type QueryTaskPreviewRequest struct {
	Query string `json:"query"`
}

// QueryBreakdownResp is one row of a preview breakdown.
type QueryBreakdownResp struct {
	Key     string  `json:"key"`
	Name    string  `json:"name"`
	Count   int     `json:"count"`
	UserID  *string `json:"user_id,omitempty"`
	GroupID *string `json:"group_id,omitempty"`
}

// QuerySampleResp is one sample finding.
type QuerySampleResp struct {
	FindingID   string     `json:"finding_id"`
	Title       string     `json:"title"`
	Severity    string     `json:"severity"`
	Status      string     `json:"status"`
	AssetID     *string    `json:"asset_id,omitempty"`
	AssetName   string     `json:"asset_name"`
	SLADeadline *time.Time `json:"sla_deadline,omitempty"`
}

// QueryStatsResp are a preview's breakdowns.
type QueryStatsResp struct {
	Severity         []QueryBreakdownResp `json:"severity"`
	Assets           []QueryBreakdownResp `json:"assets"`
	Owners           []QueryBreakdownResp `json:"owners"`
	Sample           []QuerySampleResp    `json:"sample"`
	EarliestDeadline *time.Time           `json:"earliest_deadline,omitempty"`
}

// QueryOwnerResp is a suggested owner.
type QueryOwnerResp struct {
	UserID  *string `json:"user_id,omitempty"`
	GroupID *string `json:"group_id,omitempty"`
}

// QueryTaskPreviewResponse is what a task created from the query would hold.
type QueryTaskPreviewResponse struct {
	Query             string                               `json:"query"`
	QueryVersion      int                                  `json:"query_version"`
	Description       string                               `json:"description"`
	ScopeKind         string                               `json:"scope_kind"`
	ScopeRules        []string                             `json:"scope_rules"`
	Total             int                                  `json:"total"`
	TooMany           bool                                 `json:"too_many"`
	Max               int                                  `json:"max"`
	Claimable         int                                  `json:"claimable"`
	Stats             *QueryStatsResp                      `json:"stats,omitempty"`
	Conflicts         []RemediationFindingConflictResponse `json:"conflicts"`
	SuggestedAssignee *QueryOwnerResp                      `json:"suggested_assignee,omitempty"`
}

// TaskQueryResponse is the query a task was created from.
type TaskQueryResponse struct {
	TaskID         string     `json:"task_id"`
	Query          string     `json:"query"`
	QueryVersion   int        `json:"query_version"`
	Mode           string     `json:"mode"`
	AutoState      *string    `json:"auto_state"`
	AutoReason     *string    `json:"auto_reason"`
	Cap            int        `json:"cap"`
	OwnerUserID    *string    `json:"owner_user_id"`
	LastRunAt      *time.Time `json:"last_run_at"`
	LastAddedCount int        `json:"last_added_count"`
	TotalAdded     int        `json:"total_added"`
	CreatedAt      time.Time  `json:"created_at"`
}

// CreateQueryTaskRequest creates a task from a query.
type CreateQueryTaskRequest struct {
	Title           string                     `json:"title"`
	Description     string                     `json:"description"`
	Query           string                     `json:"query"`
	Mode            string                     `json:"mode"`
	Cap             int                        `json:"cap"`
	AssigneeUserID  string                     `json:"assignee_user_id"`
	AssigneeGroupID string                     `json:"assignee_group_id"`
	CampaignID      string                     `json:"campaign_id"`
	Deadline        string                     `json:"deadline"`
	Conflicts       *RemediationConflictsInput `json:"conflicts"`
}

// CreateQueryTaskResponse is the created task and what happened to the
// matches.
type CreateQueryTaskResponse struct {
	Task    RemediationTaskResponse `json:"task"`
	Query   TaskQueryResponse       `json:"query"`
	Matched int                     `json:"matched"`
	Added   int                     `json:"added"`
	Moved   int                     `json:"moved"`
	Skipped int                     `json:"skipped"`
}

// QueryRerunPreviewResponse is what a re-run would add.
type QueryRerunPreviewResponse struct {
	Query     string          `json:"query"`
	New       int             `json:"new"`
	Truncated bool            `json:"truncated"`
	Room      int             `json:"room"`
	Stats     *QueryStatsResp `json:"stats,omitempty"`
}

// QueryRerunResponse is what a confirmed re-run added.
type QueryRerunResponse struct {
	Task    RemediationTaskResponse `json:"task"`
	Added   int                     `json:"added"`
	Skipped int                     `json:"skipped"`
	Capped  int                     `json:"capped"`
}

// QueryAutoStateRequest pauses (true) or resumes (false) auto mode.
type QueryAutoStateRequest struct {
	Paused bool `json:"paused"`
}

func toStatsResp(st *remediation.QueryPreviewStats) *QueryStatsResp {
	if st == nil {
		return nil
	}
	conv := func(in []remediation.QueryBreakdown) []QueryBreakdownResp {
		out := make([]QueryBreakdownResp, 0, len(in))
		for _, b := range in {
			out = append(out, QueryBreakdownResp{Key: b.Key, Name: b.Name, Count: b.Count, UserID: optIDStr(b.UserID), GroupID: optIDStr(b.GroupID)})
		}
		return out
	}
	r := &QueryStatsResp{Severity: conv(st.Severity), Assets: conv(st.Assets), Owners: conv(st.Owners),
		Sample: make([]QuerySampleResp, 0, len(st.Sample)), EarliestDeadline: st.EarliestDeadline}
	for _, s := range st.Sample {
		r.Sample = append(r.Sample, QuerySampleResp{FindingID: s.FindingID.String(), Title: s.Title, Severity: s.Severity,
			Status: s.Status, AssetID: optIDStr(s.AssetID), AssetName: s.AssetName, SLADeadline: s.SLADeadline})
	}
	return r
}

func toTaskQueryResp(q *remediation.TaskQuery) TaskQueryResponse {
	r := TaskQueryResponse{TaskID: q.TaskID.String(), Query: q.Text, QueryVersion: q.Version, Mode: string(q.Mode), Cap: q.Cap,
		OwnerUserID: optIDStr(q.OwnerUserID), LastRunAt: q.LastRunAt, LastAddedCount: q.LastAddedCount,
		TotalAdded: q.TotalAdded, CreatedAt: q.CreatedAt}
	if q.AutoState != nil {
		s := string(*q.AutoState)
		r.AutoState = &s
	}
	if q.AutoReason != nil {
		s := string(*q.AutoReason)
		r.AutoReason = &s
	}
	return r
}

// handleQueryError maps query-language and query-task errors, then the
// task errors.
func (h *RemediationTaskHandler) handleQueryError(w http.ResponseWriter, err error) {
	if qe, ok := querylang.AsError(err); ok {
		qe.APIError().WriteJSON(w)
		return
	}
	var de *shared.DomainError
	if errors.As(err, &de) && errors.Is(err, shared.ErrValidation) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"code": de.Code, "message": de.Message})
		return
	}
	switch {
	case errors.Is(err, querylang.ErrTimeout):
		apierror.New(http.StatusUnprocessableEntity, apierror.CodeInvalidQuery,
			"The query took longer than allowed; narrow the filter").WriteJSON(w)
		return
	case errors.Is(err, queryapp.ErrBusy):
		apierror.TooManyRequests("too many queries running; try again in a moment").WriteJSON(w)
		return
	}
	h.handleError(w, err)
}

// PreviewQueryTask previews a task from a query.
// @Summary      Preview a remediation task from a query
// @Description  Runs a "findings where ..." query as the caller (their data scope, the pentest member rule and the mandatory exclusions; closed and pentest findings are left out) and returns the number of matches, breakdowns by severity, asset and owner, a sample, the matches other active tasks hold (task details only when the caller may read that task), the earliest SLA deadline and a suggested assignee. Read-only. More than 1000 matches answers too_many.
// @Tags         Remediation
// @Accept       json
// @Produce      json
// @Param        request  body  QueryTaskPreviewRequest  true  "Query"
// @Success      200  {object}  QueryTaskPreviewResponse
// @Failure      400  {object}  apierror.Error
// @Failure      429  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /remediation/tasks/query/preview [post]
func (h *RemediationTaskHandler) PreviewQueryTask(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(w, r)
	if !ok {
		return
	}
	var req QueryTaskPreviewRequest
	if err := decodeTaskBody(w, r, &req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	p, err := h.service.PreviewQueryTask(r.Context(), tid, queryCaller(r), req.Query)
	if err != nil {
		h.handleQueryError(w, err)
		return
	}
	resp := QueryTaskPreviewResponse{Query: p.Query, QueryVersion: p.Version, Description: p.Description,
		ScopeKind: p.Scope.Kind, ScopeRules: p.Scope.Rules, Total: p.Total, TooMany: p.TooMany, Max: p.Max,
		Claimable: p.Claimable, Stats: toStatsResp(p.Stats), Conflicts: toConflictResps(p.Conflicts)}
	if resp.ScopeRules == nil {
		resp.ScopeRules = []string{}
	}
	if p.SuggestedAssignee != nil {
		resp.SuggestedAssignee = &QueryOwnerResp{UserID: optIDStr(p.SuggestedAssignee.UserID), GroupID: optIDStr(p.SuggestedAssignee.GroupID)}
	}
	writeJSON(w, http.StatusOK, resp)
}

// CreateQueryTask creates a task from a query.
// @Summary      Create a remediation task from a query
// @Description  Runs the query as the caller and creates a task holding its matches (at most 1000; more answers 400 QUERY_TOO_MANY_MATCHES). mode snapshot (default) keeps the matches at creation; auto adds new matches later as the creator, with their current access, and suspends when the creator leaves or loses access. Matches other active tasks hold answer 409 FINDINGS_IN_OTHER_TASK with details.conflicts unless "conflicts" says to skip them or which to move.
// @Tags         Remediation
// @Accept       json
// @Produce      json
// @Param        request  body  CreateQueryTaskRequest  true  "Task from a query"
// @Success      201  {object}  CreateQueryTaskResponse
// @Failure      400  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Failure      429  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /remediation/tasks/query [post]
func (h *RemediationTaskHandler) CreateQueryTask(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(w, r)
	if !ok {
		return
	}
	var req CreateQueryTaskRequest
	if err := decodeTaskBody(w, r, &req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	in := remediationapp.CreateQueryTaskInput{TenantID: tid, Caller: queryCaller(r), ActorID: callerID(r),
		Title: req.Title, Description: req.Description, Query: req.Query, Mode: remediation.QueryMode(req.Mode), Cap: req.Cap}
	var err error
	for _, p := range []struct {
		field string
		val   string
		dst   **shared.ID
	}{
		{"assignee_user_id", req.AssigneeUserID, &in.AssigneeUserID},
		{"assignee_group_id", req.AssigneeGroupID, &in.AssigneeGroupID}, {"campaign_id", req.CampaignID, &in.CampaignID},
	} {
		if *p.dst, err = parseOptID(p.field, p.val); err != nil {
			h.handleError(w, err)
			return
		}
	}
	if strings.TrimSpace(req.Deadline) != "" {
		if in.Deadline, err = parseTaskDeadline(req.Deadline); err != nil {
			h.handleError(w, err)
			return
		}
	}
	if in.Conflicts, err = parseConflicts(req.Conflicts); err != nil {
		h.handleError(w, err)
		return
	}
	out, err := h.service.CreateQueryTask(r.Context(), in, h.auditContext(r))
	if err != nil {
		h.handleQueryError(w, err)
		return
	}
	q := toTaskQueryResp(out.Query)
	q.CreatedAt = out.Task.CreatedAt
	writeJSON(w, http.StatusCreated, CreateQueryTaskResponse{Task: toRemediationTaskResp(out.Task), Query: q,
		Matched: out.Matched, Added: out.Added, Moved: out.Moved, Skipped: out.Skipped})
}

// GetTaskQuery returns the query a task was created from.
// @Summary      Get the query of a remediation task
// @Tags         Remediation
// @Produce      json
// @Param        task_id  path  string  true  "Task ID"
// @Success      200  {object}  TaskQueryResponse
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /remediation/tasks/{task_id}/query [get]
func (h *RemediationTaskHandler) GetTaskQuery(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(w, r)
	if !ok {
		return
	}
	taskID, ok := pathTaskID(w, r)
	if !ok {
		return
	}
	q, err := h.service.GetTaskQuery(r.Context(), tid, taskID)
	if err != nil {
		h.handleQueryError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toTaskQueryResp(q))
}

// PreviewQueryRerun shows what re-running a task's query would add.
// @Summary      Preview re-running the query of a remediation task
// @Description  Runs the task's stored query as the caller and returns the new matches no active task holds, with breakdowns. Read-only.
// @Tags         Remediation
// @Produce      json
// @Param        task_id  path  string  true  "Task ID"
// @Success      200  {object}  QueryRerunPreviewResponse
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /remediation/tasks/{task_id}/query/rerun/preview [post]
func (h *RemediationTaskHandler) PreviewQueryRerun(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(w, r)
	if !ok {
		return
	}
	taskID, ok := pathTaskID(w, r)
	if !ok {
		return
	}
	p, err := h.service.PreviewQueryRerun(r.Context(), tid, taskID, queryCaller(r))
	if err != nil {
		h.handleQueryError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, QueryRerunPreviewResponse{Query: p.Query, New: p.New, Truncated: p.Truncated, Room: p.Room, Stats: toStatsResp(p.Stats)})
}

// RerunQuery adds a re-run's new matches.
// @Summary      Re-run the query of a remediation task
// @Description  Runs the task's stored query as the caller and adds the new matches no active task holds, up to the task's cap. Findings other tasks hold are skipped, never taken.
// @Tags         Remediation
// @Produce      json
// @Param        task_id  path  string  true  "Task ID"
// @Success      200  {object}  QueryRerunResponse
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /remediation/tasks/{task_id}/query/rerun [post]
func (h *RemediationTaskHandler) RerunQuery(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(w, r)
	if !ok {
		return
	}
	taskID, ok := pathTaskID(w, r)
	if !ok {
		return
	}
	res, t, err := h.service.RerunQuery(r.Context(), remediationapp.RerunQueryInput{TenantID: tid, TaskID: taskID,
		Caller: queryCaller(r), ActorID: callerID(r)}, h.auditContext(r))
	if err != nil {
		h.handleQueryError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, QueryRerunResponse{Task: toRemediationTaskResp(t), Added: len(res.Added),
		Skipped: len(res.Skipped), Capped: len(res.Capped)})
}

// SetQueryAutoState pauses or resumes auto mode.
// @Summary      Pause or resume auto include of a remediation task
// @Description  A suspended task resumes only when its owner is again an active member with findings read and remediation write.
// @Tags         Remediation
// @Accept       json
// @Produce      json
// @Param        task_id  path  string                 true  "Task ID"
// @Param        request  body  QueryAutoStateRequest  true  "State"
// @Success      200  {object}  TaskQueryResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /remediation/tasks/{task_id}/query/auto [post]
func (h *RemediationTaskHandler) SetQueryAutoState(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(w, r)
	if !ok {
		return
	}
	taskID, ok := pathTaskID(w, r)
	if !ok {
		return
	}
	var req QueryAutoStateRequest
	if err := decodeTaskBody(w, r, &req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	q, err := h.service.SetQueryAutoState(r.Context(), remediationapp.SetQueryAutoStateInput{TenantID: tid, TaskID: taskID,
		ActorID: callerID(r), Paused: req.Paused}, h.auditContext(r))
	if err != nil {
		h.handleQueryError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toTaskQueryResp(q))
}
