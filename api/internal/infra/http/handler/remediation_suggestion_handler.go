package handler

// Remediation suggestion endpoints (docs/rfcs/RFC-098-remediation-tasks.md §5).

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	remediationapp "github.com/openctemio/openctem/api/internal/app/remediation"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// RemediationSuggestionHandler serves remediation suggestions.
type RemediationSuggestionHandler struct {
	service *remediationapp.SuggestionService
	tasks   *RemediationTaskHandler // shared helpers (tenant, audit context)
	logger  *logger.Logger
}

// NewRemediationSuggestionHandler creates the handler.
func NewRemediationSuggestionHandler(svc *remediationapp.SuggestionService, log *logger.Logger) *RemediationSuggestionHandler {
	return &RemediationSuggestionHandler{service: svc, tasks: &RemediationTaskHandler{logger: log}, logger: log}
}

// RemediationSuggestionPartitionResp is the findings of a suggestion that go
// to one owner.
type RemediationSuggestionPartitionResp struct {
	OwnerUserID  string   `json:"owner_user_id,omitempty"`
	OwnerGroupID string   `json:"owner_group_id,omitempty"`
	OwnerRule    string   `json:"owner_rule"`
	FindingIDs   []string `json:"finding_ids"`
	RiskPoints   int      `json:"risk_points"`
}

// RemediationSuggestionResponse is a suggestion with its explanation.
type RemediationSuggestionResponse struct {
	ID               string                               `json:"id"`
	Kind             string                               `json:"kind"`
	Algorithm        string                               `json:"algorithm"`
	AlgorithmVersion int                                  `json:"algorithm_version"`
	ActionKey        string                               `json:"action_key"`
	KeyKind          string                               `json:"key_kind"`
	Title            string                               `json:"title"`
	TargetActionID   *string                              `json:"target_action_id,omitempty"`
	TargetTaskID     *string                              `json:"target_task_id,omitempty"`
	Partitions       []RemediationSuggestionPartitionResp `json:"partitions"`
	MemberCount      int                                  `json:"member_count"`
	HiddenMembers    int                                  `json:"hidden_members"`
	Truncated        int                                  `json:"truncated"`
	RiskPoints       int                                  `json:"risk_points"`
	RiskParts        remediation.RiskParts                `json:"risk_parts"`
	HasUrgent        bool                                 `json:"has_urgent"`
	EarliestDeadline *time.Time                           `json:"earliest_deadline,omitempty"`
	Confidence       float64                              `json:"confidence"`
	FixSpec          map[string]any                       `json:"fix_spec"`
	State            string                               `json:"state"`
	DismissReason    string                               `json:"dismiss_reason,omitempty"`
	StateNote        string                               `json:"state_note,omitempty"`
	DecidedBy        *string                              `json:"decided_by,omitempty"`
	DecidedAt        *time.Time                           `json:"decided_at,omitempty"`
	SnoozedUntil     *time.Time                           `json:"snoozed_until,omitempty"`
	Version          int                                  `json:"version"`
	CreatedAt        time.Time                            `json:"created_at"`
	UpdatedAt        time.Time                            `json:"updated_at"`
}

func toSuggestionResp(s *remediation.Suggestion) RemediationSuggestionResponse {
	r := RemediationSuggestionResponse{
		ID: s.ID.String(), Kind: string(s.Kind), Algorithm: s.Algorithm, AlgorithmVersion: s.AlgorithmVersion,
		ActionKey: s.Key, KeyKind: s.KeyKind, Title: s.Title, TargetActionID: optIDStr(s.TargetActionID),
		TargetTaskID: optIDStr(s.TargetTaskID), Partitions: []RemediationSuggestionPartitionResp{},
		MemberCount: s.MemberCount, HiddenMembers: s.HiddenMembers, Truncated: s.Truncated, RiskPoints: s.RiskPoints,
		RiskParts: s.RiskParts, HasUrgent: s.HasUrgent, EarliestDeadline: s.EarliestDeadline, Confidence: s.Confidence,
		FixSpec: s.FixSpec, State: string(s.State), DismissReason: string(s.DismissReason), StateNote: s.StateNote,
		DecidedBy: optIDStr(s.DecidedBy), DecidedAt: s.DecidedAt, SnoozedUntil: s.SnoozedUntil, Version: s.Version,
		CreatedAt: s.CreatedAt, UpdatedAt: s.UpdatedAt,
	}
	for _, p := range s.Partitions {
		ids := make([]string, len(p.FindingIDs))
		for i, id := range p.FindingIDs {
			ids[i] = id.String()
		}
		r.Partitions = append(r.Partitions, RemediationSuggestionPartitionResp{OwnerUserID: p.OwnerUser,
			OwnerGroupID: p.OwnerGroup, OwnerRule: p.OwnerRule, FindingIDs: ids, RiskPoints: p.RiskPoints})
	}
	if r.FixSpec == nil {
		r.FixSpec = map[string]any{}
	}
	return r
}

func pathSuggestionID(w http.ResponseWriter, r *http.Request) (shared.ID, bool) {
	id, err := shared.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		apierror.NotFound("suggestion not found").WriteJSON(w)
		return shared.ID{}, false
	}
	return id, true
}

// List lists suggestions, best first.
// @Summary      List remediation suggestions
// @Description  Proposed remediation groups and tasks, ranked by risk reduced. Nothing changes until a person accepts one. A restricted member sees a suggestion through its findings in their scope only (hidden_members counts the rest; their ids are not returned).
// @Tags         Remediation
// @Produce      json
// @Param        state     query  string  false  "Comma list: proposed (default), snoozed, dismissed, accepted, expired, superseded"
// @Param        kind      query  string  false  "Comma list: new_group, join, task_route"
// @Param        key_kind  query  string  false  "upgrade, rotate or sol"
// @Param        min_risk  query  int     false  "Minimum risk points"
// @Param        search    query  string  false  "Title search"
// @Param        queued    query  bool    false  "Include proposals held back by the daily cap"
// @Param        page      query  int     false  "Page number" default(1)
// @Param        per_page  query  int     false  "Items per page" default(25)
// @Success      200  {object}  pagination.Result[RemediationSuggestionResponse]
// @Failure      400  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /remediation/suggestions [get]
func (h *RemediationSuggestionHandler) List(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tasks.tenant(w, r)
	if !ok {
		return
	}
	page, ok := listPageMax(w, r, 25, 100)
	if !ok {
		return
	}
	q := r.URL.Query()
	var f remediation.SuggestionFilter
	for _, p := range splitList(q.Get("state")) {
		st := remediation.SuggestionState(p)
		if !st.IsValid() {
			apierror.BadRequest("unknown state: " + p).WriteJSON(w)
			return
		}
		f.States = append(f.States, st)
	}
	for _, p := range splitList(q.Get("kind")) {
		k := remediation.SuggestionKind(p)
		if !k.IsValid() {
			apierror.BadRequest("unknown kind: " + p).WriteJSON(w)
			return
		}
		f.Kinds = append(f.Kinds, k)
	}
	switch kk := q.Get("key_kind"); kk {
	case "", remediation.KindUpgrade, remediation.KindRotate, remediation.KindSol:
		f.KeyKind = kk
	default:
		apierror.BadRequest("key_kind must be upgrade, rotate or sol").WriteJSON(w)
		return
	}
	if v := q.Get("min_risk"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 1_000_000 {
			apierror.BadRequest("min_risk must be a whole number").WriteJSON(w)
			return
		}
		f.MinRisk = n
	}
	f.Search = strings.TrimSpace(q.Get("search"))
	if len(f.Search) > 200 {
		apierror.BadRequest("search is longer than 200 characters").WriteJSON(w)
		return
	}
	f.IncludeQueued = q.Get("queued") == "true"
	res, err := h.service.List(r.Context(), tid, f, page)
	if err != nil {
		h.handleError(w, err)
		return
	}
	out := make([]RemediationSuggestionResponse, 0, len(res.Data))
	for _, s := range res.Data {
		out = append(out, toSuggestionResp(s))
	}
	writeJSON(w, http.StatusOK, pagination.NewResult(out, res.Total, page))
}

// Summary counts the open suggestions (the inbox badge).
// @Summary      Count open remediation suggestions
// @Tags         Remediation
// @Produce      json
// @Success      200  {object}  remediation.SuggestionCounts
// @Security     BearerAuth
// @Router       /remediation/suggestions/stats [get]
func (h *RemediationSuggestionHandler) Summary(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tasks.tenant(w, r)
	if !ok {
		return
	}
	c, err := h.service.Counts(r.Context(), tid)
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, c)
}

// Get returns a suggestion with its explanation.
// @Summary      Get a remediation suggestion
// @Tags         Remediation
// @Produce      json
// @Param        id             path  string  true  "Suggestion ID"
// @Success      200  {object}  RemediationSuggestionResponse
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /remediation/suggestions/{id} [get]
func (h *RemediationSuggestionHandler) Get(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tasks.tenant(w, r)
	if !ok {
		return
	}
	id, ok := pathSuggestionID(w, r)
	if !ok {
		return
	}
	s, err := h.service.Get(r.Context(), tid, id)
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toSuggestionResp(s))
}

// Members lists a suggestion's findings the caller may see.
// @Summary      List a remediation suggestion's findings
// @Tags         Remediation
// @Produce      json
// @Param        id             path   string  true   "Suggestion ID"
// @Param        page           query  int     false  "Page number" default(1)
// @Param        per_page       query  int     false  "Items per page" default(50)
// @Success      200  {object}  pagination.Result[RemediationTaskMemberResponse]
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /remediation/suggestions/{id}/members [get]
func (h *RemediationSuggestionHandler) Members(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tasks.tenant(w, r)
	if !ok {
		return
	}
	id, ok := pathSuggestionID(w, r)
	if !ok {
		return
	}
	page, ok := listPageMax(w, r, 50, 200)
	if !ok {
		return
	}
	res, err := h.service.Members(r.Context(), tid, id, page)
	if err != nil {
		h.handleError(w, err)
		return
	}
	out := make([]RemediationTaskMemberResponse, 0, len(res.Data))
	for _, m := range res.Data {
		out = append(out, RemediationTaskMemberResponse{FindingID: m.FindingID.String(), Title: m.Title, Severity: m.Severity,
			Status: m.Status, PriorityClass: m.PriorityClass, AssetID: optIDStr(m.AssetID), AssetName: m.AssetName,
			SLADeadline: m.SLADeadline})
	}
	writeJSON(w, http.StatusOK, pagination.NewResult(out, res.Total, page))
}

// DismissRemediationSuggestionRequest dismisses a suggestion.
type DismissRemediationSuggestionRequest struct {
	Version int    `json:"version"`
	Reason  string `json:"reason"`
	Note    string `json:"note"`
}

// Dismiss dismisses a suggestion with a reason.
// @Summary      Dismiss (reject) a remediation suggestion
// @Description  reason: wrong_grouping, not_actionable, already_tracked_elsewhere, wrong_owner, too_small, accepted_risk or other (other needs a note). The suggestion is not proposed again unless it changes materially.
// @Tags         Remediation
// @Accept       json
// @Produce      json
// @Param        id             path  string                               true  "Suggestion ID"
// @Param        request        body  DismissRemediationSuggestionRequest  true  "Reason"
// @Success      200  {object}  RemediationSuggestionResponse
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /remediation/suggestions/{id}/reject [post]
func (h *RemediationSuggestionHandler) Dismiss(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tasks.tenant(w, r)
	if !ok {
		return
	}
	id, ok := pathSuggestionID(w, r)
	if !ok {
		return
	}
	var req DismissRemediationSuggestionRequest
	if err := decodeTaskBody(w, r, &req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	s, err := h.service.Dismiss(r.Context(), remediationapp.DismissInput{TenantID: tid, ID: id, Version: req.Version,
		Reason: remediation.DismissReason(req.Reason), Note: req.Note, ActorID: callerID(r)}, h.tasks.auditContext(r))
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toSuggestionResp(s))
}

// SnoozeRemediationSuggestionRequest snoozes a suggestion.
type SnoozeRemediationSuggestionRequest struct {
	Version      int    `json:"version"`
	SnoozedUntil string `json:"snoozed_until"`
}

// Snooze hides a suggestion until a time (PATCH snoozed_until).
// @Summary      Snooze a remediation suggestion
// @Tags         Remediation
// @Accept       json
// @Produce      json
// @Param        id             path  string                              true  "Suggestion ID"
// @Param        request        body  SnoozeRemediationSuggestionRequest  true  "Until (RFC 3339 or a date, at most 180 days ahead)"
// @Success      200  {object}  RemediationSuggestionResponse
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /remediation/suggestions/{id} [patch]
func (h *RemediationSuggestionHandler) Snooze(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tasks.tenant(w, r)
	if !ok {
		return
	}
	id, ok := pathSuggestionID(w, r)
	if !ok {
		return
	}
	var req SnoozeRemediationSuggestionRequest
	if err := decodeTaskBody(w, r, &req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	until, err := parseTaskDeadline(req.SnoozedUntil)
	if err != nil {
		apierror.BadRequest("snoozed_until must be an RFC 3339 timestamp or a date (YYYY-MM-DD)").WriteJSON(w)
		return
	}
	s, err := h.service.Snooze(r.Context(), remediationapp.SnoozeInput{TenantID: tid, ID: id, Version: req.Version,
		Until: *until, ActorID: callerID(r)}, h.tasks.auditContext(r))
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toSuggestionResp(s))
}

// RemediationSuggestionVersionRequest names the version a decision is based on.
type RemediationSuggestionVersionRequest struct {
	Version int `json:"version"`
}

// Reopen undoes a dismissal or a snooze.
// @Summary      Reopen a dismissed or snoozed remediation suggestion
// @Tags         Remediation
// @Accept       json
// @Produce      json
// @Param        id             path  string                               true  "Suggestion ID"
// @Param        request        body  RemediationSuggestionVersionRequest  true  "Version"
// @Success      200  {object}  RemediationSuggestionResponse
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /remediation/suggestions/{id}/reopen [post]
func (h *RemediationSuggestionHandler) Reopen(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tasks.tenant(w, r)
	if !ok {
		return
	}
	id, ok := pathSuggestionID(w, r)
	if !ok {
		return
	}
	var req RemediationSuggestionVersionRequest
	if err := decodeTaskBody(w, r, &req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	s, err := h.service.Reopen(r.Context(), tid, id, req.Version, callerID(r), h.tasks.auditContext(r))
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toSuggestionResp(s))
}

// Refresh runs the generator for the caller's organization now.
// @Summary      Refresh remediation suggestions now
// @Description  Runs the suggestion generator for the organization (at most once a minute). It only proposes; nothing is created.
// @Tags         Remediation
// @Produce      json
// @Success      200  {object}  remediation.RunStats
// @Failure      429  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /remediation/suggestions/run [post]
func (h *RemediationSuggestionHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tasks.tenant(w, r)
	if !ok {
		return
	}
	st, err := h.service.Refresh(r.Context(), tid, h.tasks.auditContext(r))
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (h *RemediationSuggestionHandler) handleError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, remediation.ErrRunTooSoon):
		w.Header().Set("Retry-After", "60")
		apierror.New(http.StatusTooManyRequests, apierror.CodeRateLimitExceeded, err.Error()).WriteJSON(w)
	case errors.Is(err, remediation.ErrSuggestionNotFound):
		apierror.NotFound("suggestion not found").WriteJSON(w)
	default:
		h.tasks.handleError(w, err)
	}
}

// ApproveRemediationSuggestionRequest accepts a suggestion, with optional
// edits.
type ApproveRemediationSuggestionRequest struct {
	Version           int                               `json:"version"`
	Title             *string                           `json:"title,omitempty"`
	ExcludeFindingIDs []string                          `json:"exclude_finding_ids,omitempty"`
	Owners            []RemediationSuggestionOwnerInput `json:"owners,omitempty"`
	Deadline          string                            `json:"deadline,omitempty"`
	AutoJoin          bool                              `json:"auto_join,omitempty"`
}

// RemediationSuggestionOwnerInput names another owner for one partition.
type RemediationSuggestionOwnerInput struct {
	Index           int    `json:"index"`
	AssigneeUserID  string `json:"assignee_user_id,omitempty"`
	AssigneeGroupID string `json:"assignee_group_id,omitempty"`
}

// RemediationAcceptResponse is what an accept created.
type RemediationAcceptResponse struct {
	SuggestionID string   `json:"suggestion_id"`
	ActionID     string   `json:"action_id"`
	TaskIDs      []string `json:"task_ids"`
	Joined       int      `json:"joined"`
	Dropped      []string `json:"dropped"`
}

func toAcceptResp(r *remediation.AcceptResult) RemediationAcceptResponse {
	out := RemediationAcceptResponse{SuggestionID: r.SuggestionID.String(), ActionID: r.ActionID.String(),
		TaskIDs: make([]string, 0, len(r.TaskIDs)), Joined: r.Joined, Dropped: make([]string, 0, len(r.Dropped))}
	for _, id := range r.TaskIDs {
		out.TaskIDs = append(out.TaskIDs, id.String())
	}
	for _, id := range r.Dropped {
		out.Dropped = append(out.Dropped, id.String())
	}
	return out
}

// Approve accepts a suggestion.
// @Summary      Accept (approve) a remediation suggestion
// @Description  Creates what the suggestion proposes: a new group creates the action and one task per owner; a join adds the findings to the owner's task; a task route creates a task under the existing action. Optional edits: title, findings to remove (remembered for this fix), other owners per partition, a deadline (it only tightens), and the auto-join rule (exact keys only, needs access to every asset). Findings that closed or joined another task since are left out and listed in dropped.
// @Tags         Remediation
// @Accept       json
// @Produce      json
// @Param        id       path  string                               true  "Suggestion ID"
// @Param        request  body  ApproveRemediationSuggestionRequest  true  "Version and edits"
// @Success      200  {object}  RemediationAcceptResponse
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /remediation/suggestions/{id}/approve [post]
func (h *RemediationSuggestionHandler) Approve(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tasks.tenant(w, r)
	if !ok {
		return
	}
	id, ok := pathSuggestionID(w, r)
	if !ok {
		return
	}
	var req ApproveRemediationSuggestionRequest
	if err := decodeTaskBody(w, r, &req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	in := remediationapp.AcceptInput{TenantID: tid, ID: id, Version: req.Version, ActorID: callerID(r), Title: req.Title, AutoJoin: req.AutoJoin}
	var err error
	if in.Exclude, err = parseIDList("exclude_finding_ids", req.ExcludeFindingIDs); err != nil {
		h.handleError(w, err)
		return
	}
	for _, o := range req.Owners {
		po := remediationapp.PartitionOwner{Index: o.Index}
		if po.UserID, err = parseOptID("assignee_user_id", o.AssigneeUserID); err != nil {
			h.handleError(w, err)
			return
		}
		if po.GroupID, err = parseOptID("assignee_group_id", o.AssigneeGroupID); err != nil {
			h.handleError(w, err)
			return
		}
		in.Owners = append(in.Owners, po)
	}
	if strings.TrimSpace(req.Deadline) != "" {
		if in.Deadline, err = parseTaskDeadline(req.Deadline); err != nil {
			h.handleError(w, err)
			return
		}
	}
	res, err := h.service.Accept(r.Context(), in, h.tasks.auditContext(r))
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toAcceptResp(res))
}

// BulkApproveRemediationSuggestionsRequest accepts several suggestions as they are.
type BulkApproveRemediationSuggestionsRequest struct {
	IDs []string `json:"ids"`
}

// RemediationBulkAcceptItem is the outcome of one suggestion.
type RemediationBulkAcceptItem struct {
	ID     string                     `json:"id"`
	Result *RemediationAcceptResponse `json:"result,omitempty"`
	Error  string                     `json:"error,omitempty"`
}

// BulkApprove accepts several suggestions as they are.
// @Summary      Accept several remediation suggestions
// @Description  Accepts up to 50 suggestions (at most 5000 findings) as they are, each on its own; the response gives each one's result or error.
// @Tags         Remediation
// @Accept       json
// @Produce      json
// @Param        request  body  BulkApproveRemediationSuggestionsRequest  true  "Suggestion IDs"
// @Success      200  {array}   RemediationBulkAcceptItem
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /remediation/suggestions/approve [post]
func (h *RemediationSuggestionHandler) BulkApprove(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tasks.tenant(w, r)
	if !ok {
		return
	}
	var req BulkApproveRemediationSuggestionsRequest
	if err := decodeTaskBody(w, r, &req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	ids, err := parseIDList("ids", req.IDs)
	if err != nil {
		h.handleError(w, err)
		return
	}
	items, err := h.service.AcceptMany(r.Context(), tid, ids, callerID(r), h.tasks.auditContext(r))
	if err != nil {
		h.handleError(w, err)
		return
	}
	out := make([]RemediationBulkAcceptItem, 0, len(items))
	for _, it := range items {
		o := RemediationBulkAcceptItem{ID: it.ID.String(), Error: it.Error}
		if it.Result != nil {
			res := toAcceptResp(it.Result)
			o.Result = &res
		}
		out = append(out, o)
	}
	writeJSON(w, http.StatusOK, out)
}

// RemediationActionResponse is a remediation action.
type RemediationActionResponse struct {
	ID        string         `json:"id"`
	Key       string         `json:"key"`
	Kind      string         `json:"kind"`
	Title     string         `json:"title"`
	FixSpec   map[string]any `json:"fix_spec"`
	Origin    string         `json:"origin"`
	AutoJoin  bool           `json:"auto_join"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

func toActionResp(a *remediation.Action) RemediationActionResponse {
	spec := a.FixSpec
	if spec == nil {
		spec = map[string]any{}
	}
	return RemediationActionResponse{ID: a.ID.String(), Key: a.Key, Kind: a.Kind, Title: a.Title, FixSpec: spec,
		Origin: string(a.Origin), AutoJoin: a.AutoJoin, CreatedAt: a.CreatedAt, UpdatedAt: a.UpdatedAt}
}

// GetAction returns a remediation action.
// @Summary      Get a remediation action
// @Tags         Remediation
// @Produce      json
// @Param        id  path  string  true  "Action ID"
// @Success      200  {object}  RemediationActionResponse
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /remediation/actions/{id} [get]
func (h *RemediationSuggestionHandler) GetAction(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tasks.tenant(w, r)
	if !ok {
		return
	}
	id, ok := pathSuggestionID(w, r)
	if !ok {
		return
	}
	a, err := h.service.GetAction(r.Context(), tid, id)
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toActionResp(a))
}

// UpdateRemediationActionRequest changes an action's auto-join rule.
type UpdateRemediationActionRequest struct {
	AutoJoin *bool `json:"auto_join"`
}

// UpdateAction turns an action's auto-join rule on or off.
// @Summary      Turn a remediation action's auto-join rule on or off
// @Description  With auto-join on, new findings with the action's exact key (package upgrade or secret rotation only) join their owner's open or in-progress task without a suggestion, at most 200 a day; it never changes a finding's status. Needs access to every asset of the organization.
// @Tags         Remediation
// @Accept       json
// @Produce      json
// @Param        id       path  string                          true  "Action ID"
// @Param        request  body  UpdateRemediationActionRequest  true  "auto_join"
// @Success      200  {object}  RemediationActionResponse
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /remediation/actions/{id} [patch]
func (h *RemediationSuggestionHandler) UpdateAction(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tasks.tenant(w, r)
	if !ok {
		return
	}
	id, ok := pathSuggestionID(w, r)
	if !ok {
		return
	}
	var req UpdateRemediationActionRequest
	if err := decodeTaskBody(w, r, &req); err != nil || req.AutoJoin == nil {
		apierror.BadRequest("auto_join is required").WriteJSON(w)
		return
	}
	a, err := h.service.ChangeActionAutoJoin(r.Context(), tid, id, *req.AutoJoin, callerID(r), h.tasks.auditContext(r))
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toActionResp(a))
}
