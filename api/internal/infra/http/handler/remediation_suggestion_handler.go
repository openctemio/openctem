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
