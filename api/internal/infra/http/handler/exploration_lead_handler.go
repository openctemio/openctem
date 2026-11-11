package handler

// Exploration leads for people (docs/architecture/exploration.md,
// "Approvals and people").

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	explorationapp "github.com/openctemio/openctem/api/internal/app/exploration"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/exploration"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// LeadService is what the handler needs from the exploration lead service.
type LeadService interface {
	List(ctx context.Context, tenantID shared.ID, in explorationapp.ListInput) ([]*exploration.Lead, error)
	Get(ctx context.Context, tenantID shared.ID, id string, p explorationapp.Person) (*explorationapp.Detail, error)
	Open(ctx context.Context, tenantID shared.ID, p explorationapp.Person, in explorationapp.OpenInput) (*exploration.Lead, error)
	Approve(ctx context.Context, tenantID shared.ID, p explorationapp.Person, ids []string) ([]explorationapp.BulkResult, error)
	Dismiss(ctx context.Context, tenantID shared.ID, p explorationapp.Person, ids []string, reason string) ([]explorationapp.BulkResult, error)
}

// ExplorationLeadHandler serves /api/v1/exploration/leads.
type ExplorationLeadHandler struct {
	leads  LeadService
	logger *logger.Logger
}

// NewExplorationLeadHandler creates the handler.
func NewExplorationLeadHandler(leads LeadService, log *logger.Logger) *ExplorationLeadHandler {
	return &ExplorationLeadHandler{leads: leads, logger: log}
}

// LeadResponse is one lead.
type LeadResponse struct {
	ID             string         `json:"id"`
	Type           string         `json:"type"`
	State          string         `json:"state"`
	Capability     string         `json:"capability"`
	Tier           int            `json:"tier"`
	SubjectAssetID string         `json:"subject_asset_id,omitempty"`
	ReasonCode     string         `json:"reason_code"`
	Rationale      string         `json:"rationale"`
	Origin         string         `json:"origin"`
	Likelihood     string         `json:"likelihood"`
	Score          float64        `json:"score"`
	ScoreInputs    map[string]any `json:"score_inputs"`
	BlockedReason  string         `json:"blocked_reason,omitempty"`
	Attempts       int            `json:"attempts"`
	NextAttemptAt  *time.Time     `json:"next_attempt_at,omitempty"`
	ApprovedAt     *time.Time     `json:"approved_at,omitempty"`
	ApprovedBy     string         `json:"approved_by,omitempty"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
	ClosedAt       *time.Time     `json:"closed_at,omitempty"`
}

// LeadLinkResponse is one typed link of a lead. EndID is empty when the
// record was removed or the caller may not see it (a run without scans:read).
type LeadLinkResponse struct {
	Rel           string    `json:"rel"`
	EndKind       string    `json:"end_kind"`
	EndID         string    `json:"end_id,omitempty"`
	Effect        string    `json:"effect,omitempty"`
	OutcomeReason string    `json:"outcome_reason,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}

// LeadVerdictResponse is one verdict.
type LeadVerdictResponse struct {
	Verdict   string                    `json:"verdict"`
	Tier      string                    `json:"tier"`
	Checker   string                    `json:"checker"`
	Evidence  []exploration.EvidenceRef `json:"evidence"`
	Reason    string                    `json:"reason"`
	CreatedAt time.Time                 `json:"created_at"`
}

// LeadDetailResponse is a lead with its links and verdicts.
type LeadDetailResponse struct {
	LeadResponse
	Links    []LeadLinkResponse    `json:"links"`
	Verdicts []LeadVerdictResponse `json:"verdicts"`
}

// LeadListResponse is one page of leads.
type LeadListResponse struct {
	Data []LeadResponse `json:"data"`
	// NextBefore pages on: pass it as before for the next page.
	NextBefore *time.Time `json:"next_before,omitempty"`
}

// OpenLeadRequest opens a lead by hand.
type OpenLeadRequest struct {
	LeadType  string `json:"lead_type"`
	AssetID   string `json:"asset_id"`
	Rationale string `json:"rationale"`
}

// LeadBulkRequest names leads to approve or dismiss.
type LeadBulkRequest struct {
	IDs    []string `json:"ids"`
	Reason string   `json:"reason,omitempty"`
}

// LeadBulkResponse is the outcome per lead.
type LeadBulkResponse struct {
	Results []explorationapp.BulkResult `json:"results"`
}

func toLeadResponse(l *exploration.Lead) LeadResponse {
	out := LeadResponse{ID: l.ID.String(), Type: l.Type, State: string(l.State), Capability: l.Action.Capability,
		Tier: int(l.Tier), ReasonCode: l.ReasonCode, Rationale: l.Rationale, Origin: string(l.Origin),
		Likelihood: string(l.Likelihood), Score: l.Score, ScoreInputs: l.ScoreInputs, BlockedReason: l.BlockedReason,
		Attempts: l.Attempts, NextAttemptAt: l.NextAttemptAt, ApprovedAt: l.ApprovedAt, CreatedAt: l.CreatedAt,
		UpdatedAt: l.UpdatedAt, ClosedAt: l.ClosedAt}
	if l.SubjectAssetID != nil {
		out.SubjectAssetID = l.SubjectAssetID.String()
	}
	if l.ApprovedBy != nil {
		out.ApprovedBy = l.ApprovedBy.String()
	}
	if out.ScoreInputs == nil {
		out.ScoreInputs = map[string]any{}
	}
	return out
}

func (h *ExplorationLeadHandler) person(r *http.Request) explorationapp.Person {
	ctx := r.Context()
	uid, _ := shared.IDFromString(middleware.GetUserID(ctx))
	return explorationapp.Person{
		UserID: uid,
		Scans:  middleware.HasPermission(ctx, string(permission.ScansRead)),
		Actx: auditapp.AuditContext{
			TenantID: middleware.GetTenantID(ctx), ActorID: middleware.GetUserID(ctx), ActorEmail: auditActorEmail(ctx),
			ActorIP: getClientIP(r), UserAgent: r.UserAgent(), RequestID: middleware.GetRequestID(ctx),
			SessionID: middleware.GetSessionID(ctx),
		},
	}
}

func tenantOf(r *http.Request) (shared.ID, bool) {
	id, err := shared.IDFromString(middleware.GetTenantID(r.Context()))
	return id, err == nil
}

func (h *ExplorationLeadHandler) fail(w http.ResponseWriter, err error) {
	switch {
	case shared.IsNotFound(err), errors.Is(err, shared.ErrForbidden):
		apierror.NotFound("Lead").WriteJSON(w)
	case errors.Is(err, explorationapp.ErrAlreadyAsked), errors.Is(err, explorationapp.ErrTooManyLeads),
		errors.Is(err, exploration.ErrBadTransition), errors.Is(err, exploration.ErrStale):
		apierror.Conflict("The question cannot change that way now").WriteJSON(w)
	case shared.IsValidation(err):
		apierror.BadRequest("Invalid request").WriteJSON(w)
	default:
		h.logger.Error("exploration leads", "error", logger.SanitizeError(err))
		apierror.InternalServerError("could not process the request").WriteJSON(w)
	}
}

// List handles GET /api/v1/exploration/leads.
//
// @Summary      Exploration leads
// @Description  The organization's open questions and their outcomes, newest change first, within the caller's data scope (a lead is seen when its subject asset is). group: waiting (awaiting approval, proposed, blocked), next (open), running, done; empty for all. asset_id narrows to one asset. Keyset paging: pass next_before as before.
// @Tags         Exploration
// @Produce      json
// @Security     BearerAuth
// @Param        group     query  string  false  "waiting, next, running or done"
// @Param        asset_id  query  string  false  "Subject asset id"
// @Param        before    query  string  false  "RFC 3339 time: leads changed before it"
// @Param        limit     query  int     false  "1-200 (larger is lowered to 200), default 50"
// @Success      200  {object}  LeadListResponse
// @Failure      400  {object}  apierror.Error
// @Router       /exploration/leads [get]
func (h *ExplorationLeadHandler) List(w http.ResponseWriter, r *http.Request) {
	tid, ok := tenantOf(r)
	if !ok {
		apierror.Unauthorized("").WriteJSON(w)
		return
	}
	q := r.URL.Query()
	in := explorationapp.ListInput{Group: q.Get("group"), AssetID: q.Get("asset_id")}
	limit, ok := listLimit(w, r, 50, exploration.MaxListLimit)
	if !ok {
		return
	}
	in.Limit = limit
	if v := q.Get("before"); v != "" {
		t, err := time.Parse(time.RFC3339Nano, v)
		if err != nil {
			apierror.BadRequest("before must be an RFC 3339 time").WriteJSON(w)
			return
		}
		in.Before = &t
	}
	leads, err := h.leads.List(r.Context(), tid, in)
	if err != nil {
		h.fail(w, err)
		return
	}
	out := LeadListResponse{Data: make([]LeadResponse, 0, len(leads))}
	for _, l := range leads {
		out.Data = append(out.Data, toLeadResponse(l))
	}
	if len(leads) == in.Limit {
		t := leads[len(leads)-1].UpdatedAt
		out.NextBefore = &t
	}
	writeJSON(w, http.StatusOK, out)
}

// Get handles GET /api/v1/exploration/leads/{id}.
//
// @Summary      One exploration lead
// @Description  A lead with its typed links (derived_from: the evidence that justified it; dispatched_as: the run it started, shown with scans:read; yields: what the run produced, not_found included) and its append-only verdicts. Outside the caller's data scope or another organization's: 404.
// @Tags         Exploration
// @Produce      json
// @Security     BearerAuth
// @Param        id   path  string  true  "Lead id"
// @Success      200  {object}  LeadDetailResponse
// @Failure      404  {object}  apierror.Error
// @Router       /exploration/leads/{id} [get]
func (h *ExplorationLeadHandler) Get(w http.ResponseWriter, r *http.Request) {
	tid, ok := tenantOf(r)
	if !ok {
		apierror.Unauthorized("").WriteJSON(w)
		return
	}
	d, err := h.leads.Get(r.Context(), tid, r.PathValue("id"), h.person(r))
	if err != nil {
		h.fail(w, err)
		return
	}
	out := LeadDetailResponse{LeadResponse: toLeadResponse(d.Lead), Links: []LeadLinkResponse{}, Verdicts: []LeadVerdictResponse{}}
	for _, k := range d.Links {
		lr := LeadLinkResponse{Rel: string(k.Rel), EndKind: string(k.EndKind), Effect: string(k.Effect),
			OutcomeReason: k.OutcomeReason, CreatedAt: k.CreatedAt}
		if k.EndID != nil {
			lr.EndID = k.EndID.String()
		}
		out.Links = append(out.Links, lr)
	}
	for _, v := range d.Verdicts {
		ev := v.Evidence
		if ev == nil {
			ev = []exploration.EvidenceRef{}
		}
		out.Verdicts = append(out.Verdicts, LeadVerdictResponse{Verdict: string(v.Verdict), Tier: string(v.Tier),
			Checker: v.Checker, Evidence: ev, Reason: v.Reason, CreatedAt: v.CreatedAt})
	}
	writeJSON(w, http.StatusOK, out)
}

// Open handles POST /api/v1/exploration/leads.
//
// @Summary      Ask a question about an asset
// @Description  Opens a lead of a catalog type on an asset in the caller's data scope, with the catalog's action for the asset's type. A passive step opens at once; an active step opens at once only while automatic coverage is on, else it waits for approval; an intrusive step always waits for a person. 409 when the same question is already open or the asset or organization is at its cap.
// @Tags         Exploration
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body  body  OpenLeadRequest  true  "Lead type, asset and rationale"
// @Success      201  {object}  LeadResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Router       /exploration/leads [post]
func (h *ExplorationLeadHandler) Open(w http.ResponseWriter, r *http.Request) {
	tid, ok := tenantOf(r)
	if !ok {
		apierror.Unauthorized("").WriteJSON(w)
		return
	}
	var req OpenLeadRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	l, err := h.leads.Open(r.Context(), tid, h.person(r), explorationapp.OpenInput{LeadType: req.LeadType, AssetID: req.AssetID, Rationale: req.Rationale})
	if err != nil {
		if shared.IsNotFound(err) {
			apierror.NotFound("Asset").WriteJSON(w)
			return
		}
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, toLeadResponse(l))
}

func (h *ExplorationLeadHandler) bulk(w http.ResponseWriter, r *http.Request, do func(context.Context, shared.ID, explorationapp.Person, LeadBulkRequest) ([]explorationapp.BulkResult, error)) {
	tid, ok := tenantOf(r)
	if !ok {
		apierror.Unauthorized("").WriteJSON(w)
		return
	}
	var req LeadBulkRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	res, err := do(r.Context(), tid, h.person(r), req)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, LeadBulkResponse{Results: res})
}

// Approve handles POST /api/v1/exploration/leads/approve.
//
// @Summary      Approve leads waiting for a person
// @Description  Lets up to 100 leads that wait for approval run. Needs scans:approve and a fresh step-up. Each lead must be in the caller's data scope and waiting for approval; the result is per lead (not_found, wrong_state, changed). The step still passes the dispatch gate when it starts. The system never starts an intrusive step by itself, approved or not.
// @Tags         Exploration
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body  body  LeadBulkRequest  true  "Lead ids"
// @Success      200  {object}  LeadBulkResponse
// @Failure      400  {object}  apierror.Error
// @Router       /exploration/leads/approve [post]
func (h *ExplorationLeadHandler) Approve(w http.ResponseWriter, r *http.Request) {
	h.bulk(w, r, func(ctx context.Context, tid shared.ID, p explorationapp.Person, req LeadBulkRequest) ([]explorationapp.BulkResult, error) {
		return h.leads.Approve(ctx, tid, p, req.IDs)
	})
}

// Dismiss handles POST /api/v1/exploration/leads/reject.
//
// @Summary      Dismiss leads
// @Description  Closes up to 100 live leads without running them (a running lead settles from its run). Each lead must be in the caller's data scope; the result is per lead. The reason is audited.
// @Tags         Exploration
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body  body  LeadBulkRequest  true  "Lead ids and an optional reason"
// @Success      200  {object}  LeadBulkResponse
// @Failure      400  {object}  apierror.Error
// @Router       /exploration/leads/reject [post]
func (h *ExplorationLeadHandler) Dismiss(w http.ResponseWriter, r *http.Request) {
	h.bulk(w, r, func(ctx context.Context, tid shared.ID, p explorationapp.Person, req LeadBulkRequest) ([]explorationapp.BulkResult, error) {
		return h.leads.Dismiss(ctx, tid, p, req.IDs, req.Reason)
	})
}
