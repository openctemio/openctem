package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"time"

	"github.com/go-chi/chi/v5"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	retestapp "github.com/openctemio/openctem/api/internal/app/retest"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/pentest"
	retestdom "github.com/openctemio/openctem/api/pkg/domain/retest"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// FindingRetestHandler serves "Retest now" and a finding's retest history
// (RFC-039).
type FindingRetestHandler struct {
	service *retestapp.Service
	manual  ManualRetestSource // optional: pentest testers' retests
	logger  *logger.Logger
}

// ManualRetestSource answers the retests testers recorded by hand on a
// pentest finding. isPentest is false for any other finding. A caller who is
// not a member of the finding's campaign (and not an admin) gets an error
// wrapping shared.ErrNotFound.
type ManualRetestSource interface {
	ManualRetestsForFinding(ctx context.Context, tenantID, findingID, userID string, isAdmin bool) (retests []*pentest.Retest, isPentest bool, err error)
}

// SetManualRetestSource adds pentest manual retests to a finding's retest
// history, so a finding has one history whatever retested it.
func (h *FindingRetestHandler) SetManualRetestSource(src ManualRetestSource) { h.manual = src }

// NewFindingRetestHandler creates the handler.
func NewFindingRetestHandler(svc *retestapp.Service, log *logger.Logger) *FindingRetestHandler {
	return &FindingRetestHandler{service: svc, logger: log}
}

// FindingRetestResponse is one retest of a finding.
type FindingRetestResponse struct {
	ID string `json:"id"`
	// Kind: automated (the platform re-ran the check) or manual (a pentest
	// tester recorded the result; manual_result, notes and tested_by are set).
	Kind         string `json:"kind"`
	ManualResult string `json:"manual_result,omitempty"`
	Notes        string `json:"notes,omitempty"`
	TestedBy     string `json:"tested_by,omitempty"`
	FindingID    string `json:"finding_id"`
	Trigger      string `json:"trigger"`
	RequestedBy  string `json:"requested_by,omitempty"`
	Status       string `json:"status"`
	// Outcome: confirmed_fixed (the endpoint answered and the check did not
	// match), not_reproduced (no match, endpoint not proven checked),
	// still_vulnerable, inconclusive (reason_code says why).
	Outcome      string `json:"outcome,omitempty"`
	ReasonCode   string `json:"reason_code,omitempty"`
	Reason       string `json:"reason,omitempty"`
	PriorStatus  string `json:"prior_status"`
	ResultStatus string `json:"result_status,omitempty"`
	TemplateID   string `json:"template_id"`
	Target       string `json:"target"`
	// RunKind is "retest": an attempt is a run linked to the finding, the
	// command that carried it (check_command_id) and the sensor that ran it.
	RunKind        string `json:"run_kind"`
	CheckCommandID string `json:"check_command_id,omitempty"`
	// RunID is the scan run (kind retest) with the commands, logs and outcome.
	RunID          string     `json:"run_id,omitempty"`
	ReachCommandID string     `json:"reach_command_id,omitempty"`
	SensorID       string     `json:"sensor_id,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	CompletedAt    *time.Time `json:"completed_at,omitempty"`
	DeadlineAt     time.Time  `json:"deadline_at"`
}

// FindingRetestListResponse is a finding's retest history, newest first.
type FindingRetestListResponse struct {
	Data []FindingRetestResponse `json:"data"`
	// CanRetest: a retest of this finding would be accepted now (eligible,
	// target gates pass, an online sensor can re-check it). The console
	// offers "Retest now" from it.
	CanRetest bool `json:"can_retest"`
}

func toFindingRetestResponse(rt *retestdom.Retest) FindingRetestResponse {
	out := FindingRetestResponse{
		ID: rt.ID.String(), FindingID: rt.FindingID.String(), Trigger: string(rt.Trigger),
		Status: string(rt.Status), Outcome: string(rt.Outcome), ReasonCode: string(rt.ReasonCode), Reason: rt.Reason,
		PriorStatus: string(rt.PriorStatus), ResultStatus: string(rt.ResultStatus),
		TemplateID: rt.TemplateID, Target: rt.Target,
		CreatedAt: rt.CreatedAt, CompletedAt: rt.CompletedAt, DeadlineAt: rt.DeadlineAt,
	}
	if rt.RequestedBy != nil {
		out.RequestedBy = rt.RequestedBy.String()
	}
	out.Kind = retestKindAutomated
	out.RunKind = "retest"
	if rt.RunID != nil {
		out.RunID = rt.RunID.String()
	}
	if rt.CheckCommandID != nil {
		out.CheckCommandID = rt.CheckCommandID.String()
	}
	if rt.ReachCommandID != nil {
		out.ReachCommandID = rt.ReachCommandID.String()
	}
	if rt.SensorID != nil {
		out.SensorID = rt.SensorID.String()
	}
	return out
}

const (
	retestKindAutomated = "automated"
	retestKindManual    = "manual"
)

func manualRetestResponse(rt *pentest.Retest) FindingRetestResponse {
	out := FindingRetestResponse{
		ID: rt.ID().String(), Kind: retestKindManual, FindingID: rt.FindingID().String(),
		Trigger: "manual", ManualResult: string(rt.Status()), Notes: rt.Notes(),
		Status: "completed", CreatedAt: rt.CreatedAt(), CompletedAt: rt.TestedAt(), RunKind: "retest",
		PriorStatus: rt.PriorStatus(), ResultStatus: rt.ResultStatus(),
	}
	switch rt.Status() {
	case pentest.RetestStatusPending, pentest.RetestStatusInProgress:
		out.Status = "pending"
	}
	if rt.TestedBy() != nil {
		out.TestedBy = rt.TestedBy().String()
	}
	return out
}

// Request handles POST /api/v1/findings/{id}/retests.
// @Summary      Retest a finding now
// @Description  Re-runs the check that produced the finding against the origin of its matched-at URL (RFC-039, RFC-057). Applied asynchronously: confirmed_fixed (the re-run reached the finding's endpoint, got an answer that is not a block, an auth failure or a server error, and did not match) moves the finding to validated_fixed, or resolves it when the tenant enabled retest.auto_resolve; still_vulnerable keeps it (or reopens a resolved one); not_reproduced and inconclusive change nothing. The attempt's request and response are kept as finding evidence. Requires findings:verify; out-of-scope findings are 404.
// @Tags         Findings
// @Produce      json
// @Param        id   path      string  true  "Finding ID"
// @Success      202  {object}  FindingRetestResponse
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Failure      429  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /findings/{id}/retests [post]
func (h *FindingRetestHandler) Request(w http.ResponseWriter, r *http.Request) {
	tenantID, err := shared.IDFromString(middleware.MustGetTenantID(r.Context()))
	if err != nil {
		apierror.BadRequest("invalid tenant").WriteJSON(w)
		return
	}
	findingID, err := shared.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		apierror.NotFound("Finding").WriteJSON(w)
		return
	}
	in := retestapp.RequestInput{
		TenantID: tenantID, FindingID: findingID, Trigger: retestdom.TriggerManual,
		Audit: auditapp.AuditContext{
			TenantID: tenantID.String(), ActorID: middleware.GetUserID(r.Context()),
			ActorEmail: auditActorEmail(r.Context()), ActorIP: getClientIP(r),
			UserAgent: r.UserAgent(), RequestID: r.Header.Get("X-Request-ID"),
		},
	}
	if uid := middleware.GetLocalUserID(r.Context()); !uid.IsZero() {
		in.RequestedBy = &uid
	} else if uid, err := shared.IDFromString(middleware.GetUserID(r.Context())); err == nil {
		in.RequestedBy = &uid
	}
	rt, err := h.service.Request(r.Context(), in)
	if err != nil {
		h.writeError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(toFindingRetestResponse(rt))
}

// List handles GET /api/v1/findings/{id}/retests.
// @Summary      A finding's retests
// @Description  The finding's retest history, newest first (RFC-039).
// @Tags         Findings
// @Produce      json
// @Param        id     path      string  true   "Finding ID"
// @Param        limit  query     int     false  "Max items (1-100, default 20)"
// @Success      200    {object}  FindingRetestListResponse
// @Failure      404    {object}  apierror.Error
// @Security     BearerAuth
// @Router       /findings/{id}/retests [get]
func (h *FindingRetestHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantID, err := shared.IDFromString(middleware.MustGetTenantID(r.Context()))
	if err != nil {
		apierror.BadRequest("invalid tenant").WriteJSON(w)
		return
	}
	findingID, err := shared.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		apierror.NotFound("Finding").WriteJSON(w)
		return
	}
	// 0: the store's default page of retests.
	limit, ok := listLimit(w, r, 0, 100)
	if !ok {
		return
	}
	// Pentest findings: the campaign decides who sees them (non-members get
	// 404, as on every pentest surface), and testers' manual retests join the
	// history.
	var manual []*pentest.Retest
	if h.manual != nil {
		m, _, merr := h.manual.ManualRetestsForFinding(r.Context(), tenantID.String(), findingID.String(),
			middleware.GetUserID(r.Context()), middleware.IsAdmin(r.Context()))
		if merr != nil {
			h.writeError(w, merr)
			return
		}
		manual = m
	}
	list, err := h.service.List(r.Context(), tenantID, findingID, limit)
	if err != nil {
		h.writeError(w, err)
		return
	}
	out := FindingRetestListResponse{Data: make([]FindingRetestResponse, 0, len(list)+len(manual))}
	for _, rt := range list {
		out.Data = append(out.Data, toFindingRetestResponse(rt))
	}
	for _, rt := range manual {
		out.Data = append(out.Data, manualRetestResponse(rt))
	}
	// One history, newest first.
	sort.SliceStable(out.Data, func(i, j int) bool { return out.Data[i].CreatedAt.After(out.Data[j].CreatedAt) })
	if limit > 0 && len(out.Data) > limit {
		out.Data = out.Data[:limit]
	}
	can, err := h.service.CanRetest(r.Context(), tenantID, findingID)
	if err != nil {
		h.logger.Warn("retest availability check failed", "finding_id", findingID.String(), "error", err)
	}
	out.CanRetest = can
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func (h *FindingRetestHandler) writeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, retestdom.ErrRateLimited):
		apierror.TooManyRequests(err.Error()).WriteJSON(w)
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Finding").WriteJSON(w)
	case errors.Is(err, shared.ErrConflict):
		apierror.Conflict(err.Error()).WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	default:
		h.logger.Error("retest request failed", "error", err)
		apierror.InternalServerError("Internal server error").WriteJSON(w)
	}
}
