package handler

// Scan approval requests (RFC-072,
// docs/rfcs/RFC-072-scan-approval-governance.md §8): the New Scan preview,
// a scan's approval state and submission, the approvals inbox, decisions,
// reminders and emergency runs. The tenant is the authenticated principal's;
// another organization's scan or request answers 404.

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	scangovapp "github.com/openctemio/openctem/api/internal/app/scangov"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scangov"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// ScanApprovalHandler serves scan approval requests.
type ScanApprovalHandler struct {
	svc    *scangovapp.Service
	logger *logger.Logger
}

// NewScanApprovalHandler creates the handler.
func NewScanApprovalHandler(svc *scangovapp.Service, log *logger.Logger) *ScanApprovalHandler {
	return &ScanApprovalHandler{svc: svc, logger: log.With("handler", "scan_approval")}
}

// ScanApprovalRequestResponse is one approval request.
type ScanApprovalRequestResponse struct {
	ID            string                 `json:"id"`
	ScanID        string                 `json:"scan_id"`
	ScanName      string                 `json:"scan_name"`
	Status        string                 `json:"status" enums:"pending,approved,rejected,expired,superseded,canceled"`
	Digest        string                 `json:"definition_digest"`
	Definition    scangov.Definition     `json:"definition"`
	Changes       []scangov.Change       `json:"changes"`
	Evaluation    scangov.Evaluation     `json:"evaluation"`
	Justification string                 `json:"justification,omitempty"`
	Ticket        string                 `json:"ticket,omitempty"`
	RunOnApproval bool                   `json:"run_on_approval"`
	RequestedBy   *ActorRef              `json:"requested_by,omitempty"`
	RequestedAt   time.Time              `json:"requested_at"`
	ExpiresAt     time.Time              `json:"expires_at"`
	Approvals     []ScanApprovalResponse `json:"approvals"`
	Remaining     int                    `json:"remaining"`
	ValidUntil    *time.Time             `json:"valid_until,omitempty"`
	DecidedAt     *time.Time             `json:"decided_at,omitempty"`
	DecidedBy     *ActorRef              `json:"decided_by,omitempty"`
	DecisionNote  string                 `json:"decision_note,omitempty"`
	RemindedAt    *time.Time             `json:"reminded_at,omitempty"`
	Emergency     bool                   `json:"emergency"`
	// Viewer: what the caller may do with the request.
	CanApprove            bool `json:"can_approve"`
	SelfApprovalAvailable bool `json:"self_approval_available"`
	// EligibleApprovers names who may still approve (only for a caller who
	// may see the organization's members); EligibleApproverCount always.
	EligibleApproverCount int        `json:"eligible_approver_count"`
	EligibleApprovers     []ActorRef `json:"eligible_approvers,omitempty"`
}

// ScanApprovalResponse is one approval.
type ScanApprovalResponse struct {
	Approver   *ActorRef `json:"approver,omitempty"`
	ApprovedAt time.Time `json:"approved_at"`
	Note       string    `json:"note,omitempty"`
	Self       bool      `json:"self"`
	Emergency  bool      `json:"emergency"`
}

// ScanApprovalStatusResponse is a scan's approval state.
type ScanApprovalStatusResponse struct {
	Mode       string                       `json:"mode" enums:"off,on,strict"`
	Evaluation scangov.Evaluation           `json:"evaluation"`
	Required   bool                         `json:"required"`
	Approved   bool                         `json:"approved"`
	Current    *ScanApprovalRequestResponse `json:"current,omitempty"`
	Changes    []scangov.Change             `json:"changes"`
}

// ScanApprovalPreviewRequest is the part of a New Scan form the rules read.
type ScanApprovalPreviewRequest struct {
	Targets           []string `json:"targets" validate:"max=10000"`
	AssetGroupIDs     []string `json:"asset_group_ids" validate:"max=100"`
	ScanType          string   `json:"scan_type"`
	ScannerName       string   `json:"scanner_name"`
	ScanWorkflowID    string   `json:"scan_workflow_id"`
	ScheduleType      string   `json:"schedule_type"`
	SensorPreference  string   `json:"sensor_preference"`
	RunOnTenantRunner bool     `json:"run_on_tenant_runner"`
	ScanZoneID        string   `json:"scan_zone_id"`
}

// SubmitScanApprovalRequest asks for approval of a scan.
type SubmitScanApprovalRequest struct {
	Justification string `json:"justification"`
	Ticket        string `json:"ticket"`
	RunOnApproval bool   `json:"run_on_approval"`
}

// ScanApprovalDecisionRequest approves or rejects.
type ScanApprovalDecisionRequest struct {
	Note string `json:"note"`
}

// ScanSelfApprovalRequest is an owner's approval of their own request.
type ScanSelfApprovalRequest struct {
	Reason   string `json:"reason"`
	TOTPCode string `json:"totp_code"`
}

// ScanEmergencyRunRequest is an emergency run.
type ScanEmergencyRunRequest struct {
	Reason string `json:"reason"`
	Hours  int    `json:"hours"`
}

func (h *ScanApprovalHandler) ids(w http.ResponseWriter, r *http.Request) (shared.ID, shared.ID, bool) {
	tid, err := shared.IDFromString(middleware.GetTenantID(r.Context()))
	if err != nil || tid.IsZero() {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return shared.ID{}, shared.ID{}, false
	}
	id, err := shared.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		apierror.NotFound("Scan approval").WriteJSON(w)
		return shared.ID{}, shared.ID{}, false
	}
	return tid, id, true
}

func (h *ScanApprovalHandler) actor(r *http.Request) scangovapp.Actor {
	return scangovapp.Actor{UserID: middleware.GetUserID(r.Context()), AuditContext: governanceAuditContext(r)}
}

// Preview handles POST /api/v1/scans/approval-preview.
// @Summary      Which approval rules a scan would need
// @Description  Evaluates the organization's scan approval rules for an unsaved scan (the New Scan review step): required, the rules that caught it, the approvals and evidence it needs. Needs scans:write.
// @Tags         Scans
// @Accept       json
// @Produce      json
// @Param        body  body      ScanApprovalPreviewRequest  true  "Scan form"
// @Success      200   {object}  scangov.Evaluation
// @Failure      400   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scans/approval-preview [post]
func (h *ScanApprovalHandler) Preview(w http.ResponseWriter, r *http.Request) {
	tid, err := shared.IDFromString(middleware.GetTenantID(r.Context()))
	if err != nil || tid.IsZero() {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}
	var req ScanApprovalPreviewRequest
	if !decodeGovernanceBody(w, r, &req) {
		return
	}
	if len(req.Targets) > 10000 || len(req.AssetGroupIDs) > 100 {
		apierror.BadRequest("too many targets or asset groups").WriteJSON(w)
		return
	}
	sc := &scan.Scan{TenantID: tid, Targets: req.Targets, ScanType: scan.ScanType(req.ScanType), ScannerName: req.ScannerName,
		ScheduleType: scan.ScheduleType(req.ScheduleType), SensorPreference: scan.SensorPreference(req.SensorPreference),
		RunOnTenantRunner: req.RunOnTenantRunner}
	for _, g := range req.AssetGroupIDs {
		if id, err := shared.IDFromString(g); err == nil {
			sc.AssetGroupIDs = append(sc.AssetGroupIDs, id)
		}
	}
	if id, err := shared.IDFromString(req.ScanWorkflowID); err == nil {
		sc.ScanWorkflowID = &id
	}
	if id, err := shared.IDFromString(req.ScanZoneID); err == nil {
		sc.ScanZoneID = &id
	}
	ev, err := h.svc.Preview(r.Context(), sc)
	if err != nil {
		h.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ev)
}

// ScanStatus handles GET /api/v1/scans/{id}/approval.
// @Summary      A scan's approval state
// @Description  Whether the organization's rules require an approval for the scan's current definition, whether one is in force, the pending request, and the changes since the last approved definition. Needs scans:read.
// @Tags         Scans
// @Produce      json
// @Param        id   path      string  true  "Scan ID"
// @Success      200  {object}  ScanApprovalStatusResponse
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scans/{id}/approval [get]
func (h *ScanApprovalHandler) ScanStatus(w http.ResponseWriter, r *http.Request) {
	tid, id, ok := h.ids(w, r)
	if !ok {
		return
	}
	st, err := h.svc.Status(r.Context(), tid, id)
	if err != nil {
		h.writeErr(w, err)
		return
	}
	resp := ScanApprovalStatusResponse{Mode: string(st.Mode), Evaluation: st.Evaluation, Required: st.Evaluation.Required,
		Approved: st.Approved, Changes: st.Changes}
	if resp.Changes == nil {
		resp.Changes = []scangov.Change{}
	}
	if st.Current != nil {
		resp.Current = h.requestResponse(r, st.Current)
	}
	writeJSON(w, http.StatusOK, resp)
}

// Submit handles POST /api/v1/scans/{id}/approval.
// @Summary      Submit a scan for approval
// @Description  Asks for approval of the scan's current definition (targets, intensity, tools, schedule, placement). Refused when the rules need no approval (400 SCAN_APPROVAL_NOT_REQUIRED) or evidence is missing (400 SCAN_APPROVAL_EVIDENCE). run_on_approval starts a run as the requester once approved. The approvers are notified. Needs scans:write.
// @Tags         Scans
// @Accept       json
// @Produce      json
// @Param        id    path      string                     true  "Scan ID"
// @Param        body  body      SubmitScanApprovalRequest  true  "Evidence"
// @Success      201   {object}  ScanApprovalRequestResponse
// @Failure      400   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scans/{id}/approval [post]
func (h *ScanApprovalHandler) Submit(w http.ResponseWriter, r *http.Request) {
	tid, id, ok := h.ids(w, r)
	if !ok {
		return
	}
	var req SubmitScanApprovalRequest
	if !decodeGovernanceBody(w, r, &req) {
		return
	}
	q, err := h.svc.Submit(r.Context(), tid, id, scangovapp.SubmitInput{
		Justification: req.Justification, Ticket: req.Ticket, RunOnApproval: req.RunOnApproval,
	}, h.actor(r))
	if err != nil {
		h.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, h.requestResponse(r, q))
}

// Emergency handles POST /api/v1/scans/{id}/emergency-run.
// @Summary      Emergency run of a scan without its approval
// @Description  An owner or administrator runs a scan that needs an approval it does not have, now and for 1-24 hours (default 4), with a reason. Needs scans:approve and step-up. Audited critical; every administrator is told. The run passes every other gate.
// @Tags         Scans
// @Accept       json
// @Produce      json
// @Param        id    path      string                   true  "Scan ID"
// @Param        body  body      ScanEmergencyRunRequest  true  "Reason and window"
// @Success      201   {object}  ScanApprovalRequestResponse
// @Failure      400   {object}  apierror.Error
// @Failure      403   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scans/{id}/emergency-run [post]
func (h *ScanApprovalHandler) Emergency(w http.ResponseWriter, r *http.Request) {
	tid, id, ok := h.ids(w, r)
	if !ok {
		return
	}
	var req ScanEmergencyRunRequest
	if !decodeGovernanceBody(w, r, &req) {
		return
	}
	q, err := h.svc.Emergency(r.Context(), tid, id, scangovapp.EmergencyInput{Reason: req.Reason, Hours: req.Hours}, h.actor(r))
	if err != nil && q == nil {
		h.writeErr(w, err)
		return
	}
	if err != nil {
		// The window is open; the run itself was refused by another gate.
		h.logger.Warn("emergency run refused by a gate", "error", logger.SanitizeError(err))
	}
	writeJSON(w, http.StatusCreated, h.requestResponse(r, q))
}

// List handles GET /api/v1/scan-approvals.
// @Summary      Scan approval requests
// @Description  The organization's scan approval requests, newest first (status: pending, approved, rejected, expired, superseded, canceled; comma-separated). Overdue pending requests are expired first. Needs scans:read.
// @Tags         Scans
// @Produce      json
// @Param        status    query  string  false  "Statuses"
// @Param        scan_id   query  string  false  "Scan ID"
// @Param        page      query  int     false  "Page (1-based)"
// @Param        per_page  query  int     false  "Page size (max 100)"
// @Success      200  {object}  map[string]any
// @Security     BearerAuth
// @Router       /scan-approvals [get]
func (h *ScanApprovalHandler) List(w http.ResponseWriter, r *http.Request) {
	tid, err := shared.IDFromString(middleware.GetTenantID(r.Context()))
	if err != nil || tid.IsZero() {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}
	q := r.URL.Query()
	f := scangov.ListFilter{TenantID: tid}
	for _, s := range strings.Split(q.Get("status"), ",") {
		if s = strings.TrimSpace(s); s != "" {
			f.Statuses = append(f.Statuses, scangov.Status(s))
		}
	}
	if id, err := shared.IDFromString(q.Get("scan_id")); err == nil {
		f.ScanID = &id
	}
	pg, ok := listPage(w, r, 50)
	if !ok {
		return
	}
	page, per := pg.Page, min(pg.PerPage, 100)
	f.Limit, f.Offset = per, (page-1)*per
	items, total, err := h.svc.List(r.Context(), f)
	if err != nil {
		h.writeErr(w, err)
		return
	}
	out := make([]*ScanApprovalRequestResponse, 0, len(items))
	for _, it := range items {
		out = append(out, h.requestResponse(r, it))
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": out, "total": total, "page": page, "per_page": per})
}

// Get handles GET /api/v1/scan-approvals/{id}.
// @Summary      One scan approval request
// @Tags         Scans
// @Produce      json
// @Param        id   path      string  true  "Request ID"
// @Success      200  {object}  ScanApprovalRequestResponse
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scan-approvals/{id} [get]
func (h *ScanApprovalHandler) Get(w http.ResponseWriter, r *http.Request) {
	tid, id, ok := h.ids(w, r)
	if !ok {
		return
	}
	q, err := h.svc.Get(r.Context(), tid, id)
	if err != nil {
		h.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, h.requestResponse(r, q))
}

// Approve handles POST /api/v1/scan-approvals/{id}/approve.
// @Summary      Approve a scan approval request
// @Description  Needs scans:approve; the requester never approves their own request (403 SCAN_APPROVAL_OWN_REQUEST), and the rule may name the approvers (403 SCAN_APPROVAL_NOT_ELIGIBLE). Audited.
// @Tags         Scans
// @Accept       json
// @Produce      json
// @Param        id    path      string                       true  "Request ID"
// @Param        body  body      ScanApprovalDecisionRequest  true  "Note"
// @Success      200   {object}  ScanApprovalRequestResponse
// @Failure      403   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Failure      409   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scan-approvals/{id}/approve [post]
func (h *ScanApprovalHandler) Approve(w http.ResponseWriter, r *http.Request) {
	h.decide(w, r, h.svc.Approve)
}

// Reject handles POST /api/v1/scan-approvals/{id}/reject.
// @Summary      Reject a scan approval request
// @Tags         Scans
// @Accept       json
// @Produce      json
// @Param        id    path      string                       true  "Request ID"
// @Param        body  body      ScanApprovalDecisionRequest  true  "Note"
// @Success      200   {object}  ScanApprovalRequestResponse
// @Failure      403   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scan-approvals/{id}/reject [post]
func (h *ScanApprovalHandler) Reject(w http.ResponseWriter, r *http.Request) {
	h.decide(w, r, h.svc.Reject)
}

func (h *ScanApprovalHandler) decide(w http.ResponseWriter, r *http.Request,
	fn func(ctx context.Context, tenantID, id shared.ID, note string, actor scangovapp.Actor) (*scangov.Request, error),
) {
	tid, id, ok := h.ids(w, r)
	if !ok {
		return
	}
	var req ScanApprovalDecisionRequest
	if !decodeGovernanceBody(w, r, &req) {
		return
	}
	q, err := fn(r.Context(), tid, id, req.Note, h.actor(r))
	if err != nil {
		h.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, h.requestResponse(r, q))
}

// SelfApprove handles POST /api/v1/scan-approvals/{id}/self-approve.
// @Summary      Approve your own scan (no other approver)
// @Description  An owner approves their own request when no other approver can give the remaining approvals, with a fresh authenticator code and a reason. Needs scans:approve. 403 SELF_APPROVAL_NOT_ALLOWED otherwise. Audited high; every administrator is told.
// @Tags         Scans
// @Accept       json
// @Produce      json
// @Param        id    path      string                   true  "Request ID"
// @Param        body  body      ScanSelfApprovalRequest  true  "Reason and code"
// @Success      200   {object}  ScanApprovalRequestResponse
// @Failure      403   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scan-approvals/{id}/self-approve [post]
func (h *ScanApprovalHandler) SelfApprove(w http.ResponseWriter, r *http.Request) {
	tid, id, ok := h.ids(w, r)
	if !ok {
		return
	}
	var req ScanSelfApprovalRequest
	if !decodeGovernanceBody(w, r, &req) {
		return
	}
	q, err := h.svc.SelfApprove(r.Context(), tid, id, req.Reason, req.TOTPCode, h.actor(r))
	if err != nil {
		h.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, h.requestResponse(r, q))
}

// Remind handles POST /api/v1/scan-approvals/{id}/remind.
// @Summary      Remind the approvers of a scan
// @Description  At most once an hour per request (429 REMINDER_TOO_SOON). Needs scans:write. Audited.
// @Tags         Scans
// @Produce      json
// @Param        id   path      string  true  "Request ID"
// @Success      200  {object}  ScanApprovalRequestResponse
// @Failure      429  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scan-approvals/{id}/remind [post]
func (h *ScanApprovalHandler) Remind(w http.ResponseWriter, r *http.Request) {
	tid, id, ok := h.ids(w, r)
	if !ok {
		return
	}
	q, _, err := h.svc.Remind(r.Context(), tid, id, h.actor(r))
	if err != nil {
		h.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, h.requestResponse(r, q))
}

// Cancel handles POST /api/v1/scan-approvals/{id}/cancel.
// @Summary      Withdraw your scan approval request
// @Tags         Scans
// @Produce      json
// @Param        id   path      string  true  "Request ID"
// @Success      200  {object}  ScanApprovalRequestResponse
// @Failure      403  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scan-approvals/{id}/cancel [post]
func (h *ScanApprovalHandler) Cancel(w http.ResponseWriter, r *http.Request) {
	tid, id, ok := h.ids(w, r)
	if !ok {
		return
	}
	q, err := h.svc.Cancel(r.Context(), tid, id, h.actor(r))
	if err != nil {
		h.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, h.requestResponse(r, q))
}

func userActor(id string) *ActorRef {
	if id == "" {
		return nil
	}
	return actorRef(id)
}

func (h *ScanApprovalHandler) requestResponse(r *http.Request, q *scangov.Request) *ScanApprovalRequestResponse {
	viewer := middleware.GetUserID(r.Context())
	out := &ScanApprovalRequestResponse{
		ID: q.ID.String(), ScanID: q.ScanID.String(), ScanName: q.ScanName, Status: string(q.Status), Digest: q.Digest,
		Definition: q.Definition, Changes: q.Changes, Evaluation: q.Evaluation, Justification: q.Justification,
		Ticket: q.Ticket, RunOnApproval: q.RunOnApproval, RequestedBy: userActor(q.RequestedBy), RequestedAt: q.RequestedAt,
		ExpiresAt: q.ExpiresAt, Remaining: q.Remaining(), ValidUntil: q.ValidUntil, DecidedAt: q.DecidedAt,
		DecidedBy: userActor(q.DecidedBy), DecisionNote: q.DecisionNote, RemindedAt: q.RemindedAt, Emergency: q.Emergency,
		Approvals: make([]ScanApprovalResponse, 0, len(q.Approvals)),
	}
	if out.Changes == nil {
		out.Changes = []scangov.Change{}
	}
	for _, a := range q.Approvals {
		out.Approvals = append(out.Approvals, ScanApprovalResponse{Approver: userActor(a.UserID), ApprovedAt: a.ApprovedAt,
			Note: a.Note, Self: a.Self, Emergency: a.Emergency})
	}
	if q.Status != scangov.StatusPending {
		return out
	}
	eligible, self, err := h.svc.Approvers(r.Context(), q, viewer)
	if err != nil {
		h.logger.Warn("scan approvers", "error", logger.SanitizeError(err))
		return out
	}
	out.EligibleApproverCount, out.SelfApprovalAvailable = len(eligible), self
	canApprove := middleware.HasPermission(r.Context(), permission.ScansApprove.String())
	showNames := middleware.HasPermission(r.Context(), permission.MembersRead.String())
	for _, a := range eligible {
		if a.UserID == viewer && canApprove {
			out.CanApprove = true
		}
		if showNames {
			out.EligibleApprovers = append(out.EligibleApprovers, ActorRef{Kind: ActorKindUser, ID: a.UserID, Name: a.Name})
		}
	}
	return out
}

func (h *ScanApprovalHandler) writeErr(w http.ResponseWriter, err error) {
	if writeStepUpError(w, err) {
		return
	}
	var de *shared.DomainError
	switch {
	case errors.As(err, &de) && de.Code != "":
		status := http.StatusBadRequest
		switch {
		case errors.Is(err, scangov.ErrReminderTooSoon):
			status = http.StatusTooManyRequests
		case errors.Is(err, shared.ErrForbidden):
			status = http.StatusForbidden
		case errors.Is(err, shared.ErrConflict):
			status = http.StatusConflict
		case errors.Is(err, shared.ErrNotFound):
			status = http.StatusNotFound
		}
		apierror.New(status, apierror.Code(de.Code), de.Message).WriteJSON(w)
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Scan approval").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	default:
		h.logger.Error("scan approval", "error", logger.SanitizeError(err))
		apierror.InternalServerError("could not handle the scan approval").WriteJSON(w)
	}
}

// latestStatuses answers the status of each scan's newest approval request
// (list badges); empty when not wired or unreadable (logged).
func (h *ScanApprovalHandler) latestStatuses(ctx context.Context, tenantID shared.ID, scans []*scan.Scan) map[shared.ID]string {
	out := map[shared.ID]string{}
	if h == nil || h.svc == nil {
		return out
	}
	latest, err := h.svc.LatestByScans(ctx, tenantID, scans)
	if err != nil {
		h.logger.Warn("scan approval badges", "error", logger.SanitizeError(err))
		return out
	}
	now := time.Now()
	for id, q := range latest {
		st := string(q.Status)
		if q.Status == scangov.StatusPending && !q.IsPending(now) {
			st = string(scangov.StatusExpired)
		}
		out[id] = st
	}
	return out
}
