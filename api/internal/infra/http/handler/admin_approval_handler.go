package handler

// Security > Approvals: four-eyes approvals for the console's catastrophic
// actions (docs/architecture/platform-console.md, "Four-eyes approvals").
// Super admin only; requesting takes a step-up and approving a fresh one
// (route layer). The protected handlers call requireSecondApproval.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/app/adminapproval"
	"github.com/openctemio/openctem/api/internal/app/adminconsole"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// CodeSecondApprovalRequired is the 428 error code of a protected action that
// needs another super admin's approval first. Its details name the action, the
// target and the caller's open request, if any.
const CodeSecondApprovalRequired apierror.Code = "SECOND_APPROVAL_REQUIRED"

// approvalGate is the four-eyes gate of a protected action.
type approvalGate interface {
	Require(ctx context.Context, actor *admin.AdminUser, action admin.ApprovalAction, target string, client adminconsole.ClientInfo) (*adminapproval.Grant, error)
	Release(ctx context.Context, actor *admin.AdminUser, g *adminapproval.Grant, client adminconsole.ClientInfo)
}

// SecondApprovalDetails are the details of a SECOND_APPROVAL_REQUIRED refusal.
type SecondApprovalDetails struct {
	Action            string `json:"action"`
	Target            string `json:"target"`
	TargetLabel       string `json:"target_label,omitempty"`
	PendingApprovalID string `json:"pending_approval_id,omitempty"`
}

// requireSecondApproval runs the four-eyes gate. It writes the refusal and
// returns ok=false when the action must not run. A nil gate (tests that do not
// wire approvals) allows; the server always wires it.
func requireSecondApproval(w http.ResponseWriter, r *http.Request, gate approvalGate, actor *admin.AdminUser,
	action admin.ApprovalAction, target string, log *logger.Logger) (*adminapproval.Grant, bool) {
	if gate == nil {
		return nil, true
	}
	g, err := gate.Require(r.Context(), actor, action, target, clientInfo(r))
	if err == nil {
		return g, true
	}
	var required *admin.ApprovalRequiredError
	if errors.As(err, &required) {
		d := SecondApprovalDetails{Action: string(required.Action), Target: required.Target, TargetLabel: required.TargetLabel}
		if required.PendingID != nil {
			d.PendingApprovalID = required.PendingID.String()
		}
		apierror.New(http.StatusPreconditionRequired, CodeSecondApprovalRequired,
			"Another super admin must approve this change first.").WithDetails(d).WriteJSON(w)
		return nil, false
	}
	log.Error("four-eyes approval check", "action", string(action), "error", sanitizeLogField(err.Error()))
	apierror.ServiceUnavailable("The approval check could not run, so the change was not made. Try again.").WriteJSON(w)
	return nil, false
}

// releaseSecondApproval hands a spent approval back after the action failed.
func releaseSecondApproval(r *http.Request, gate approvalGate, actor *admin.AdminUser, g *adminapproval.Grant) {
	if gate != nil && g != nil {
		gate.Release(r.Context(), actor, g, clientInfo(r))
	}
}

// AdminApprovalHandler serves /api/v1/admin/approvals.
type AdminApprovalHandler struct {
	svc    *adminapproval.Service
	logger *logger.Logger
}

// NewAdminApprovalHandler creates the handler.
func NewAdminApprovalHandler(svc *adminapproval.Service, log *logger.Logger) *AdminApprovalHandler {
	return &AdminApprovalHandler{svc: svc, logger: log.With("handler", "admin_approval")}
}

// AdminApprovalResponse is one approval request.
type AdminApprovalResponse struct {
	ID               string     `json:"id"`
	Action           string     `json:"action"`
	Target           string     `json:"target"`
	TargetLabel      string     `json:"target_label,omitempty"`
	Reason           string     `json:"reason"`
	Status           string     `json:"status"`
	RequestedByID    string     `json:"requested_by_id"`
	RequestedByEmail string     `json:"requested_by_email,omitempty"`
	RequestedAt      time.Time  `json:"requested_at"`
	ExpiresAt        time.Time  `json:"expires_at"`
	DecidedByEmail   string     `json:"decided_by_email,omitempty"`
	DecidedAt        *time.Time `json:"decided_at,omitempty"`
	DecisionNote     string     `json:"decision_note,omitempty"`
	UsedAt           *time.Time `json:"used_at,omitempty"`
	// Mine: the caller asked (may cancel, never decide).
	Mine bool `json:"mine"`
}

// AdminApprovalListResponse is the Approvals page.
type AdminApprovalListResponse struct {
	FourEyes AdminFourEyesStatus     `json:"four_eyes"`
	TTLHours int                     `json:"ttl_hours"`
	Data     []AdminApprovalResponse `json:"data"`
}

// AdminFourEyesStatus says whether approvals are on for the caller.
type AdminFourEyesStatus struct {
	// Active: another super admin can approve the caller's requests.
	Active bool `json:"active"`
	// Approvers counts the active, named (not break-glass) super admins.
	Approvers int `json:"approvers"`
	// CanApprove: the caller may approve others' requests (not break-glass).
	CanApprove bool `json:"can_approve"`
}

// AdminApprovalRequest asks for an approval.
type AdminApprovalRequest struct {
	Action string `json:"action"`
	Target string `json:"target"`
	Reason string `json:"reason"`
}

// AdminApprovalDecisionRequest carries an optional note.
type AdminApprovalDecisionRequest struct {
	Note string `json:"note"`
}

func (h *AdminApprovalHandler) toResponse(a *admin.Approval, caller shared.ID, now time.Time) AdminApprovalResponse {
	return AdminApprovalResponse{
		ID: a.ID.String(), Action: string(a.Action), Target: a.Target, TargetLabel: a.TargetLabel,
		Reason: a.Reason, Status: a.Status(now), RequestedByID: a.RequestedBy.String(),
		RequestedByEmail: a.RequestedByEmail, RequestedAt: a.RequestedAt, ExpiresAt: a.ExpiresAt,
		DecidedByEmail: a.DecidedByEmail, DecidedAt: a.DecidedAt, DecisionNote: a.Note, UsedAt: a.ConsumedAt,
		Mine: a.RequestedBy == caller,
	}
}

// List handles GET /api/v1/admin/approvals.
// @Summary List four-eyes approval requests
// @Description Super admin only. Open requests and those of the last 30 days, newest first, and whether approvals are on (another active super admin who is not a break-glass account exists).
// @Tags Admin Approvals
// @Produce json
// @Success 200 {object} AdminApprovalListResponse
// @Security BearerAuth
// @Router /admin/approvals [get]
func (h *AdminApprovalHandler) List(w http.ResponseWriter, r *http.Request) {
	actor := middleware.MustGetAdminUser(r.Context())
	st, err := h.svc.Status(r.Context(), actor)
	if err != nil {
		h.logger.Error("four-eyes status", "error", sanitizeLogField(err.Error()))
		apierror.InternalError(err).WriteJSON(w)
		return
	}
	list, err := h.svc.List(r.Context())
	if err != nil {
		h.logger.Error("list approvals", "error", sanitizeLogField(err.Error()))
		apierror.InternalError(err).WriteJSON(w)
		return
	}
	now := h.svc.Now()
	resp := AdminApprovalListResponse{
		FourEyes: AdminFourEyesStatus{Active: st.Active, Approvers: st.Approvers,
			CanApprove: actor.IsActive() && actor.Role() == admin.AdminRoleSuperAdmin && !actor.IsBreakGlass()},
		TTLHours: int(admin.ApprovalTTL / time.Hour),
		Data:     make([]AdminApprovalResponse, 0, len(list)),
	}
	for _, a := range list {
		resp.Data = append(resp.Data, h.toResponse(a, actor.ID(), now))
	}
	writeJSON(w, http.StatusOK, resp)
}

// Create handles POST /api/v1/admin/approvals.
// @Summary Ask another super admin to approve a protected action
// @Description Super admin with a step-up. The action and its exact target come from the SECOND_APPROVAL_REQUIRED refusal of the protected action; a reason is required. One open request per action and target (an existing one is returned). Refused (409) when no other super admin can approve. Audited critical; the other administrators are e-mailed.
// @Tags Admin Approvals
// @Accept json
// @Produce json
// @Param request body AdminApprovalRequest true "Action, target and reason"
// @Success 201 {object} AdminApprovalResponse
// @Failure 400 {object} apierror.Error "Unknown action, bad target or no reason"
// @Failure 409 {object} apierror.Error "No other super admin can approve"
// @Security BearerAuth
// @Router /admin/approvals [post]
func (h *AdminApprovalHandler) Create(w http.ResponseWriter, r *http.Request) {
	actor := middleware.MustGetAdminUser(r.Context())
	var req AdminApprovalRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	a, err := h.svc.Request(r.Context(), actor, admin.ApprovalAction(strings.TrimSpace(req.Action)),
		strings.TrimSpace(req.Target), req.Reason, clientInfo(r))
	if err != nil {
		h.writeError(w, err, "request approval")
		return
	}
	writeJSON(w, http.StatusCreated, h.toResponse(a, actor.ID(), h.svc.Now()))
}

// Approve handles POST /api/v1/admin/approvals/{id}/approve.
// @Summary Approve another super admin's request
// @Description Super admin with a fresh step-up; never the requester, never a break-glass account. The requester then repeats the action within the request's 24 hours, once. Audited critical; the administrators are e-mailed.
// @Tags Admin Approvals
// @Accept json
// @Produce json
// @Param id path string true "Approval ID"
// @Param request body AdminApprovalDecisionRequest false "Optional note"
// @Success 200 {object} AdminApprovalResponse
// @Failure 403 {object} apierror.Error "Your own request, or a break-glass account"
// @Failure 404 {object} apierror.Error "Not Found"
// @Failure 409 {object} apierror.Error "No longer pending"
// @Security BearerAuth
// @Router /admin/approvals/{id}/approve [post]
func (h *AdminApprovalHandler) Approve(w http.ResponseWriter, r *http.Request) {
	h.decide(w, r, h.svc.Approve, "approve")
}

// Reject handles POST /api/v1/admin/approvals/{id}/reject.
// @Summary Reject another super admin's request
// @Description Super admin with a step-up; never the requester. Audited critical.
// @Tags Admin Approvals
// @Accept json
// @Produce json
// @Param id path string true "Approval ID"
// @Param request body AdminApprovalDecisionRequest false "Optional note"
// @Success 200 {object} AdminApprovalResponse
// @Failure 403 {object} apierror.Error "Your own request"
// @Failure 404 {object} apierror.Error "Not Found"
// @Failure 409 {object} apierror.Error "No longer pending"
// @Security BearerAuth
// @Router /admin/approvals/{id}/reject [post]
func (h *AdminApprovalHandler) Reject(w http.ResponseWriter, r *http.Request) {
	h.decide(w, r, h.svc.Reject, "reject")
}

// Cancel handles POST /api/v1/admin/approvals/{id}/cancel.
// @Summary Withdraw your own request
// @Description Super admin; only the requester. Audited critical.
// @Tags Admin Approvals
// @Produce json
// @Param id path string true "Approval ID"
// @Success 200 {object} AdminApprovalResponse
// @Failure 403 {object} apierror.Error "Not your request"
// @Failure 404 {object} apierror.Error "Not Found"
// @Failure 409 {object} apierror.Error "No longer pending"
// @Security BearerAuth
// @Router /admin/approvals/{id}/cancel [post]
func (h *AdminApprovalHandler) Cancel(w http.ResponseWriter, r *http.Request) {
	h.decide(w, r, func(ctx context.Context, a *admin.AdminUser, id shared.ID, _ string, c adminconsole.ClientInfo) (*admin.Approval, error) {
		return h.svc.Cancel(ctx, a, id, c)
	}, "cancel")
}

type approvalDecision func(ctx context.Context, actor *admin.AdminUser, id shared.ID, note string, client adminconsole.ClientInfo) (*admin.Approval, error)

func (h *AdminApprovalHandler) decide(w http.ResponseWriter, r *http.Request, fn approvalDecision, what string) {
	actor := middleware.MustGetAdminUser(r.Context())
	id, err := shared.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		apierror.BadRequest("invalid approval id").WriteJSON(w)
		return
	}
	var req AdminApprovalDecisionRequest
	if r.ContentLength != 0 {
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req); err != nil {
			apierror.BadRequest("invalid request body").WriteJSON(w)
			return
		}
	}
	a, err := fn(r.Context(), actor, id, req.Note, clientInfo(r))
	if err != nil {
		h.writeError(w, err, what+" approval")
		return
	}
	writeJSON(w, http.StatusOK, h.toResponse(a, actor.ID(), h.svc.Now()))
}

func (h *AdminApprovalHandler) writeError(w http.ResponseWriter, err error, what string) {
	switch {
	case errors.Is(err, admin.ErrApprovalNotFound):
		apierror.NotFound("approval").WriteJSON(w)
	case errors.Is(err, admin.ErrSelfApproval):
		apierror.Forbidden("Another super admin must decide on your request.").WriteJSON(w)
	case errors.Is(err, admin.ErrApproverNotEligible):
		apierror.Forbidden("Only an active super admin who is not a break-glass account can approve.").WriteJSON(w)
	case errors.Is(err, admin.ErrNotRequester):
		apierror.Forbidden("Only the administrator who asked can cancel this request.").WriteJSON(w)
	case errors.Is(err, admin.ErrApprovalNotPending):
		apierror.Conflict("This request is no longer pending.").WriteJSON(w)
	case errors.Is(err, admin.ErrFourEyesInactive):
		apierror.Conflict("No other super admin can approve, so the action runs on your confirmation alone.").WriteJSON(w)
	case errors.Is(err, admin.ErrInvalidApproval):
		apierror.BadRequest("Give a known action, its exact target and a reason (at most 1000 characters).").WriteJSON(w)
	default:
		h.logger.Error(what, "error", sanitizeLogField(err.Error()))
		apierror.ServiceUnavailable("The request could not be recorded in the audit log, so nothing changed. Try again.").WriteJSON(w)
	}
}
