package handler

// Who approves a pending scope entry, reminders, and an owner's own approval
// when no other approver exists (RFC-054 §7, amendment 2026-10-09).

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	auditsvc "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// ScopeApprovalStatusResponse says who can still approve a pending entry.
type ScopeApprovalStatusResponse struct {
	// Remaining approvals the entry needs before it authorizes anything.
	Remaining int `json:"remaining"`
	// EligibleApproverCount: members who may approve it (owners,
	// administrators and holders of attack_surface:scope:approve, except the
	// requester and those who already approved).
	EligibleApproverCount int `json:"eligible_approver_count"`
	// EligibleApprovers names them, only for a caller who may see the
	// organization's members (team:members:read); otherwise omitted.
	EligibleApprovers []ActorRef `json:"eligible_approvers,omitempty"`
	// SelfApprovalAvailable: the caller may approve their own entry (they
	// requested it, are an owner, and no other approver can).
	SelfApprovalAvailable bool `json:"self_approval_available"`
	// RemindedAt: when the approvers were last reminded; CanRemindAt: the
	// earliest next reminder.
	RemindedAt  *time.Time `json:"reminded_at,omitempty"`
	CanRemindAt *time.Time `json:"can_remind_at,omitempty"`
}

// addApprovalStatus sets Approval on the pending entries of outs (outs[i]
// is the response for targets[i]). A directory failure leaves the field
// unset and is logged: the entry itself is still answered.
func (h *ScopeHandler) addApprovalStatus(r *http.Request, outs []*ScopeTargetResponse, targets []*scopedom.Target) {
	ctx := r.Context()
	tid, err := shared.IDFromString(middleware.MustGetTenantID(ctx))
	if err != nil {
		return
	}
	statuses, err := h.service.ApprovalStatuses(ctx, tid, targets, scopeActor(r))
	if err != nil {
		h.logger.Warn("scope approvers: status", "error", logger.SanitizeError(err))
		return
	}
	if len(statuses) == 0 {
		return
	}
	showNames := middleware.HasPermission(ctx, permission.MembersRead.String())
	for i, t := range targets {
		st, ok := statuses[t.ID().String()]
		if !ok || i >= len(outs) {
			continue
		}
		resp := &ScopeApprovalStatusResponse{
			Remaining: st.Remaining, EligibleApproverCount: len(st.Eligible),
			SelfApprovalAvailable: st.SelfApprovalAvailable, RemindedAt: t.RemindedAt(),
		}
		if at := t.RemindedAt(); at != nil {
			next := at.Add(scopedom.ReminderInterval)
			if next.After(time.Now()) {
				resp.CanRemindAt = &next
			}
		}
		if showNames {
			resp.EligibleApprovers = make([]ActorRef, 0, len(st.Eligible))
			for _, a := range st.Eligible {
				resp.EligibleApprovers = append(resp.EligibleApprovers, ActorRef{Kind: ActorKindUser, ID: a.UserID, Name: a.Name})
			}
		}
		outs[i].Approval = resp
	}
}

// SelfApproveScopeTargetRequest is an owner's approval of their own entry.
type SelfApproveScopeTargetRequest struct {
	// Reason is why the entry may take effect without a second person.
	Reason string `json:"reason" validate:"required,max=1000"`
	// TOTPCode is a fresh code from the caller's authenticator app.
	TOTPCode string `json:"totp_code" validate:"required,max=16"`
}

// SelfApproveTarget handles POST /api/v1/scope/targets/{id}/self-approve
// @Summary      Approve your own scope entry (no other approver)
// @Description  An owner puts their own pending scope entry into effect when no other member can approve it (RFC-054 §7). Needs attack_surface:scope:approve, the owner role, a fresh code from the caller's authenticator app (totp_code) and a reason. Refused with 403 SELF_APPROVAL_NOT_ALLOWED while another approver exists, SELF_APPROVAL_NEEDS_TOTP without an authenticator, SELF_APPROVAL_INVALID_CODE for a wrong or reused code. Audited at high severity; every administrator and the organization's channels are told.
// @Tags         Scope
// @Accept       json
// @Produce      json
// @Param        id    path      string                         true  "Target ID"
// @Param        body  body      SelfApproveScopeTargetRequest  true  "Reason and code"
// @Success      200   {object}  ScopeTargetResponse
// @Failure      400   {object}  apierror.Error
// @Failure      403   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Failure      409   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scope/targets/{id}/self-approve [post]
func (h *ScopeHandler) SelfApproveTarget(w http.ResponseWriter, r *http.Request) {
	targetID := chi.URLParam(r, "id")
	tenantID := middleware.MustGetTenantID(r.Context())
	var req SelfApproveScopeTargetRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req); err != nil {
		apierror.BadRequest("Invalid JSON").WriteJSON(w)
		return
	}
	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}
	before, ok := h.targetBefore(w, r, tenantID, targetID)
	if !ok {
		return
	}
	target, err := h.service.SelfApproveTarget(r.Context(), targetID, tenantID, scopeActor(r), req.Reason, req.TOTPCode)
	if err != nil {
		h.handleServiceError(w, "Scope target", err)
		return
	}
	h.auditSelfApproval(r, before, target, strings.TrimSpace(req.Reason))
	h.discover(tenantID, target)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(h.joinedOut(r, target))
}

// auditSelfApproval records the self-approval at high severity with the
// reason, and the state before and after.
func (h *ScopeHandler) auditSelfApproval(r *http.Request, before, after *scopedom.Target, reason string) {
	changes := audit.NewChanges()
	changes.Before, changes.After = auditSnapshot(toScopeTargetResponse(before)), auditSnapshot(toScopeTargetResponse(after))
	event := auditsvc.NewSuccessEvent(audit.ActionScopeTargetSelfApproved, audit.ResourceTypeScopeTarget, after.ID().String()).
		WithResourceName(after.Pattern()).
		WithChanges(changes).
		WithSeverity(audit.SeverityHigh).
		WithMessage("Scope entry approved by its own requester: no other approver exists").
		WithMetadata("reason", reason).
		WithMetadata("second_factor", "totp")
	logRequestChange(h.audit, h.logger, r, event)
}

// RemindApproversResponse is the result of a reminder.
type RemindApproversResponse struct {
	// Reminded: how many approvers were reminded.
	Reminded   int        `json:"reminded"`
	RemindedAt *time.Time `json:"reminded_at"`
	// CanRemindAt: the earliest next reminder.
	CanRemindAt time.Time `json:"can_remind_at"`
}

// RemindApprovers handles POST /api/v1/scope/targets/{id}/remind
// @Summary      Remind the approvers of a pending scope entry
// @Description  Sends the approval request again to everyone who can still approve the entry (in-app, email and the organization's channels). Needs attack_surface:scope:write; at most once per hour per entry (429 REMINDER_TOO_SOON). Audited.
// @Tags         Scope
// @Produce      json
// @Param        id   path      string  true  "Target ID"
// @Success      200  {object}  RemindApproversResponse
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Failure      429  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scope/targets/{id}/remind [post]
func (h *ScopeHandler) RemindApprovers(w http.ResponseWriter, r *http.Request) {
	targetID := chi.URLParam(r, "id")
	tenantID := middleware.MustGetTenantID(r.Context())
	target, n, err := h.service.RemindApprovers(r.Context(), targetID, tenantID, scopeActor(r))
	if err != nil {
		h.handleServiceError(w, "Scope target", err)
		return
	}
	event := auditsvc.NewSuccessEvent(audit.ActionScopeTargetApproversReminded, audit.ResourceTypeScopeTarget, target.ID().String()).
		WithResourceName(target.Pattern()).
		WithMessage("Approvers of a pending scope entry reminded").
		WithMetadata("reminded", n)
	logRequestChange(h.audit, h.logger, r, event)
	resp := RemindApproversResponse{Reminded: n, RemindedAt: target.RemindedAt()}
	if at := target.RemindedAt(); at != nil {
		resp.CanRemindAt = at.Add(scopedom.ReminderInterval)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// ScopeAttestationResponse is the attestation state of an active t2 entry
// (RFC-054 §12.5).
type ScopeAttestationResponse struct {
	// DueAt: when the next confirmation falls due (null: the entry expires
	// first and needs none).
	DueAt *time.Time `json:"due_at,omitempty"`
	// RequestedAt: an open request; DowngradeAt: when the entry falls back to
	// t1 without a confirmation.
	RequestedAt *time.Time `json:"requested_at,omitempty"`
	DowngradeAt *time.Time `json:"downgrade_at,omitempty"`
	// AttestedAt and AttestedBy: the last confirmation.
	AttestedAt *time.Time `json:"attested_at,omitempty"`
	AttestedBy *ActorRef  `json:"attested_by,omitempty"`
}

// addAttestationStatus sets Attestation on the active t2 entries of outs.
func (h *ScopeHandler) addAttestationStatus(r *http.Request, outs []*ScopeTargetResponse, targets []*scopedom.Target) {
	var interval time.Duration
	loaded := false
	refs := []*ActorRef{}
	for i, t := range targets {
		if i >= len(outs) || t.MaxTier() != scopedom.TierIntrusive || t.Status() != scopedom.StatusActive {
			continue
		}
		if !loaded {
			d, err := h.service.AttestationInterval(r.Context(), middleware.MustGetTenantID(r.Context()))
			if err != nil {
				h.logger.Warn("scope attestation: interval", "error", logger.SanitizeError(err))
				return
			}
			interval, loaded = d, true
		}
		a := &ScopeAttestationResponse{
			DueAt: t.AttestationDueAt(interval), RequestedAt: t.AttestationRequestedAt(),
			DowngradeAt: t.DowngradeAt(), AttestedAt: t.AttestedAt(), AttestedBy: actorRef(t.AttestedBy()),
		}
		if a.DueAt == nil && a.RequestedAt == nil && a.AttestedAt == nil {
			continue
		}
		refs = append(refs, a.AttestedBy)
		outs[i].Attestation = a
	}
	if len(refs) > 0 {
		resolveActors(r.Context(), h.actors, h.logger, middleware.MustGetTenantID(r.Context()), refs)
	}
}

// AttestTarget handles POST /api/v1/scope/targets/{id}/attest
// @Summary      Keep an intrusive (t2) scope entry
// @Description  Confirms that an active t2 entry should keep intrusive probes and starts its next attestation period (RFC-054 §12.5). Without a confirmation within 14 days of a request the entry falls back to t1. Needs attack_surface:scope:approve; one click (it widens nothing). Audited.
// @Tags         Scope
// @Produce      json
// @Param        id   path      string  true  "Target ID"
// @Success      200  {object}  ScopeTargetResponse
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scope/targets/{id}/attest [post]
func (h *ScopeHandler) AttestTarget(w http.ResponseWriter, r *http.Request) {
	targetID := chi.URLParam(r, "id")
	tenantID := middleware.MustGetTenantID(r.Context())
	before, ok := h.targetBefore(w, r, tenantID, targetID)
	if !ok {
		return
	}
	target, err := h.service.AttestTarget(r.Context(), targetID, tenantID, scopeActor(r))
	if err != nil {
		h.handleServiceError(w, "Scope target", err)
		return
	}
	h.auditTarget(r, audit.ActionScopeTargetAttested, targetID, before, target)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(h.targetOut(r, target))
}
