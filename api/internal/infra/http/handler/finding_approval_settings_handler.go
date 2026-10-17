package handler

// Finding approval settings and the sole member's self-approval
// (api/docs/architecture/finding-status-lifecycle.md, "Approvals").

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/approvalpolicy"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// FindingApprovalSettingsService reads and writes the organization's
// finding approval settings (*tenant.TenantService).
type FindingApprovalSettingsService interface {
	GetFindingApprovalSettings(ctx context.Context, tenantID string) (*tenantdom.FindingApprovalSettings, error)
	UpdateFindingApprovalSettings(ctx context.Context, tenantID string, change func(*tenantdom.FindingApprovalSettings) error,
		actx auditapp.AuditContext) (before, after *tenantdom.FindingApprovalSettings, err error)
}

// SetFindingApprovalSettings wires the settings routes (nil: 404).
func (h *VulnerabilityHandler) SetFindingApprovalSettings(svc FindingApprovalSettingsService) {
	h.approvalSettings = svc
}

// SelfApproveRequest is the body of POST /approvals/{id}/self-approve.
type SelfApproveRequest struct {
	Reason string `json:"reason" validate:"required,min=1,max=2000"`
	Code   string `json:"code" validate:"required,min=6,max=8"`
}

// SelfApproveResponse is the approved request; end_shortened tells that the
// acceptance end was brought forward to the self-approval limit.
type SelfApproveResponse struct {
	ApprovalResponse
	EndShortened bool `json:"end_shortened"`
}

// SelfApproveApproval handles POST /approvals/{id}/self-approve: the sole
// active member of the organization, an owner, approves their own request
// with a fresh authenticator code and a reason. Every refusal is audited.
// @Summary      Approve your own request as the sole member
// @Description  The owner of an organization with exactly one active person approves their own pending finding request with a fresh authenticator code and a reason. Refused when another member is active or one was suspended or removed in the last 7 days. An accepted risk is shortened to the self-approval limit. Requires findings:approve.
// @Tags         Findings
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id    path      string              true  "Approval ID"
// @Param        body  body      SelfApproveRequest  true  "Reason and authenticator code"
// @Success      200   {object}  SelfApproveResponse
// @Failure      403   {object}  map[string]string
// @Failure      404   {object}  map[string]string
// @Router       /approvals/{id}/self-approve [post]
func (h *VulnerabilityHandler) SelfApproveApproval(w http.ResponseWriter, r *http.Request) {
	approvalID := r.PathValue("id")
	var req SelfApproveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}
	res, err := h.service.SelfApproveSolo(r.Context(), finding.SelfApproveInput{
		TenantID:   middleware.GetTenantID(r.Context()),
		ApprovalID: approvalID,
		UserID:     middleware.GetUserID(r.Context()),
		Reason:     req.Reason,
		Code:       req.Code,
	})
	if err != nil {
		var de *shared.DomainError
		if errors.As(err, &de) && (errors.Is(err, shared.ErrForbidden) || errors.Is(err, vulnerability.ErrSoloApprovalNeedsReason)) {
			h.auditApproval(r, auditapp.NewDeniedEvent(auditdom.ActionFindingApprovalSelfRefused, auditdom.ResourceTypeFindingApproval, approvalID, de.Code).
				WithSeverity(auditdom.SeverityHigh).
				WithMessage("Refused: a sole-member self-approval did not meet its conditions ("+de.Code+")"), nil)
		}
		h.handleServiceError(w, err, "self-approve approval")
		return
	}
	a := res.Approval
	h.auditApproval(r, auditapp.NewSuccessEvent(auditdom.ActionFindingApprovalSelfApproved, auditdom.ResourceTypeFindingApproval, a.ID.String()).
		WithSeverity(auditdom.SeverityHigh).
		WithMetadata("reason", a.SelfApprovalReason).
		WithMetadata("end_shortened", res.EndShortened).
		WithMessage(fmt.Sprintf("The sole member approved their own %s request (authenticator code and reason)", a.RequestedStatus)), a)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(SelfApproveResponse{ApprovalResponse: toApprovalResponse(a), EndShortened: res.EndShortened})
}

// FindingApprovalSettingsResponse is the organization's finding approval
// settings.
type FindingApprovalSettingsResponse struct {
	BackupContactEmail string `json:"backup_contact_email"`
	// FPApproval is the false-positive approval level in force: all,
	// high_and_above or off.
	FPApproval string `json:"fp_approval" enums:"all,high_and_above,off"`
	// PendingFPApproval is a lower level that takes effect at
	// PendingFPApprovalAt (a lowering waits 24 hours).
	PendingFPApproval   string  `json:"pending_fp_approval,omitempty"`
	PendingFPApprovalAt *string `json:"pending_fp_approval_at,omitempty"`
	SecondLookPercent   int     `json:"second_look_percent"`
	// PendingSecondLookPercent is a lower share that takes effect at
	// PendingSecondLookAt (a lowering waits 24 hours).
	PendingSecondLookPercent *int    `json:"pending_second_look_percent,omitempty"`
	PendingSecondLookAt      *string `json:"pending_second_look_at,omitempty"`
	// Policy is the approval policy in force (RFC-111); PendingPolicy a
	// relaxing change that takes effect at PendingPolicyAt.
	Policy          ApprovalPolicyDTO  `json:"policy"`
	PendingPolicy   *ApprovalPolicyDTO `json:"pending_policy,omitempty"`
	PendingPolicyAt *string            `json:"pending_policy_at,omitempty"`
	// Floors and Defaults are the platform's tier per "<kind>.<class>" (for
	// the editor: a cell may not go below its floor).
	Floors   map[string]string `json:"floors"`
	Defaults map[string]string `json:"defaults"`
}

// ApprovalPolicyDTO is an organization's approval policy on the wire.
type ApprovalPolicyDTO struct {
	// Tiers sets a tier per "<kind>.<class>", e.g. "accepted.high": "dual".
	Tiers               map[string]string `json:"tiers,omitempty"`
	SecurityPoolGroupID string            `json:"security_pool_group_id,omitempty"`
	SecurityPoolStrict  bool              `json:"security_pool_strict"`
	ExcludeAssignee     bool              `json:"exclude_assignee"`
	StepUpAllTiers      bool              `json:"step_up_all_tiers"`
	// MaxAcceptanceDays caps an accepted risk per class (standard, high,
	// critical), below the platform cap.
	MaxAcceptanceDays map[string]int `json:"max_acceptance_days,omitempty"`
	DecideWithinDays  int            `json:"decide_within_days,omitempty"`
	EPSSThreshold     float64        `json:"epss_threshold,omitempty"`
	// OnMaterialChange: accepted end_on_tier_rise | end_on_any_change;
	// single_person_fp flag | revoke.
	OnMaterialChangeAccepted       string `json:"on_material_change_accepted,omitempty" enums:"end_on_tier_rise,end_on_any_change"`
	OnMaterialChangeSinglePersonFP string `json:"on_material_change_single_person_fp,omitempty" enums:"flag,revoke"`
}

func toApprovalPolicyDTO(p approvalpolicy.Policy) ApprovalPolicyDTO {
	out := ApprovalPolicyDTO{
		SecurityPoolGroupID: p.SecurityPoolGroupID, SecurityPoolStrict: p.SecurityPoolStrict,
		ExcludeAssignee: p.ExcludeAssignee, StepUpAllTiers: p.StepUpAllTiers,
		DecideWithinDays: p.DecideWithinDays, EPSSThreshold: p.EPSSThreshold,
		OnMaterialChangeAccepted:       p.OnMaterialChange.Accepted,
		OnMaterialChangeSinglePersonFP: p.OnMaterialChange.SinglePersonFP,
	}
	if out.OnMaterialChangeAccepted == "" {
		out.OnMaterialChangeAccepted = approvalpolicy.AcceptedEndOnTierRise
	}
	if out.OnMaterialChangeSinglePersonFP == "" {
		out.OnMaterialChangeSinglePersonFP = approvalpolicy.SinglePersonFPFlag
	}
	for k, t := range p.Tiers {
		if out.Tiers == nil {
			out.Tiers = map[string]string{}
		}
		out.Tiers[k] = string(t)
	}
	for c, d := range p.MaxAcceptanceDays {
		if out.MaxAcceptanceDays == nil {
			out.MaxAcceptanceDays = map[string]int{}
		}
		out.MaxAcceptanceDays[string(c)] = d
	}
	return out
}

func (d ApprovalPolicyDTO) toPolicy() approvalpolicy.Policy {
	p := approvalpolicy.Policy{
		SecurityPoolGroupID: d.SecurityPoolGroupID, SecurityPoolStrict: d.SecurityPoolStrict,
		ExcludeAssignee: d.ExcludeAssignee, StepUpAllTiers: d.StepUpAllTiers,
		DecideWithinDays: d.DecideWithinDays, EPSSThreshold: d.EPSSThreshold,
		OnMaterialChange: approvalpolicy.MaterialChangePolicy{
			Accepted: d.OnMaterialChangeAccepted, SinglePersonFP: d.OnMaterialChangeSinglePersonFP,
		},
	}
	for k, t := range d.Tiers {
		if p.Tiers == nil {
			p.Tiers = map[string]approvalpolicy.Tier{}
		}
		p.Tiers[k] = approvalpolicy.Tier(t)
	}
	for c, n := range d.MaxAcceptanceDays {
		if p.MaxAcceptanceDays == nil {
			p.MaxAcceptanceDays = map[approvalpolicy.Class]int{}
		}
		p.MaxAcceptanceDays[approvalpolicy.Class(c)] = n
	}
	return p
}

// platformTierTables are the floors and defaults per "<kind>.<class>".
func platformTierTables() (floors, defaults map[string]string) {
	floors, defaults = map[string]string{}, map[string]string{}
	for _, k := range approvalpolicy.Kinds {
		for _, c := range approvalpolicy.Classes {
			key := string(k) + "." + string(c)
			floors[key] = string(approvalpolicy.Floor(k, c))
			defaults[key] = string(approvalpolicy.Default(k, c))
		}
	}
	return floors, defaults
}

func toFindingApprovalSettingsResponse(s *tenantdom.FindingApprovalSettings) FindingApprovalSettingsResponse {
	now := time.Now()
	out := FindingApprovalSettingsResponse{
		BackupContactEmail: s.BackupContactEmail,
		FPApproval:         s.EffectiveFPApproval(now),
		SecondLookPercent:  s.EffectiveSecondLookPercent(now),
	}
	if s.PendingSecondLookPercent != nil && s.PendingSecondLookAt != nil && now.Before(*s.PendingSecondLookAt) {
		at := s.PendingSecondLookAt.UTC().Format(time.RFC3339)
		out.PendingSecondLookPercent, out.PendingSecondLookAt = s.PendingSecondLookPercent, &at
	}
	if s.PendingFPApproval != "" && s.PendingFPApprovalAt != nil && now.Before(*s.PendingFPApprovalAt) {
		at := s.PendingFPApprovalAt.UTC().Format(time.RFC3339)
		out.PendingFPApproval, out.PendingFPApprovalAt = s.PendingFPApproval, &at
	}
	out.Policy = toApprovalPolicyDTO(s.EffectivePolicy(now))
	if s.PendingPolicy != nil && s.PendingPolicyAt != nil && now.Before(*s.PendingPolicyAt) {
		pending := toApprovalPolicyDTO(*s.PendingPolicy)
		at := s.PendingPolicyAt.UTC().Format(time.RFC3339)
		out.PendingPolicy, out.PendingPolicyAt = &pending, &at
	}
	out.Floors, out.Defaults = platformTierTables()
	return out
}

// GetFindingApprovalSettings handles GET /organization/settings/finding-approvals.
// @Summary      Finding approval settings
// @Description  The organization's finding approval settings. Requires findings:read.
// @Tags         Findings
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  FindingApprovalSettingsResponse
// @Router       /organization/settings/finding-approvals [get]
func (h *VulnerabilityHandler) GetFindingApprovalSettings(w http.ResponseWriter, r *http.Request) {
	if h.approvalSettings == nil {
		apierror.NotFound("finding approval settings").WriteJSON(w)
		return
	}
	s, err := h.approvalSettings.GetFindingApprovalSettings(r.Context(), middleware.GetTenantID(r.Context()))
	if err != nil {
		h.handleServiceError(w, err, "finding approval settings")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toFindingApprovalSettingsResponse(s))
}

// UpdateFindingApprovalSettingsRequest is a partial update: a nil field
// keeps its value.
type UpdateFindingApprovalSettingsRequest struct {
	BackupContactEmail *string `json:"backup_contact_email" validate:"omitempty,max=254"`
	// FPApproval: all, high_and_above or off. A lower level than the one in
	// force takes effect 24 hours later; a higher one at once.
	FPApproval        *string `json:"fp_approval" validate:"omitempty,oneof=all high_and_above off"`
	SecondLookPercent *int    `json:"second_look_percent" validate:"omitempty,min=0,max=10"`
	// Policy replaces the approval policy. A change that relaxes anything
	// takes effect 24 hours later (the stricter of both applies meanwhile).
	Policy *ApprovalPolicyDTO `json:"policy"`
	// CancelPending drops the waiting lowerings (false-positive level,
	// second look share, relaxing policy) and keeps the values in force. It
	// is applied before the other fields.
	CancelPending bool `json:"cancel_pending"`
}

// UpdateFindingApprovalSettings handles PUT /organization/settings/finding-approvals
// (settings:write and a recent re-authentication). The change is audited
// with the values before and after, and the organization's approvers are
// told.
// @Summary      Change the finding approval settings
// @Description  Partial update of the organization's finding approval settings. Requires settings:write and a recent re-authentication; audited, approvers told.
// @Tags         Findings
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body  body      UpdateFindingApprovalSettingsRequest  true  "Fields to change"
// @Success      200   {object}  FindingApprovalSettingsResponse
// @Failure      403   {object}  map[string]string
// @Router       /organization/settings/finding-approvals [put]
func (h *VulnerabilityHandler) UpdateFindingApprovalSettings(w http.ResponseWriter, r *http.Request) {
	if h.approvalSettings == nil {
		apierror.NotFound("finding approval settings").WriteJSON(w)
		return
	}
	var req UpdateFindingApprovalSettingsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}
	tenantID := middleware.GetTenantID(r.Context())
	if req.Policy != nil {
		// The security pool must be a group of this organization.
		if err := h.service.ValidateSecurityPoolGroup(r.Context(), tenantID, req.Policy.SecurityPoolGroupID); err != nil {
			h.handleServiceError(w, err, "finding approval settings")
			return
		}
	}
	before, after, err := h.approvalSettings.UpdateFindingApprovalSettings(r.Context(), tenantID, func(s *tenantdom.FindingApprovalSettings) error {
		if req.CancelPending {
			s.CancelPending(time.Now())
		}
		if req.Policy != nil {
			if _, err := s.SetPolicy(req.Policy.toPolicy(), time.Now()); err != nil {
				return err
			}
		}
		if req.BackupContactEmail != nil {
			s.BackupContactEmail = *req.BackupContactEmail
		}
		if req.FPApproval != nil {
			if err := s.SetFPApproval(*req.FPApproval, time.Now()); err != nil {
				return err
			}
		}
		if req.SecondLookPercent != nil {
			if err := s.SetSecondLookPercent(*req.SecondLookPercent, time.Now()); err != nil {
				return err
			}
		}
		return nil
	}, configAuditContext(r))
	if err != nil {
		h.handleServiceError(w, err, "finding approval settings")
		return
	}
	body := "An administrator changed how this organization approves finding decisions. Review the change in Settings."
	resp := toFindingApprovalSettingsResponse(after)
	if resp.PendingFPApproval != "" && resp.PendingFPApproval != toFindingApprovalSettingsResponse(before).PendingFPApproval {
		body = fmt.Sprintf("An administrator lowered the false-positive approval level to %q. It takes effect at %s unless it is raised again before then.",
			resp.PendingFPApproval, *resp.PendingFPApprovalAt)
	}
	if resp.PendingPolicyAt != nil && (toFindingApprovalSettingsResponse(before).PendingPolicyAt == nil ||
		*toFindingApprovalSettingsResponse(before).PendingPolicyAt != *resp.PendingPolicyAt) {
		body = fmt.Sprintf("An administrator relaxed the approval policy. The change takes effect at %s unless it is reverted before then; until then the stricter rules apply.",
			*resp.PendingPolicyAt)
	}
	h.service.NotifyApprovalSettingsChanged(r.Context(), tenantID, middleware.GetUserID(r.Context()),
		"Finding approval settings changed", body)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// FalsePositivePolicyResponse is how a false positive on one finding is
// decided now.
type FalsePositivePolicyResponse struct {
	FPApproval string `json:"fp_approval"`
	// SinglePerson: a holder of findings:approve may mark this finding a
	// false positive alone (it applies at once, a closure reason and a note
	// still required). CanDecideAlone adds that the caller holds it.
	SinglePerson        bool    `json:"single_person"`
	CanDecideAlone      bool    `json:"can_decide_alone"`
	Material            bool    `json:"material"`
	PendingFPApproval   string  `json:"pending_fp_approval,omitempty"`
	PendingFPApprovalAt *string `json:"pending_fp_approval_at,omitempty"`
	// Evaluation is how a request of the asked status (?status=, default
	// false_positive) by the caller would be decided now.
	Evaluation *ApprovalEvaluationResponse `json:"evaluation,omitempty"`
}

// ApprovalEvaluationResponse is the approval policy's evaluation of one
// request: the tier and why, who may approve, how long.
type ApprovalEvaluationResponse struct {
	Kind              string   `json:"kind"`
	Tier              string   `json:"tier" enums:"single,peer,security,dual"`
	Floor             string   `json:"floor"`
	RiskClass         string   `json:"risk_class" enums:"standard,high,critical"`
	ApprovalsRequired int      `json:"approvals_required"`
	Reasons           []string `json:"reasons"`
	// SecurityPool: a sign-off must come from the security pool;
	// SecurityPoolFallback: nobody there is eligible, the approver pool
	// stands in.
	SecurityPool         bool `json:"security_pool"`
	SecurityPoolFallback bool `json:"security_pool_fallback"`
	StepUp               bool `json:"step_up"`
	EligibleApprovers    int  `json:"eligible_approvers"`
	EligibleSecurityPool int  `json:"eligible_security_pool"`
	// Satisfiable: enough eligible people exist to complete the request.
	Satisfiable       bool `json:"satisfiable"`
	MinNoteLength     int  `json:"min_note_length"`
	MaxAcceptanceDays int  `json:"max_acceptance_days,omitempty"`
	DecideWithinDays  int  `json:"decide_within_days"`
	// CallerExcluded says why the caller could not approve such a request
	// of another person (asset_owner, assignee); empty when they could.
	CallerExcluded string `json:"caller_excluded,omitempty"`
}

// GetFalsePositivePolicy handles GET /findings/{id}/approvals/policy
// (findings:read; the finding must be in the caller's data scope).
// @Summary      How a false positive on a finding is decided
// @Description  Whether the organization's false-positive approval level lets one person mark this finding a false positive now, and whether the caller may. Requires findings:read and the finding in the caller's data scope.
// @Tags         Findings
// @Produce      json
// @Security     BearerAuth
// @Param        id      path      string  true   "Finding ID"
// @Param        status  query     string  false  "false_positive (default) or accepted"
// @Success      200  {object}  FalsePositivePolicyResponse
// @Failure      404  {object}  map[string]string
// @Router       /findings/{id}/approvals/policy [get]
func (h *VulnerabilityHandler) GetFalsePositivePolicy(w http.ResponseWriter, r *http.Request) {
	d, err := h.service.FalsePositivePolicy(r.Context(), middleware.GetTenantID(r.Context()), r.PathValue("id"))
	if err != nil {
		h.handleServiceError(w, err, "finding")
		return
	}
	out := FalsePositivePolicyResponse{
		FPApproval:     d.Level,
		SinglePerson:   d.SinglePerson,
		CanDecideAlone: d.SinglePerson && middleware.HasPermission(r.Context(), permission.FindingsApprove.String()),
		// CanDecideAlone is refined below from the evaluation (an asset owner
		// never decides alone).
		Material:          d.Material,
		PendingFPApproval: d.PendingLevel,
	}
	if d.PendingAt != nil {
		at := d.PendingAt.UTC().Format(time.RFC3339)
		out.PendingFPApprovalAt = &at
	}
	status := r.URL.Query().Get("status")
	if status == "" {
		status = string(vulnerability.FindingStatusFalsePositive)
	}
	canApprove := middleware.HasPermission(r.Context(), permission.FindingsApprove.String())
	v, err := h.service.FindingApprovalPolicy(r.Context(), middleware.GetTenantID(r.Context()), r.PathValue("id"),
		middleware.GetUserID(r.Context()), status, canApprove)
	if err != nil {
		h.handleServiceError(w, err, "finding")
		return
	}
	res := v.Result
	out.Evaluation = &ApprovalEvaluationResponse{
		Kind: string(res.Kind), Tier: string(res.Tier), Floor: string(res.Floor), RiskClass: string(res.Class),
		ApprovalsRequired: res.Required, Reasons: res.Reasons, SecurityPool: res.SecurityPool,
		SecurityPoolFallback: res.PoolFallback, StepUp: res.StepUp,
		EligibleApprovers: v.EligibleCount, EligibleSecurityPool: v.PoolCount, Satisfiable: res.Satisfiable(),
		MinNoteLength: res.MinNoteLength, MaxAcceptanceDays: v.MaxAcceptanceDays,
		DecideWithinDays: int(res.DecideWithin / (24 * time.Hour)), CallerExcluded: v.CallerExcluded,
	}
	if status == string(vulnerability.FindingStatusFalsePositive) {
		// One rule for the dialog and the request path: the evaluation.
		out.CanDecideAlone = res.SinglePerson()
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}
