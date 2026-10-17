package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	authapp "github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/approvalpolicy"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/suppression"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// SuppressionHandler handles suppression rule HTTP requests.
type SuppressionHandler struct {
	service      *suppression.Service
	logger       *logger.Logger
	auditService *auditapp.AuditService
}

// SetAuditService wires the tenant audit log (approvals are recorded there; a
// self-approval at Critical severity). Nil-safe.
func (h *SuppressionHandler) SetAuditService(s *auditapp.AuditService) {
	h.auditService = s
}

// NewSuppressionHandler creates a new suppression handler.
func NewSuppressionHandler(svc *suppression.Service, log *logger.Logger) *SuppressionHandler {
	return &SuppressionHandler{
		service: svc,
		logger:  log,
	}
}

// SuppressionRuleResponse represents a suppression rule in API responses.
type SuppressionRuleResponse struct {
	ID              string  `json:"id"`
	TenantID        string  `json:"tenant_id"`
	Name            string  `json:"name"`
	Description     string  `json:"description,omitempty"`
	SuppressionType string  `json:"suppression_type"`
	RuleID          string  `json:"rule_id,omitempty"`
	ToolName        string  `json:"tool_name,omitempty"`
	PathPattern     string  `json:"path_pattern,omitempty"`
	AssetID         *string `json:"asset_id,omitempty"`
	Status          string  `json:"status"`
	RequestedBy     string  `json:"requested_by"`
	// RequestedByActor names a requester that is not a user (a CI job).
	RequestedByActor string  `json:"requested_by_actor,omitempty"`
	RequestedAt      string  `json:"requested_at"`
	ApprovedBy       *string `json:"approved_by,omitempty"`
	ApprovedAt       *string `json:"approved_at,omitempty"`
	RejectedBy       *string `json:"rejected_by,omitempty"`
	RejectedAt       *string `json:"rejected_at,omitempty"`
	RejectionReason  string  `json:"rejection_reason,omitempty"`
	ExpiresAt        *string `json:"expires_at,omitempty"`
	CreatedAt        string  `json:"created_at"`
	UpdatedAt        string  `json:"updated_at"`
	// ReviewFlaggedAt is set when the platform gave the rule an end it did
	// not have; ReviewReason says why (no_end_date). The flag clears when a
	// person edits the rule.
	ReviewFlaggedAt *string `json:"review_flagged_at,omitempty"`
	ReviewReason    string  `json:"review_reason,omitempty"`
	// ReasonCode is the rule's structured reason; Tier, ApprovalsRequired
	// and ApprovalsCollected come from the approval policy (RFC-111).
	ReasonCode         string `json:"reason_code,omitempty"`
	Tier               string `json:"tier,omitempty" enums:"peer,security,dual"`
	ApprovalsRequired  int    `json:"approvals_required"`
	ApprovalsCollected int    `json:"approvals_collected"`
}

// toSuppressionRuleResponse converts a domain rule to API response.
func toSuppressionRuleResponse(r *suppression.Rule) SuppressionRuleResponse {
	resp := SuppressionRuleResponse{
		ReasonCode:         r.ReasonCode(),
		Tier:               r.Tier(),
		ApprovalsRequired:  r.RequiredApprovals(),
		ApprovalsCollected: r.ApprovalsCollected(),
		ID:                 r.ID().String(),
		TenantID:           r.TenantID().String(),
		Name:               r.Name(),
		Description:        r.Description(),
		SuppressionType:    string(r.SuppressionType()),
		RuleID:             r.RuleID(),
		ToolName:           r.ToolName(),
		PathPattern:        r.PathPattern(),
		Status:             string(r.Status()),
		RequestedBy:        r.RequestedBy().StringOrEmpty(),
		RequestedByActor:   r.RequestedByActor(),
		RequestedAt:        r.RequestedAt().Format(time.RFC3339),
		RejectionReason:    r.RejectionReason(),
		CreatedAt:          r.CreatedAt().Format(time.RFC3339),
		// Full precision: an approval sends this back as the version it
		// reviewed, and two edits in the same second must not look equal.
		UpdatedAt: r.UpdatedAt().Format(time.RFC3339Nano),
	}

	if r.AssetID() != nil {
		s := r.AssetID().String()
		resp.AssetID = &s
	}
	if r.ApprovedBy() != nil {
		s := r.ApprovedBy().String()
		resp.ApprovedBy = &s
	}
	if r.ApprovedAt() != nil {
		s := r.ApprovedAt().Format(time.RFC3339)
		resp.ApprovedAt = &s
	}
	if r.RejectedBy() != nil {
		s := r.RejectedBy().String()
		resp.RejectedBy = &s
	}
	if r.RejectedAt() != nil {
		s := r.RejectedAt().Format(time.RFC3339)
		resp.RejectedAt = &s
	}
	if r.ExpiresAt() != nil {
		s := r.ExpiresAt().Format(time.RFC3339)
		resp.ExpiresAt = &s
	}
	if r.ReviewFlaggedAt() != nil {
		s := r.ReviewFlaggedAt().Format(time.RFC3339)
		resp.ReviewFlaggedAt = &s
		resp.ReviewReason = r.ReviewReason()
	}

	return resp
}

// CreateSuppressionRuleRequest represents a request to create a suppression rule.
type CreateSuppressionRuleRequest struct {
	Name            string  `json:"name"`
	Description     string  `json:"description,omitempty"`
	SuppressionType string  `json:"suppression_type"`
	RuleID          string  `json:"rule_id,omitempty"`
	ToolName        string  `json:"tool_name,omitempty"`
	PathPattern     string  `json:"path_pattern,omitempty"`
	AssetID         *string `json:"asset_id,omitempty"`
	ExpiresAt       *string `json:"expires_at,omitempty"`
	// ReasonCode is required: a false-positive justification for a
	// false_positive rule, an accepted-risk reason otherwise (the finding
	// closure reason catalog). Description is the note, also required.
	ReasonCode string `json:"reason_code"`
}

// CreateRule handles POST /api/v1/suppressions
func (h *SuppressionHandler) CreateRule(w http.ResponseWriter, r *http.Request) {
	var req CreateSuppressionRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	tenantID := middleware.MustGetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())

	tenantUUID, err := shared.IDFromString(tenantID)
	if err != nil {
		apierror.BadRequest("Invalid tenant ID").WriteJSON(w)
		return
	}

	userUUID, err := shared.IDFromString(userID)
	if err != nil {
		apierror.BadRequest("Invalid user ID").WriteJSON(w)
		return
	}

	// Parse asset ID if provided
	var assetID *shared.ID
	if req.AssetID != nil && *req.AssetID != "" {
		id, err := shared.IDFromString(*req.AssetID)
		if err != nil {
			apierror.BadRequest("Invalid asset ID").WriteJSON(w)
			return
		}
		assetID = &id
	}

	input := suppression.CreateRuleInput{
		TenantID:        tenantUUID,
		Name:            req.Name,
		Description:     req.Description,
		SuppressionType: suppression.SuppressionType(req.SuppressionType),
		RuleID:          req.RuleID,
		ToolName:        req.ToolName,
		PathPattern:     req.PathPattern,
		AssetID:         assetID,
		RequestedBy:     userUUID,
		ExpiresAt:       req.ExpiresAt,
		ReasonCode:      req.ReasonCode,
	}

	rule, err := h.service.CreateRule(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	h.logger.Info("suppression rule created",
		"rule_id", rule.ID().String(),
		"user_id", userID,
		"tenant_id", tenantID,
	)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(toSuppressionRuleResponse(rule))
}

// ListRules handles GET /api/v1/suppressions
func (h *SuppressionHandler) ListRules(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	tenantUUID, err := shared.IDFromString(tenantID)
	if err != nil {
		apierror.BadRequest("Invalid tenant ID").WriteJSON(w)
		return
	}

	// Parse query parameters
	filter := suppression.RuleFilter{}

	if status := r.URL.Query().Get("status"); status != "" {
		s := suppression.RuleStatus(status)
		filter.Status = &s
	}

	if toolName := r.URL.Query().Get("tool_name"); toolName != "" {
		filter.ToolName = &toolName
	}

	rules, err := h.service.ListRules(r.Context(), tenantUUID, filter)
	if err == nil {
		// A person sees organization-wide rules and the rules bound to an asset
		// in their data scope.
		rules, err = h.service.VisibleRules(r.Context(), tenantUUID, rules)
	}
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	response := make([]SuppressionRuleResponse, len(rules))
	for i, rule := range rules {
		response[i] = toSuppressionRuleResponse(rule)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"data":  response,
		"total": len(response),
	})
}

// UpdateSuppressionRuleRequest represents a request to update a suppression rule.
type UpdateSuppressionRuleRequest struct {
	Name        *string `json:"name,omitempty"`
	Description *string `json:"description,omitempty"`
	RuleID      *string `json:"rule_id,omitempty"`
	ToolName    *string `json:"tool_name,omitempty"`
	PathPattern *string `json:"path_pattern,omitempty"`
	ExpiresAt   *string `json:"expires_at,omitempty"`
}

// UpdateRule handles PUT /api/v1/suppressions/{id}
func (h *SuppressionHandler) UpdateRule(w http.ResponseWriter, r *http.Request) {
	ruleID := r.PathValue("id")
	if ruleID == "" {
		apierror.BadRequest("Rule ID is required").WriteJSON(w)
		return
	}

	var req UpdateSuppressionRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	tenantID := middleware.MustGetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())

	tenantUUID, err := shared.IDFromString(tenantID)
	if err != nil {
		apierror.BadRequest("Invalid tenant ID").WriteJSON(w)
		return
	}

	ruleUUID, err := shared.IDFromString(ruleID)
	if err != nil {
		apierror.BadRequest("Invalid rule ID").WriteJSON(w)
		return
	}

	userUUID, err := shared.IDFromString(userID)
	if err != nil {
		apierror.BadRequest("Invalid user ID").WriteJSON(w)
		return
	}

	input := suppression.UpdateRuleInput{
		TenantID:    tenantUUID,
		RuleID:      ruleUUID,
		Name:        req.Name,
		Description: req.Description,
		RuleIDPat:   req.RuleID,
		ToolName:    req.ToolName,
		PathPattern: req.PathPattern,
		ExpiresAt:   req.ExpiresAt,
		UpdatedBy:   userUUID,
	}

	rule, err := h.service.UpdateRule(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	h.logger.Info("suppression rule updated",
		"rule_id", ruleID,
		"updated_by", userID,
		"tenant_id", tenantID,
	)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toSuppressionRuleResponse(rule))
}

// GetRule handles GET /api/v1/suppressions/{id}
func (h *SuppressionHandler) GetRule(w http.ResponseWriter, r *http.Request) {
	ruleID := r.PathValue("id")
	if ruleID == "" {
		apierror.BadRequest("Rule ID is required").WriteJSON(w)
		return
	}

	tenantID := middleware.MustGetTenantID(r.Context())
	tenantUUID, err := shared.IDFromString(tenantID)
	if err != nil {
		apierror.BadRequest("Invalid tenant ID").WriteJSON(w)
		return
	}

	ruleUUID, err := shared.IDFromString(ruleID)
	if err != nil {
		apierror.BadRequest("Invalid rule ID").WriteJSON(w)
		return
	}

	rule, err := h.service.GetRule(r.Context(), tenantUUID, ruleUUID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toSuppressionRuleResponse(rule))
}

// ApproveRuleRequest represents a request to approve a rule.
type ApproveRuleRequest struct {
	// ReviewedUpdatedAt is the rule's updated_at exactly as the approver last
	// loaded it. The approval is refused (409) if the rule changed since.
	ReviewedUpdatedAt string `json:"reviewed_updated_at"`
	// SelfApprovalReason and TOTPCode: the owner approves their own rule
	// because no other approver exists; both are required then, and the
	// code must be fresh from the owner's authenticator app.
	SelfApprovalReason string `json:"self_approval_reason,omitempty"`
	TOTPCode           string `json:"totp_code,omitempty"`
}

// ApproveRule handles POST /api/v1/suppressions/{id}/approve
func (h *SuppressionHandler) ApproveRule(w http.ResponseWriter, r *http.Request) {
	ruleID := r.PathValue("id")
	if ruleID == "" {
		apierror.BadRequest("Rule ID is required").WriteJSON(w)
		return
	}

	tenantID := middleware.MustGetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())

	tenantUUID, err := shared.IDFromString(tenantID)
	if err != nil {
		apierror.BadRequest("Invalid tenant ID").WriteJSON(w)
		return
	}

	ruleUUID, err := shared.IDFromString(ruleID)
	if err != nil {
		apierror.BadRequest("Invalid rule ID").WriteJSON(w)
		return
	}

	userUUID, err := shared.IDFromString(userID)
	if err != nil {
		apierror.BadRequest("Invalid user ID").WriteJSON(w)
		return
	}

	var req ApproveRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	if len(req.SelfApprovalReason) > 1000 || len(req.TOTPCode) > 16 {
		apierror.BadRequest("self_approval_reason is at most 1000 characters").WriteJSON(w)
		return
	}
	input := suppression.ApproveRuleInput{
		TenantID:           tenantUUID,
		RuleID:             ruleUUID,
		ApprovedBy:         userUUID,
		SelfApprovalReason: req.SelfApprovalReason,
		TOTPCode:           req.TOTPCode,
	}
	if req.ReviewedUpdatedAt != "" {
		reviewed, err := time.Parse(time.RFC3339Nano, req.ReviewedUpdatedAt)
		if err != nil {
			apierror.BadRequest("reviewed_updated_at must be the rule's updated_at (RFC 3339)").WriteJSON(w)
			return
		}
		input.ReviewedUpdatedAt = &reviewed
	}

	result, err := h.service.ApproveRule(r.Context(), input)
	if err != nil {
		if suppression.IsSelfApprovalRefusal(err) {
			h.auditSelfApprovalRefused(r, ruleID, err)
		}
		if ref, ok := approvalpolicy.IsRefusal(err); ok {
			h.auditPolicyRefusal(r, ruleID, ref.Reason)
			status := http.StatusForbidden
			if ref.Code == approvalpolicy.CodeNoEligibleApprover {
				status = http.StatusConflict
			}
			apierror.New(status, apierror.Code(ref.Code), ref.Error()).
				WithDetails(map[string]string{"reason": ref.Reason}).WriteJSON(w)
			return
		}
		if middleware.WriteStepUpError(w, err, authapp.StepUpWindow) {
			return
		}
		h.handleServiceError(w, err)
		return
	}
	rule := result.Rule
	h.auditApproval(r, result)

	h.logger.Info("suppression rule approved",
		"rule_id", ruleID,
		"approved_by", userID,
		"tenant_id", tenantID,
		"applied_findings", result.AppliedFindings,
		"capped", result.Capped,
	)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ApproveSuppressionRuleResponse{
		SuppressionRuleResponse: toSuppressionRuleResponse(rule),
		AppliedFindings:         result.AppliedFindings,
		Capped:                  result.Capped,
	})
}

// ApproveSuppressionRuleResponse is the approved rule plus what the approval
// did to existing findings.
type ApproveSuppressionRuleResponse struct {
	SuppressionRuleResponse
	// AppliedFindings is the number of open findings the approval gave the
	// rule's disposition (false_positive or accepted).
	AppliedFindings int `json:"applied_findings"`
	// Capped: more open findings matched than one approval changes; the rest
	// stay open.
	Capped bool `json:"capped"`
}

// SuppressionRulePreviewResponse is what approving a rule would do now.
type SuppressionRulePreviewResponse struct {
	// MatchingOpenFindings is the number of the organization's open findings
	// the rule matches and an approval would close, at most Limit.
	MatchingOpenFindings int `json:"matching_open_findings"`
	// Capped: more than Limit match; an approval closes Limit of them.
	Capped bool `json:"capped"`
	Limit  int  `json:"limit"`
	// InScopeFindings is how many of those are on assets the caller's data
	// scope covers (at most Limit); Sample lists the first few of them.
	// Findings outside the caller's scope are only in MatchingOpenFindings.
	InScopeFindings int                             `json:"in_scope_findings"`
	Sample          []SuppressionPreviewFindingResp `json:"sample"`
}

// SuppressionPreviewFindingResp is one finding of a preview sample.
type SuppressionPreviewFindingResp struct {
	ID        string `json:"id"`
	AssetID   string `json:"asset_id"`
	AssetName string `json:"asset_name,omitempty"`
	RuleID    string `json:"rule_id,omitempty"`
	FilePath  string `json:"file_path,omitempty"`
	Title     string `json:"title"`
	Severity  string `json:"severity"`
	Status    string `json:"status"`
}

// PreviewRule handles GET /api/v1/suppressions/{id}/preview: the number of
// open findings an approval would close. The count is organization-wide, as
// the approval is, so the route is gated like the approval itself; the sample
// and the in-scope count only cover the caller's data scope.
// @Summary      Preview a suppression rule's approval
// @Description  The number of the organization's open findings the rule matches and an approval would close now (at most limit; capped when more match). Organization-wide, like the approval; needs findings:suppressions:approve. in_scope_findings and sample cover only the findings on assets the caller's data scope admits.
// @Tags         Suppressions
// @Produce      json
// @Param        id   path      string  true  "Suppression rule ID"
// @Success      200  {object}  SuppressionRulePreviewResponse
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /suppressions/{id}/preview [get]
func (h *SuppressionHandler) PreviewRule(w http.ResponseWriter, r *http.Request) {
	tenantUUID, err := shared.IDFromString(middleware.MustGetTenantID(r.Context()))
	if err != nil {
		apierror.BadRequest("Invalid tenant ID").WriteJSON(w)
		return
	}
	ruleUUID, err := shared.IDFromString(r.PathValue("id"))
	if err != nil {
		apierror.BadRequest("Invalid rule ID").WriteJSON(w)
		return
	}

	preview, err := h.service.PreviewRule(r.Context(), tenantUUID, ruleUUID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	// The approver may approve without being allowed to read findings: the
	// examples are finding data, so they need findings:read as well (the
	// counts stay).
	examples := preview.Sample
	if !middleware.HasPermission(r.Context(), permission.FindingsRead.String()) {
		examples = nil
	}
	sample := make([]SuppressionPreviewFindingResp, 0, len(examples))
	for _, f := range examples {
		sample = append(sample, SuppressionPreviewFindingResp{
			ID: f.ID.String(), AssetID: f.AssetID.String(), AssetName: f.AssetName, RuleID: f.RuleID,
			FilePath: f.FilePath, Title: f.Title, Severity: f.Severity, Status: f.Status,
		})
	}
	json.NewEncoder(w).Encode(SuppressionRulePreviewResponse{
		MatchingOpenFindings: preview.MatchingOpenFindings,
		Capped:               preview.Capped,
		Limit:                preview.Limit,
		InScopeFindings:      preview.InScopeFindings,
		Sample:               sample,
	})
}

// auditApproval records the approval in the tenant audit log. A self-approval
// (B16) is Critical.
func (h *SuppressionHandler) auditApproval(r *http.Request, result *suppression.ApproveResult) {
	if h.auditService == nil {
		return
	}
	rule := result.Rule
	action, msg := auditdom.ActionSuppressionRuleApproved, "Suppression rule approved"
	if result.Pending {
		action = auditdom.ActionSuppressionRuleSigned
		msg = fmt.Sprintf("Suppression rule approved by one approver (%d of %d); it needs more approvals",
			result.ApprovalsCollected, result.ApprovalsRequired)
	}
	if result.SelfApproved {
		action = auditdom.ActionSuppressionRuleSelfApproved
		msg = "Suppression rule approved by its own requester (the owner, the only eligible approver) with a fresh authenticator code"
	}
	actx := auditapp.AuditContext{
		TenantID:   middleware.GetTenantID(r.Context()),
		ActorID:    middleware.GetUserID(r.Context()),
		ActorEmail: auditActorEmail(r.Context()),
		ActorIP:    getClientIP(r),
		UserAgent:  r.UserAgent(),
		RequestID:  r.Header.Get("X-Request-ID"),
	}
	event := auditapp.NewSuccessEvent(action, auditdom.ResourceTypeSuppressionRule, rule.ID().String()).
		WithResourceName(rule.Name()).
		WithMessage(msg).
		WithMetadata("suppression_type", string(rule.SuppressionType())).
		WithMetadata("requested_by", rule.RequestedBy().StringOrEmpty()).
		WithMetadata("applied_findings", result.AppliedFindings).
		WithMetadata("capped", result.Capped).
		WithSeverity(auditdom.SeverityForAction(action))
	if err := h.auditService.LogEvent(r.Context(), actx, event); err != nil {
		h.logger.Warn("failed to audit suppression approval", "error", err)
	}
}

// MarkReviewed handles POST /api/v1/suppressions/{id}/reviewed: an approver
// clears the review flag of a rule the platform gave an end it did not have.
// The rule keeps its end. Audited with the flag before and after.
// @Summary      Clear a suppression rule's review flag
// @Description  An approver confirms they reviewed a rule flagged because it had no end date. The rule keeps its end; 409 when the rule is not flagged. Needs findings:suppressions:approve.
// @Tags         Suppressions
// @Produce      json
// @Param        id   path      string  true  "Suppression rule ID"
// @Success      200  {object}  SuppressionRuleResponse
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /suppressions/{id}/reviewed [post]
func (h *SuppressionHandler) MarkReviewed(w http.ResponseWriter, r *http.Request) {
	tenantUUID, err := shared.IDFromString(middleware.MustGetTenantID(r.Context()))
	if err != nil {
		apierror.BadRequest("Invalid tenant ID").WriteJSON(w)
		return
	}
	ruleUUID, err := shared.IDFromString(r.PathValue("id"))
	if err != nil {
		apierror.BadRequest("Invalid rule ID").WriteJSON(w)
		return
	}
	userUUID, err := shared.IDFromString(middleware.GetUserID(r.Context()))
	if err != nil {
		apierror.BadRequest("Invalid user ID").WriteJSON(w)
		return
	}
	// The body is optional: the rule's own requester sends a reason and a
	// fresh authenticator code (the sole-approver path).
	var req MarkReviewedRequest
	if r.ContentLength != 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			apierror.BadRequest("invalid request body").WriteJSON(w)
			return
		}
	}
	rule, flaggedAt, reason, err := h.service.MarkReviewed(r.Context(), suppression.MarkReviewedInput{
		TenantID: tenantUUID, RuleID: ruleUUID, By: userUUID,
		SelfApprovalReason: req.SelfApprovalReason, TOTPCode: req.TOTPCode,
	})
	if err != nil {
		if suppression.IsSelfApprovalRefusal(err) || errors.Is(err, suppression.ErrSelfApprovalAfterRemoval) {
			h.auditReviewRefusal(r, tenantUUID, userUUID, ruleUUID, err)
		}
		h.handleServiceError(w, err)
		return
	}
	if h.auditService != nil {
		actx := auditapp.AuditContext{
			TenantID:   tenantUUID.String(),
			ActorID:    userUUID.String(),
			ActorEmail: auditActorEmail(r.Context()),
			ActorIP:    getClientIP(r),
			UserAgent:  r.UserAgent(),
			RequestID:  r.Header.Get("X-Request-ID"),
		}
		changes := auditdom.NewChanges().
			Set("review_flagged_at", flaggedAt.UTC().Format(time.RFC3339), nil).
			Set("review_reason", reason, "")
		event := auditapp.NewSuccessEvent(auditdom.ActionSuppressionRuleReviewed, auditdom.ResourceTypeSuppressionRule, rule.ID().String()).
			WithResourceName(rule.Name()).
			WithChanges(changes).
			WithMessage("Suppression rule review flag cleared").
			WithSeverity(auditdom.SeverityForAction(auditdom.ActionSuppressionRuleReviewed))
		if err := h.auditService.LogEvent(r.Context(), actx, event); err != nil {
			h.logger.Warn("failed to audit suppression review", "error", err)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toSuppressionRuleResponse(rule))
}

// auditSelfApprovalRefused records a refused own approval at High: the
// signal of someone trying to bypass the second approver.
func (h *SuppressionHandler) auditSelfApprovalRefused(r *http.Request, ruleID string, cause error) {
	if h.auditService == nil {
		return
	}
	actx := auditapp.AuditContext{
		TenantID:   middleware.GetTenantID(r.Context()),
		ActorID:    middleware.GetUserID(r.Context()),
		ActorEmail: auditActorEmail(r.Context()),
		ActorIP:    getClientIP(r),
		UserAgent:  r.UserAgent(),
		RequestID:  r.Header.Get("X-Request-ID"),
	}
	action := auditdom.ActionSuppressionRuleSelfApprovalRefused
	event := auditapp.NewFailureEvent(action, auditdom.ResourceTypeSuppressionRule, ruleID, cause).
		WithMessage("Own approval of a suppression rule refused").
		WithSeverity(auditdom.SeverityForAction(action))
	if err := h.auditService.LogEvent(r.Context(), actx, event); err != nil {
		h.logger.Warn("failed to audit refused suppression self-approval", "error", err)
	}
}

// RejectRuleRequest represents a request to reject a rule.
type RejectRuleRequest struct {
	Reason string `json:"reason"`
}

// RejectRule handles POST /api/v1/suppressions/{id}/reject
func (h *SuppressionHandler) RejectRule(w http.ResponseWriter, r *http.Request) {
	ruleID := r.PathValue("id")
	if ruleID == "" {
		apierror.BadRequest("Rule ID is required").WriteJSON(w)
		return
	}

	var req RejectRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	tenantID := middleware.MustGetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())

	tenantUUID, err := shared.IDFromString(tenantID)
	if err != nil {
		apierror.BadRequest("Invalid tenant ID").WriteJSON(w)
		return
	}

	ruleUUID, err := shared.IDFromString(ruleID)
	if err != nil {
		apierror.BadRequest("Invalid rule ID").WriteJSON(w)
		return
	}

	userUUID, err := shared.IDFromString(userID)
	if err != nil {
		apierror.BadRequest("Invalid user ID").WriteJSON(w)
		return
	}

	input := suppression.RejectRuleInput{
		TenantID:   tenantUUID,
		RuleID:     ruleUUID,
		RejectedBy: userUUID,
		Reason:     req.Reason,
	}

	rule, err := h.service.RejectRule(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	h.logger.Info("suppression rule rejected",
		"rule_id", ruleID,
		"rejected_by", userID,
		"tenant_id", tenantID,
		"reason", req.Reason,
	)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toSuppressionRuleResponse(rule))
}

// DeleteRule handles DELETE /api/v1/suppressions/{id}
func (h *SuppressionHandler) DeleteRule(w http.ResponseWriter, r *http.Request) {
	ruleID := r.PathValue("id")
	if ruleID == "" {
		apierror.BadRequest("Rule ID is required").WriteJSON(w)
		return
	}

	tenantID := middleware.MustGetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())

	tenantUUID, err := shared.IDFromString(tenantID)
	if err != nil {
		apierror.BadRequest("Invalid tenant ID").WriteJSON(w)
		return
	}

	ruleUUID, err := shared.IDFromString(ruleID)
	if err != nil {
		apierror.BadRequest("Invalid rule ID").WriteJSON(w)
		return
	}

	userUUID, err := shared.IDFromString(userID)
	if err != nil {
		apierror.BadRequest("Invalid user ID").WriteJSON(w)
		return
	}

	if err := h.service.DeleteRule(r.Context(), tenantUUID, ruleUUID, userUUID); err != nil {
		h.handleServiceError(w, err)
		return
	}

	h.logger.Info("suppression rule deleted",
		"rule_id", ruleID,
		"deleted_by", userID,
		"tenant_id", tenantID,
	)

	w.WriteHeader(http.StatusNoContent)
}

// ListActiveRules handles GET /api/v1/suppressions/active, the user-facing
// view of a tenant's active rules (tenant from the JWT). Sensors read the same
// rules from GET /api/v2/sensor/suppressions.
func (h *SuppressionHandler) ListActiveRules(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	tenantUUID, err := shared.IDFromString(tenantID)
	if err != nil {
		apierror.BadRequest("Invalid tenant ID").WriteJSON(w)
		return
	}
	h.writeActiveRules(w, r, tenantUUID)
}

// SensorSuppressionRule is one rule in the active-rules list sensors read.
type SensorSuppressionRule struct {
	RuleID      string  `json:"rule_id,omitempty"`
	ToolName    string  `json:"tool_name,omitempty"`
	PathPattern string  `json:"path_pattern,omitempty"`
	AssetID     *string `json:"asset_id,omitempty"`
	ExpiresAt   *string `json:"expires_at,omitempty"`
}

// SensorSuppressionsResponse is the active-rules list: {"count": n, "rules": [...]}.
type SensorSuppressionsResponse struct {
	Count int                     `json:"count"`
	Rules []SensorSuppressionRule `json:"rules"`
}

func (h *SuppressionHandler) writeActiveRules(w http.ResponseWriter, r *http.Request, tenantID shared.ID) {
	rules, err := h.service.ListActiveRules(r.Context(), tenantID)
	if err == nil {
		// A person sees organization-wide rules and the rules bound to an asset
		// in their data scope, never another asset's id or path pattern.
		rules, err = h.service.VisibleRules(r.Context(), tenantID, rules)
	}
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	writeActiveRulesResponse(w, rules)
}

func writeActiveRulesResponse(w http.ResponseWriter, rules []*suppression.Rule) {
	response := make([]SensorSuppressionRule, len(rules))
	for i, rule := range rules {
		resp := SensorSuppressionRule{
			RuleID:      rule.RuleID(),
			ToolName:    rule.ToolName(),
			PathPattern: rule.PathPattern(),
		}
		if rule.AssetID() != nil {
			s := rule.AssetID().String()
			resp.AssetID = &s
		}
		if rule.ExpiresAt() != nil {
			s := rule.ExpiresAt().Format(time.RFC3339)
			resp.ExpiresAt = &s
		}
		response[i] = resp
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(SensorSuppressionsResponse{Count: len(response), Rules: response})
}

// handleServiceError converts service errors to HTTP responses.
func (h *SuppressionHandler) handleServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, suppression.ErrRuleAssetNotFound):
		apierror.NotFound("Asset").WriteJSON(w)
	case errors.Is(err, suppression.ErrRuleNotFound):
		apierror.NotFound("Suppression rule not found").WriteJSON(w)
	case errors.Is(err, suppression.ErrRuleNotPending):
		apierror.BadRequest("Rule is not in pending status").WriteJSON(w)
	case errors.Is(err, suppression.ErrRuleExpired):
		apierror.BadRequest("Rule has expired").WriteJSON(w)
	case errors.Is(err, suppression.ErrInvalidCriteria):
		apierror.BadRequest("Invalid suppression criteria").WriteJSON(w)
	case shared.IsValidation(err):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	case errors.Is(err, shared.ErrForbidden):
		apierror.Forbidden(err.Error()).WriteJSON(w)
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Suppression rule not found").WriteJSON(w)
	case errors.Is(err, shared.ErrConflict):
		// e.g. approving or rejecting a rule that is no longer pending
		apierror.Conflict(err.Error()).WriteJSON(w)
	default:
		h.logger.Error("suppression service error", "error", logger.SanitizeError(err))
		apierror.InternalServerError("Internal server error").WriteJSON(w)
	}
}

// auditPolicyRefusal records an approver the approval policy refused.
func (h *SuppressionHandler) auditPolicyRefusal(r *http.Request, ruleID, reason string) {
	if h.auditService == nil {
		return
	}
	actx := auditapp.AuditContext{
		TenantID:   middleware.GetTenantID(r.Context()),
		ActorID:    middleware.GetUserID(r.Context()),
		ActorEmail: auditActorEmail(r.Context()),
		ActorIP:    getClientIP(r),
		UserAgent:  r.UserAgent(),
		RequestID:  r.Header.Get("X-Request-ID"),
	}
	event := auditapp.NewDeniedEvent(auditdom.ActionSuppressionRuleApprovalRefused, auditdom.ResourceTypeSuppressionRule, ruleID, reason).
		WithMessage("Refused by the approval policy ("+reason+")").
		WithMetadata("reason", reason).
		WithSeverity(auditdom.SeverityMedium)
	if err := h.auditService.LogEvent(r.Context(), actx, event); err != nil {
		h.logger.Warn("failed to audit suppression approval refusal", "error", err)
	}
}

// MarkReviewedRequest is the optional body of POST /suppressions/{id}/reviewed:
// the rule's own requester gives a reason and a fresh authenticator code.
type MarkReviewedRequest struct {
	SelfApprovalReason string `json:"self_approval_reason"`
	TOTPCode           string `json:"totp_code"`
}

// auditReviewRefusal records a refused attempt to clear the review flag of
// one's own rule.
func (h *SuppressionHandler) auditReviewRefusal(r *http.Request, tenantID, userID, ruleID shared.ID, cause error) {
	if h.auditService == nil {
		return
	}
	actx := auditapp.AuditContext{
		TenantID: tenantID.String(), ActorID: userID.String(), ActorEmail: auditActorEmail(r.Context()),
		ActorIP: getClientIP(r), UserAgent: r.UserAgent(), RequestID: r.Header.Get("X-Request-ID"),
	}
	event := auditapp.NewDeniedEvent(auditdom.ActionSuppressionRuleReviewed, auditdom.ResourceTypeSuppressionRule, ruleID.String(), cause.Error()).
		WithSeverity(auditdom.SeverityHigh).
		WithMessage("Refused: the requester tried to clear the review flag of their own rule")
	if err := h.auditService.LogEvent(r.Context(), actx, event); err != nil {
		h.logger.Warn("failed to audit suppression review refusal", "error", err)
	}
}
