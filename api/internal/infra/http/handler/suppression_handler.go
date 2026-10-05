package handler

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/suppression"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/sensorproto/legacyv1"
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
	RequestedAt     string  `json:"requested_at"`
	ApprovedBy      *string `json:"approved_by,omitempty"`
	ApprovedAt      *string `json:"approved_at,omitempty"`
	RejectedBy      *string `json:"rejected_by,omitempty"`
	RejectedAt      *string `json:"rejected_at,omitempty"`
	RejectionReason string  `json:"rejection_reason,omitempty"`
	ExpiresAt       *string `json:"expires_at,omitempty"`
	CreatedAt       string  `json:"created_at"`
	UpdatedAt       string  `json:"updated_at"`
}

// toSuppressionRuleResponse converts a domain rule to API response.
func toSuppressionRuleResponse(r *suppression.Rule) SuppressionRuleResponse {
	resp := SuppressionRuleResponse{
		ID:              r.ID().String(),
		TenantID:        r.TenantID().String(),
		Name:            r.Name(),
		Description:     r.Description(),
		SuppressionType: string(r.SuppressionType()),
		RuleID:          r.RuleID(),
		ToolName:        r.ToolName(),
		PathPattern:     r.PathPattern(),
		Status:          string(r.Status()),
		RequestedBy:     r.RequestedBy().StringOrEmpty(),
		RequestedAt:     r.RequestedAt().Format(time.RFC3339),
		RejectionReason: r.RejectionReason(),
		CreatedAt:       r.CreatedAt().Format(time.RFC3339),
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
	input := suppression.ApproveRuleInput{
		TenantID:   tenantUUID,
		RuleID:     ruleUUID,
		ApprovedBy: userUUID,
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
		h.handleServiceError(w, err)
		return
	}
	rule := result.Rule
	h.auditApproval(r, rule, result.SelfApproved)

	h.logger.Info("suppression rule approved",
		"rule_id", ruleID,
		"approved_by", userID,
		"tenant_id", tenantID,
	)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toSuppressionRuleResponse(rule))
}

// auditApproval records the approval in the tenant audit log. A self-approval
// (B16) is Critical.
func (h *SuppressionHandler) auditApproval(r *http.Request, rule *suppression.Rule, selfApproved bool) {
	if h.auditService == nil {
		return
	}
	action, msg := auditdom.ActionSuppressionRuleApproved, "Suppression rule approved"
	if selfApproved {
		action = auditdom.ActionSuppressionRuleSelfApproved
		msg = "Suppression rule approved by its own requester (the owner, the only eligible approver)"
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
		WithSeverity(auditdom.SeverityForAction(action))
	if err := h.auditService.LogEvent(r.Context(), actx, event); err != nil {
		h.logger.Warn("failed to audit suppression approval", "error", err)
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
// rules from GET /api/v1/agent/suppressions (SensorActiveRules).
func (h *SuppressionHandler) ListActiveRules(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	tenantUUID, err := shared.IDFromString(tenantID)
	if err != nil {
		apierror.BadRequest("Invalid tenant ID").WriteJSON(w)
		return
	}
	h.writeActiveRules(w, r, tenantUUID)
}

// SensorActiveRules returns the handler for GET /api/v1/agent/suppressions:
// the active suppression rules of the authenticated sensor's tenant, in the
// {rules, count} shape the SDK's security gate parses. It must be mounted
// behind IngestHandler.AuthenticateSource. The tenant comes only from the
// sensor's identity, never from the request; a platform sensor (no tenant) is
// refused with 403. When the suppressions module is disabled for the tenant
// (moduleEnabled returns false) the answer is an empty list rather than an
// error, so a CI gate degrades to "nothing suppressed" instead of failing.
// moduleEnabled may be nil (no module gating).
//
// Additive to sensor protocol v1 (RFC-023 §9.2): before it existed the SDK
// called /api/v1/suppressions/active with the sensor key, which is a user
// route, so every call was a 401 and the CI security gate never applied
// suppressions.
//
// @Summary      Active suppression rules for the sensor's tenant
// @Description  Approved, unexpired suppression rules of the authenticated sensor's tenant, for the sensor-side security gate. Empty when the suppressions module is disabled. Platform sensors (no tenant) get 403.
// @Tags         Sensor
// @Produce      json
// @Success      200  {object}  SensorSuppressionsResponse
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Security     ApiKeyAuth
// @Router       /agent/suppressions [get]
func (h *SuppressionHandler) SensorActiveRules(moduleEnabled func(ctx context.Context, tenantID string) bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		agt := SensorFromContext(r.Context())
		if agt == nil {
			apierror.Unauthorized(legacyv1.MsgNotAuthenticated).WriteJSON(w)
			return
		}
		if !requireSensorTenant(w, agt) {
			return
		}
		if moduleEnabled != nil && !moduleEnabled(r.Context(), agt.TenantID.String()) {
			writeActiveRulesResponse(w, nil)
			return
		}
		h.writeActiveRules(w, r, *agt.TenantID)
	}
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
		h.logger.Error("suppression service error", "error", err)
		apierror.InternalServerError("Internal server error").WriteJSON(w)
	}
}
