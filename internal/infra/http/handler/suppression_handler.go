package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/suppression"
	"github.com/openctemio/api/pkg/logger"
)

// SuppressionHandler handles suppression rule HTTP requests.
type SuppressionHandler struct {
	service *suppression.Service
	logger  *logger.Logger
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
		RequestedBy:     r.RequestedBy().String(),
		RequestedAt:     r.RequestedAt().Format(time.RFC3339),
		RejectionReason: r.RejectionReason(),
		CreatedAt:       r.CreatedAt().Format(time.RFC3339),
		UpdatedAt:       r.UpdatedAt().Format(time.RFC3339),
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
type ApproveRuleRequest struct{}

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

	input := suppression.ApproveRuleInput{
		TenantID:   tenantUUID,
		RuleID:     ruleUUID,
		ApprovedBy: userUUID,
	}

	rule, err := h.service.ApproveRule(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	h.logger.Info("suppression rule approved",
		"rule_id", ruleID,
		"approved_by", userID,
		"tenant_id", tenantID,
	)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toSuppressionRuleResponse(rule))
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

// ListActiveRules handles GET /api/v1/suppressions/active
// This endpoint is used by agents to fetch active suppression rules.
func (h *SuppressionHandler) ListActiveRules(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	tenantUUID, err := shared.IDFromString(tenantID)
	if err != nil {
		apierror.BadRequest("Invalid tenant ID").WriteJSON(w)
		return
	}

	rules, err := h.service.ListActiveRules(r.Context(), tenantUUID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// Return simplified format for agent consumption
	type ActiveRuleResponse struct {
		RuleID      string  `json:"rule_id,omitempty"`
		ToolName    string  `json:"tool_name,omitempty"`
		PathPattern string  `json:"path_pattern,omitempty"`
		AssetID     *string `json:"asset_id,omitempty"`
		ExpiresAt   *string `json:"expires_at,omitempty"`
	}

	response := make([]ActiveRuleResponse, len(rules))
	for i, rule := range rules {
		resp := ActiveRuleResponse{
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
	json.NewEncoder(w).Encode(map[string]any{
		"rules": response,
		"count": len(response),
	})
}

// handleServiceError converts service errors to HTTP responses.
func (h *SuppressionHandler) handleServiceError(w http.ResponseWriter, err error) {
	switch {
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
	default:
		h.logger.Error("suppression service error", "error", err)
		apierror.InternalServerError("Internal server error").WriteJSON(w)
	}
}
