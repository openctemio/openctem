package handler

import (
	"github.com/openctemio/api/internal/app/scope"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/accesscontrol"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/validator"
)

// ScopeRuleHandler handles HTTP requests for scope rules.
type ScopeRuleHandler struct {
	svc       *scope.RuleService
	validator *validator.Validator
	logger    *logger.Logger
}

// NewScopeRuleHandler creates a new ScopeRuleHandler.
func NewScopeRuleHandler(svc *scope.RuleService, v *validator.Validator, log *logger.Logger) *ScopeRuleHandler {
	return &ScopeRuleHandler{
		svc:       svc,
		validator: v,
		logger:    log.With("handler", "scope_rule"),
	}
}

// ListScopeRules handles GET /api/v1/groups/{groupId}/scope-rules
func (h *ScopeRuleHandler) ListScopeRules(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	groupID := chi.URLParam(r, "groupId")
	if groupID == "" {
		apierror.BadRequest("groupId is required").WriteJSON(w)
		return
	}

	limit := 50
	offset := 0

	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 100 {
			limit = parsed
		}
	}
	if o := r.URL.Query().Get("offset"); o != "" {
		if parsed, err := strconv.Atoi(o); err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	filter := accesscontrol.ScopeRuleFilter{
		Limit:  limit,
		Offset: offset,
	}
	if active := r.URL.Query().Get("is_active"); active != "" {
		if parsed, err := strconv.ParseBool(active); err == nil {
			filter.IsActive = &parsed
		}
	}

	rules, totalCount, err := h.svc.ListRules(r.Context(), tenantID, groupID, filter)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"rules":       mapScopeRules(rules),
		"total_count": totalCount,
		"limit":       limit,
		"offset":      offset,
	})
}

// CreateScopeRule handles POST /api/v1/groups/{groupId}/scope-rules
func (h *ScopeRuleHandler) CreateScopeRule(w http.ResponseWriter, r *http.Request) {
	groupID := chi.URLParam(r, "groupId")
	if groupID == "" {
		apierror.BadRequest("groupId is required").WriteJSON(w)
		return
	}

	var input scope.CreateRuleInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	input.GroupID = groupID
	input.TenantID = middleware.MustGetTenantID(r.Context())

	if err := h.validator.Validate(input); err != nil {
		apierror.BadRequest(err.Error()).WriteJSON(w)
		return
	}

	userID := middleware.GetUserID(r.Context())
	rule, err := h.svc.CreateRule(r.Context(), input, userID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(mapScopeRule(rule))
}

// GetScopeRule handles GET /api/v1/groups/{groupId}/scope-rules/{ruleId}
func (h *ScopeRuleHandler) GetScopeRule(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	groupID := chi.URLParam(r, "groupId")
	ruleID := chi.URLParam(r, "ruleId")
	if ruleID == "" {
		apierror.BadRequest("ruleId is required").WriteJSON(w)
		return
	}

	rule, err := h.svc.GetRule(r.Context(), tenantID, ruleID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// Validate rule belongs to the group in the URL path
	if rule.GroupID().String() != groupID {
		apierror.NotFound("Scope rule").WriteJSON(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(mapScopeRule(rule))
}

// UpdateScopeRule handles PUT /api/v1/groups/{groupId}/scope-rules/{ruleId}
func (h *ScopeRuleHandler) UpdateScopeRule(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	groupID := chi.URLParam(r, "groupId")
	ruleID := chi.URLParam(r, "ruleId")
	if ruleID == "" {
		apierror.BadRequest("ruleId is required").WriteJSON(w)
		return
	}

	// Pre-validate rule belongs to this group
	existing, err := h.svc.GetRule(r.Context(), tenantID, ruleID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	if existing.GroupID().String() != groupID {
		apierror.NotFound("Scope rule").WriteJSON(w)
		return
	}

	var input scope.UpdateRuleInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(input); err != nil {
		apierror.BadRequest(err.Error()).WriteJSON(w)
		return
	}

	rule, err := h.svc.UpdateRule(r.Context(), tenantID, ruleID, input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(mapScopeRule(rule))
}

// DeleteScopeRule handles DELETE /api/v1/groups/{groupId}/scope-rules/{ruleId}
func (h *ScopeRuleHandler) DeleteScopeRule(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	groupID := chi.URLParam(r, "groupId")
	ruleID := chi.URLParam(r, "ruleId")
	if ruleID == "" {
		apierror.BadRequest("ruleId is required").WriteJSON(w)
		return
	}

	// Validate rule belongs to this group
	existing, err := h.svc.GetRule(r.Context(), tenantID, ruleID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	if existing.GroupID().String() != groupID {
		apierror.NotFound("Scope rule").WriteJSON(w)
		return
	}

	if err := h.svc.DeleteRule(r.Context(), tenantID, ruleID); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// PreviewScopeRule handles POST /api/v1/groups/{groupId}/scope-rules/{ruleId}/preview
func (h *ScopeRuleHandler) PreviewScopeRule(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	groupID := chi.URLParam(r, "groupId")
	ruleID := chi.URLParam(r, "ruleId")
	if ruleID == "" {
		apierror.BadRequest("ruleId is required").WriteJSON(w)
		return
	}

	// Validate rule belongs to this group
	existing, err := h.svc.GetRule(r.Context(), tenantID, ruleID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	if existing.GroupID().String() != groupID {
		apierror.NotFound("Scope rule").WriteJSON(w)
		return
	}

	result, err := h.svc.PreviewScopeRule(r.Context(), tenantID, ruleID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

// ReconcileGroup handles POST /api/v1/groups/{groupId}/scope-rules/reconcile
func (h *ScopeRuleHandler) ReconcileGroup(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	groupID := chi.URLParam(r, "groupId")
	if groupID == "" {
		apierror.BadRequest("groupId is required").WriteJSON(w)
		return
	}

	result, err := h.svc.ReconcileGroup(r.Context(), tenantID, groupID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

// handleServiceError maps service errors to HTTP responses.
func (h *ScopeRuleHandler) handleServiceError(w http.ResponseWriter, err error) {
	switch {
	case shared.IsNotFound(err):
		apierror.NotFound("Scope rule").WriteJSON(w)
	case shared.IsValidation(err):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	default:
		h.logger.Error("scope rule handler error", "error", err)
		apierror.InternalError(err).WriteJSON(w)
	}
}

// mapScopeRule converts a domain ScopeRule to an API response.
func mapScopeRule(rule *accesscontrol.ScopeRule) map[string]any {
	matchAssetGroupIDs := make([]string, 0, len(rule.MatchAssetGroupIDs()))
	for _, id := range rule.MatchAssetGroupIDs() {
		matchAssetGroupIDs = append(matchAssetGroupIDs, id.String())
	}

	result := map[string]any{
		"id":                    rule.ID().String(),
		"tenant_id":             rule.TenantID().String(),
		"group_id":              rule.GroupID().String(),
		"name":                  rule.Name(),
		"description":           rule.Description(),
		"rule_type":             rule.RuleType().String(),
		"match_tags":            rule.MatchTags(),
		"match_logic":           string(rule.MatchLogic()),
		"match_asset_group_ids": matchAssetGroupIDs,
		"ownership_type":        rule.OwnershipType().String(),
		"priority":              rule.Priority(),
		"is_active":             rule.IsActive(),
		"created_at":            rule.CreatedAt(),
		"updated_at":            rule.UpdatedAt(),
	}

	if rule.CreatedBy() != nil {
		result["created_by"] = rule.CreatedBy().String()
	}

	return result
}

// mapScopeRules converts a slice of domain ScopeRules to API responses.
func mapScopeRules(rules []*accesscontrol.ScopeRule) []map[string]any {
	result := make([]map[string]any, 0, len(rules))
	for _, rule := range rules {
		result = append(result, mapScopeRule(rule))
	}
	return result
}
