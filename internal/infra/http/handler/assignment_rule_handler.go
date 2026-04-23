package handler

import (
	"github.com/openctemio/api/internal/app/assignment"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/accesscontrol"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/validator"
)

// AssignmentRuleHandler handles assignment rule HTTP requests.
type AssignmentRuleHandler struct {
	service   *assignment.RuleService
	validator *validator.Validator
	logger    *logger.Logger
}

// NewAssignmentRuleHandler creates a new assignment rule handler.
func NewAssignmentRuleHandler(svc *assignment.RuleService, v *validator.Validator, log *logger.Logger) *AssignmentRuleHandler {
	return &AssignmentRuleHandler{
		service:   svc,
		validator: v,
		logger:    log,
	}
}

// =============================================================================
// Response Types
// =============================================================================

// AssignmentRuleResponse represents an assignment rule in API responses.
type AssignmentRuleResponse struct {
	ID            string                             `json:"id"`
	TenantID      string                             `json:"tenant_id"`
	Name          string                             `json:"name"`
	Description   string                             `json:"description,omitempty"`
	Priority      int                                `json:"priority"`
	IsActive      bool                               `json:"is_active"`
	Conditions    accesscontrol.AssignmentConditions `json:"conditions"`
	TargetGroupID string                             `json:"target_group_id"`
	Options       accesscontrol.AssignmentOptions    `json:"options"`
	CreatedAt     time.Time                          `json:"created_at"`
	UpdatedAt     time.Time                          `json:"updated_at"`
	CreatedBy     string                             `json:"created_by,omitempty"`
}

// AssignmentRuleListResponse represents a paginated list of assignment rules.
type AssignmentRuleListResponse struct {
	Rules      []AssignmentRuleResponse `json:"rules"`
	TotalCount int64                    `json:"total_count"`
	Limit      int                      `json:"limit"`
	Offset     int                      `json:"offset"`
}

func toAssignmentRuleResponse(r *accesscontrol.AssignmentRule) AssignmentRuleResponse {
	resp := AssignmentRuleResponse{
		ID:            r.ID().String(),
		TenantID:      r.TenantID().String(),
		Name:          r.Name(),
		Description:   r.Description(),
		Priority:      r.Priority(),
		IsActive:      r.IsActive(),
		Conditions:    r.Conditions(),
		TargetGroupID: r.TargetGroupID().String(),
		Options:       r.Options(),
		CreatedAt:     r.CreatedAt(),
		UpdatedAt:     r.UpdatedAt(),
	}
	if r.CreatedBy() != nil {
		resp.CreatedBy = r.CreatedBy().String()
	}
	return resp
}

// =============================================================================
// Request Types
// =============================================================================

// CreateAssignmentRuleRequest represents the request to create an assignment rule.
type CreateAssignmentRuleRequest struct {
	Name          string                             `json:"name" validate:"required,min=2,max=200"`
	Description   string                             `json:"description" validate:"max=1000"`
	Priority      int                                `json:"priority"`
	Conditions    accesscontrol.AssignmentConditions `json:"conditions"`
	TargetGroupID string                             `json:"target_group_id" validate:"required,uuid"`
	Options       accesscontrol.AssignmentOptions    `json:"options"`
}

// UpdateAssignmentRuleRequest represents the request to update an assignment rule.
type UpdateAssignmentRuleRequest struct {
	Name          *string                             `json:"name" validate:"omitempty,min=2,max=200"`
	Description   *string                             `json:"description" validate:"omitempty,max=1000"`
	Priority      *int                                `json:"priority"`
	IsActive      *bool                               `json:"is_active"`
	Conditions    *accesscontrol.AssignmentConditions `json:"conditions"`
	TargetGroupID *string                             `json:"target_group_id" validate:"omitempty,uuid"`
	Options       *accesscontrol.AssignmentOptions    `json:"options"`
}

// =============================================================================
// Error Handlers
// =============================================================================

func (h *AssignmentRuleHandler) handleValidationError(w http.ResponseWriter, err error) {
	var validationErrors validator.ValidationErrors
	if errors.As(err, &validationErrors) {
		apiErrors := make([]apierror.ValidationError, len(validationErrors))
		for i, ve := range validationErrors {
			apiErrors[i] = apierror.ValidationError{
				Field:   ve.Field,
				Message: ve.Message,
			}
		}
		apierror.ValidationFailed("Validation failed", apiErrors).WriteJSON(w)
		return
	}
	apierror.BadRequest("Validation error").WriteJSON(w)
}

func (h *AssignmentRuleHandler) handleServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Assignment rule").WriteJSON(w)
	case errors.Is(err, shared.ErrAlreadyExists):
		apierror.Conflict("Assignment rule already exists").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		msg := err.Error()
		if idx := strings.Index(msg, ": "); idx != -1 {
			msg = msg[idx+2:]
		}
		apierror.BadRequest(msg).WriteJSON(w)
	default:
		h.logger.Error("service error", "error", err)
		apierror.InternalError(err).WriteJSON(w)
	}
}

// =============================================================================
// CRUD Handlers
// =============================================================================

// ListRules handles GET /api/v1/assignment-rules
func (h *AssignmentRuleHandler) ListRules(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantID := middleware.MustGetTenantID(ctx)

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

	input := assignment.ListRulesInput{
		TenantID:  tenantID,
		Search:    r.URL.Query().Get("search"),
		Limit:     limit,
		Offset:    offset,
		OrderBy:   r.URL.Query().Get("order_by"),
		OrderDesc: r.URL.Query().Get("order") == "desc",
	}

	// Support both "is_active" (preferred) and "active" (legacy) query params
	activeParam := r.URL.Query().Get("is_active")
	if activeParam == "" {
		activeParam = r.URL.Query().Get("active")
	}
	if active := activeParam; active != "" {
		if parsed, err := strconv.ParseBool(active); err == nil {
			input.IsActive = &parsed
		}
	}

	if gid := r.URL.Query().Get("target_group_id"); gid != "" {
		input.TargetGroupID = &gid
	}

	output, err := h.service.ListRules(ctx, input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	rules := make([]AssignmentRuleResponse, len(output.Rules))
	for i, rule := range output.Rules {
		rules[i] = toAssignmentRuleResponse(rule)
	}

	resp := AssignmentRuleListResponse{
		Rules:      rules,
		TotalCount: output.TotalCount,
		Limit:      limit,
		Offset:     offset,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// CreateRule handles POST /api/v1/assignment-rules
func (h *AssignmentRuleHandler) CreateRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantID := middleware.MustGetTenantID(ctx)

	var req CreateAssignmentRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	createdBy := ""
	if localUser := middleware.GetLocalUser(r.Context()); localUser != nil {
		createdBy = localUser.ID().String()
	}

	input := assignment.CreateRuleInput{
		TenantID:      tenantID,
		Name:          req.Name,
		Description:   req.Description,
		Priority:      req.Priority,
		Conditions:    req.Conditions,
		TargetGroupID: req.TargetGroupID,
		Options:       req.Options,
	}

	rule, err := h.service.CreateRule(ctx, input, createdBy)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(toAssignmentRuleResponse(rule))
}

// GetRule handles GET /api/v1/assignment-rules/{id}
func (h *AssignmentRuleHandler) GetRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantID := middleware.MustGetTenantID(ctx)
	ruleID := chi.URLParam(r, "id")

	rule, err := h.service.GetRule(ctx, tenantID, ruleID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toAssignmentRuleResponse(rule))
}

// UpdateRule handles PUT /api/v1/assignment-rules/{id}
func (h *AssignmentRuleHandler) UpdateRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantID := middleware.MustGetTenantID(ctx)
	ruleID := chi.URLParam(r, "id")

	var req UpdateAssignmentRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := assignment.UpdateRuleInput{
		Name:          req.Name,
		Description:   req.Description,
		Priority:      req.Priority,
		IsActive:      req.IsActive,
		Conditions:    req.Conditions,
		TargetGroupID: req.TargetGroupID,
		Options:       req.Options,
	}

	rule, err := h.service.UpdateRule(ctx, tenantID, ruleID, input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toAssignmentRuleResponse(rule))
}

// DeleteRule handles DELETE /api/v1/assignment-rules/{id}
func (h *AssignmentRuleHandler) DeleteRule(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	ruleID := chi.URLParam(r, "id")

	if err := h.service.DeleteRule(r.Context(), tenantID, ruleID); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// TestRule handles POST /api/v1/assignment-rules/{id}/test
func (h *AssignmentRuleHandler) TestRule(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	ruleID := chi.URLParam(r, "id")

	result, err := h.service.TestRule(r.Context(), tenantID, ruleID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}
