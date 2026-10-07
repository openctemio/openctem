package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	auditsvc "github.com/openctemio/openctem/api/internal/app/audit"
	authapp "github.com/openctemio/openctem/api/internal/app/auth"
	scansvc "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/internal/app/scopeauth"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// ScopeHandler handles scope configuration HTTP requests.
type ScopeHandler struct {
	service   *scope.Service
	audit     *auditsvc.AuditService
	validator *validator.Validator
	logger    *logger.Logger
	scopeJoin ScopeJoinReevaluator
	settings  ScopeSettingsStore
	dryRun    ScopeDryRunner
	coverage  ScopeCoverage
	// activeProof is the operator's SCOPE_ACTIVE_PROOF (read-only view).
	activeProof string
}

// NewScopeHandler creates a new scope handler.
func NewScopeHandler(svc *scope.Service, v *validator.Validator, log *logger.Logger) *ScopeHandler {
	return &ScopeHandler{
		service:   svc,
		validator: v,
		logger:    log,
	}
}

// SetAuditService records every change to scope targets and exclusions in
// the tenant's audit log, with the state before and after (RFC-040 §5.11).
func (h *ScopeHandler) SetAuditService(svc *auditsvc.AuditService) {
	h.audit = svc
}

// notifyExclusionReduced tells every administrator that an exclusion in
// effect was taken away or shortened: scope grew (RFC-054 §7).
func (h *ScopeHandler) notifyExclusionReduced(tenantID string, e *scopedom.Exclusion, title string) {
	id, err := shared.IDFromString(tenantID)
	if err != nil || e == nil {
		return
	}
	h.service.NotifyAdmins(context.Background(), id, title, e.ExclusionType().String()+" "+e.Pattern())
}

// ScopeJoinReevaluator confirms the tenant's pending discovered names that
// its permanent scope targets and seeds cover (*easm.ScopeJoin).
type ScopeJoinReevaluator interface {
	Reevaluate(ctx context.Context, tenantID shared.ID) ([]string, error)
}

// SetScopeJoin re-evaluates the review queue after a scope target becomes
// active (RFC-054 §4.3). Nil: the periodic run picks the change up.
func (h *ScopeHandler) SetScopeJoin(j ScopeJoinReevaluator) { h.scopeJoin = j }

// scopeJoinTimeout bounds one background re-evaluation.
const scopeJoinTimeout = 2 * time.Minute

// reevaluate runs the scope join for the tenant in the background, detached
// from the request (the change is committed; the join is idempotent and the
// periodic run repeats it on failure).
func (h *ScopeHandler) reevaluate(tenantID string, t *scopedom.Target) {
	if h.scopeJoin == nil || t == nil || !t.IsActive() {
		return
	}
	id, err := shared.IDFromString(tenantID)
	if err != nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), scopeJoinTimeout)
		defer cancel()
		if _, err := h.scopeJoin.Reevaluate(ctx, id); err != nil {
			h.logger.Warn("scope join after a scope target change failed", "error", logger.SanitizeError(err))
		}
	}()
}

func (h *ScopeHandler) auditTarget(r *http.Request, action audit.Action, id string, before, after *scopedom.Target) {
	name := ""
	var b, a map[string]any
	if before != nil {
		b, name = auditSnapshot(toScopeTargetResponse(before)), before.Pattern()
	}
	if after != nil {
		a, name = auditSnapshot(toScopeTargetResponse(after)), after.Pattern()
	}
	auditResourceChange(h.audit, h.logger, r, action, audit.ResourceTypeScopeTarget, id, name, b, a)
}

func (h *ScopeHandler) auditExclusion(r *http.Request, action audit.Action, id string, before, after *scopedom.Exclusion) {
	name := ""
	var b, a map[string]any
	if before != nil {
		b, name = auditSnapshot(toScopeExclusionResponse(before)), before.Pattern()
	}
	if after != nil {
		a, name = auditSnapshot(toScopeExclusionResponse(after)), after.Pattern()
	}
	auditResourceChange(h.audit, h.logger, r, action, audit.ResourceTypeScopeExclusion, id, name, b, a)
}

// targetBefore and exclusionBefore read the state a change starts from.
// A failed read answers the request (the change would fail the same way).
func (h *ScopeHandler) targetBefore(w http.ResponseWriter, r *http.Request, tenantID, id string) (*scopedom.Target, bool) {
	t, err := h.service.GetTarget(r.Context(), tenantID, id)
	if err != nil {
		h.handleServiceError(w, "Scope target", err)
		return nil, false
	}
	return t, true
}

func (h *ScopeHandler) exclusionBefore(w http.ResponseWriter, r *http.Request, tenantID, id string) (*scopedom.Exclusion, bool) {
	e, err := h.service.GetExclusion(r.Context(), tenantID, id)
	if err != nil {
		h.handleServiceError(w, "Scope exclusion", err)
		return nil, false
	}
	return e, true
}

// =============================================================================
// Response Types
// =============================================================================

// ScopeTargetResponse represents a scope entry in API responses (RFC-054 §6.1).
type ScopeTargetResponse struct {
	ID         string `json:"id"`
	TenantID   string `json:"tenant_id"`
	TargetType string `json:"target_type"`
	Pattern    string `json:"pattern"`
	// Covers: name, domain_and_subdomains, addresses or pattern.
	Covers      string `json:"covers"`
	Description string `json:"description,omitempty"`
	Reason      string `json:"reason,omitempty"`
	Priority    int    `json:"priority"`
	// Status: active, pending, inactive, rejected or expired.
	Status string `json:"status"`
	// InEffect: the entry authorizes probes now (active, not expired).
	InEffect          bool                    `json:"in_effect"`
	ExpiresAt         *time.Time              `json:"expires_at,omitempty"`
	MaxTier           string                  `json:"max_tier"`
	ApprovalsRequired int                     `json:"approvals_required"`
	Approvals         []ScopeApprovalResponse `json:"approvals"`
	ApprovedAt        *time.Time              `json:"approved_at,omitempty"`
	RejectedBy        string                  `json:"rejected_by,omitempty"`
	RejectedAt        *time.Time              `json:"rejected_at,omitempty"`
	Tags              []string                `json:"tags,omitempty"`
	// CreatedBy is the requester: whoever created or last widened the entry.
	// They cannot approve it.
	CreatedBy string    `json:"created_by,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ScopeApprovalResponse is one approval of a scope entry.
type ScopeApprovalResponse struct {
	UserID     string    `json:"user_id"`
	ApprovedAt time.Time `json:"approved_at"`
}

// ScopeExclusionResponse represents a scope exclusion in API responses.
type ScopeExclusionResponse struct {
	ID            string     `json:"id"`
	TenantID      string     `json:"tenant_id"`
	ExclusionType string     `json:"exclusion_type"`
	Pattern       string     `json:"pattern"`
	Reason        string     `json:"reason"`
	Status        string     `json:"status"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	ApprovedBy    string     `json:"approved_by,omitempty"`
	ApprovedAt    *time.Time `json:"approved_at,omitempty"`
	RejectedBy    string     `json:"rejected_by,omitempty"`
	RejectedAt    *time.Time `json:"rejected_at,omitempty"`
	// InEffect is true only for an approved, active, unexpired exclusion —
	// the ones scans actually skip.
	InEffect  bool      `json:"in_effect"`
	CreatedBy string    `json:"created_by,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// CreateTargetResponseWithWarnings wraps a target response with overlap warnings.
type CreateTargetResponseWithWarnings struct {
	ScopeTargetResponse
	Warnings []string `json:"warnings,omitempty"`
}

// ScopeStatsResponse represents scope statistics in API responses.
type ScopeStatsResponse struct {
	TotalTargets     int64   `json:"total_targets"`
	ActiveTargets    int64   `json:"active_targets"`
	TotalExclusions  int64   `json:"total_exclusions"`
	ActiveExclusions int64   `json:"active_exclusions"`
	Coverage         float64 `json:"coverage"`
}

// =============================================================================
// Request Types
// =============================================================================

// CreateScopeTargetRequest represents the request to create a scope target.
type CreateScopeTargetRequest struct {
	TargetType  string   `json:"target_type" validate:"required"`
	Pattern     string   `json:"pattern" validate:"required,max=500"`
	Description string   `json:"description" validate:"max=1000"`
	Priority    int      `json:"priority" validate:"min=0,max=100"`
	Tags        []string `json:"tags" validate:"max=20,dive,max=50"`
	// Reason is the authority statement; required for a one-off entry, a
	// request and a t2 entry.
	Reason string `json:"reason" validate:"max=1000"`
	// ExpiresInDays (1..one_off_max_days) or ExpiresAt makes a one-off entry.
	ExpiresInDays *int       `json:"expires_in_days" validate:"omitempty,min=1,max=30"`
	ExpiresAt     *time.Time `json:"expires_at"`
	// MaxTier: t0, t1 or t2 (default: the organization's default_max_tier).
	MaxTier string `json:"max_tier" validate:"omitempty,oneof=t0 t1 t2"`
}

// UpdateScopeTargetRequest represents the request to update a scope target.
// A later or removed expiry, or a higher tier, widens the entry.
type UpdateScopeTargetRequest struct {
	Description   *string    `json:"description" validate:"omitempty,max=1000"`
	Priority      *int       `json:"priority" validate:"omitempty,min=0,max=100"`
	Tags          []string   `json:"tags" validate:"omitempty,max=20,dive,max=50"`
	Reason        *string    `json:"reason" validate:"omitempty,max=1000"`
	ExpiresInDays *int       `json:"expires_in_days" validate:"omitempty,min=1,max=30"`
	ExpiresAt     *time.Time `json:"expires_at"`
	ClearExpiry   bool       `json:"clear_expiry"`
	MaxTier       *string    `json:"max_tier" validate:"omitempty,oneof=t0 t1 t2"`
}

// CreateScopeExclusionRequest represents the request to create a scope exclusion.
type CreateScopeExclusionRequest struct {
	ExclusionType string     `json:"exclusion_type" validate:"required"`
	Pattern       string     `json:"pattern" validate:"required,max=500"`
	Reason        string     `json:"reason" validate:"required,max=1000"`
	ExpiresAt     *time.Time `json:"expires_at"`
}

// UpdateScopeExclusionRequest represents the request to update a scope exclusion.
type UpdateScopeExclusionRequest struct {
	Reason    *string    `json:"reason" validate:"omitempty,max=1000"`
	ExpiresAt *time.Time `json:"expires_at"`
}

// BulkDeleteTargetsRequest represents bulk delete targets request.
type BulkDeleteTargetsRequest struct {
	TargetIDs []string `json:"target_ids" validate:"required,min=1,max=100,dive,uuid"`
}

// BulkDeleteExclusionsRequest represents bulk delete exclusions request.
type BulkDeleteExclusionsRequest struct {
	ExclusionIDs []string `json:"exclusion_ids" validate:"required,min=1,max=100,dive,uuid"`
}

// BulkOperationResponse represents the response for bulk operations.
type ScopeBulkOperationResponse struct {
	Success       bool              `json:"success"`
	AffectedCount int               `json:"affected_count"`
	FailedIDs     []string          `json:"failed_ids,omitempty"`
	Errors        map[string]string `json:"errors,omitempty"`
}

// =============================================================================
// Conversion Functions
// =============================================================================

func toScopeTargetResponse(t *scopedom.Target) ScopeTargetResponse {
	return ScopeTargetResponse{
		ID:                t.ID().String(),
		TenantID:          t.TenantID().String(),
		TargetType:        t.TargetType().String(),
		Pattern:           t.Pattern(),
		Covers:            t.Covers(),
		Description:       t.Description(),
		Reason:            t.Reason(),
		Priority:          t.Priority(),
		Status:            t.Status().String(),
		InEffect:          t.InEffect(time.Now()),
		ExpiresAt:         t.ExpiresAt(),
		MaxTier:           t.MaxTier().String(),
		ApprovalsRequired: t.ApprovalsRequired(),
		Approvals:         approvalsResponse(t.Approvals()),
		ApprovedAt:        t.ApprovedAt(),
		RejectedBy:        t.RejectedBy(),
		RejectedAt:        t.RejectedAt(),
		Tags:              t.Tags(),
		CreatedBy:         t.CreatedBy(),
		CreatedAt:         t.CreatedAt(),
		UpdatedAt:         t.UpdatedAt(),
	}
}

func approvalsResponse(list []scopedom.Approval) []ScopeApprovalResponse {
	out := make([]ScopeApprovalResponse, 0, len(list))
	for _, a := range list {
		out = append(out, ScopeApprovalResponse{UserID: a.UserID, ApprovedAt: a.ApprovedAt})
	}
	return out
}

// scopeActor is the caller as a scope actor.
func scopeActor(r *http.Request) scope.Actor {
	ctx := r.Context()
	return scope.Actor{UserID: middleware.GetUserID(ctx), CanApprove: middleware.HasPermission(ctx, permission.ScopeApprove.String())}
}

func toScopeExclusionResponse(e *scopedom.Exclusion) ScopeExclusionResponse {
	return ScopeExclusionResponse{
		ID:            e.ID().String(),
		TenantID:      e.TenantID().String(),
		ExclusionType: e.ExclusionType().String(),
		Pattern:       e.Pattern(),
		Reason:        e.Reason(),
		Status:        e.Status().String(),
		ExpiresAt:     e.ExpiresAt(),
		ApprovedBy:    e.ApprovedBy(),
		ApprovedAt:    e.ApprovedAt(),
		RejectedBy:    e.RejectedBy(),
		RejectedAt:    e.RejectedAt(),
		InEffect:      e.IsActive(),
		CreatedBy:     e.CreatedBy(),
		CreatedAt:     e.CreatedAt(),
		UpdatedAt:     e.UpdatedAt(),
	}
}

// =============================================================================
// Error Handling
// =============================================================================

func (h *ScopeHandler) handleValidationError(w http.ResponseWriter, err error) {
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

func (h *ScopeHandler) handleServiceError(w http.ResponseWriter, resource string, err error) {
	if middleware.WriteStepUpError(w, err, authapp.StepUpWindow) {
		return
	}
	var de *shared.DomainError
	if errors.As(err, &de) && de.Code != "" && de.Code != "STEP_UP_UNAVAILABLE" {
		status := http.StatusBadRequest
		switch {
		case errors.Is(err, shared.ErrForbidden):
			status = http.StatusForbidden
		case errors.Is(err, shared.ErrConflict):
			status = http.StatusConflict
		}
		apierror.New(status, apierror.Code(de.Code), de.Message).WriteJSON(w)
		return
	}
	if errors.As(err, &de) && de.Code == "STEP_UP_UNAVAILABLE" {
		apierror.New(http.StatusForbidden, middleware.CodeStepUpUnavailable, de.Message).WriteJSON(w)
		return
	}
	switch {
	case errors.Is(err, shared.ErrNotFound),
		errors.Is(err, scopedom.ErrTargetNotFound),
		errors.Is(err, scopedom.ErrExclusionNotFound):
		apierror.NotFound(resource).WriteJSON(w)
	case errors.Is(err, shared.ErrAlreadyExists),
		errors.Is(err, scopedom.ErrTargetAlreadyExists),
		errors.Is(err, scopedom.ErrExclusionAlreadyExists):
		apierror.Conflict(resource + " already exists").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	case errors.Is(err, scopedom.ErrExclusionReduceNeedsApprover):
		apierror.Forbidden("Removing or shortening an approved scope exclusion needs the exclusion approval permission").WriteJSON(w)
	case errors.Is(err, scopedom.ErrExclusionSelfReduce):
		apierror.Forbidden("You cannot remove or shorten a scope exclusion you requested; another approver must").WriteJSON(w)
	case errors.Is(err, scopedom.ErrExclusionSelfApproval):
		apierror.Forbidden("You cannot approve a scope exclusion you requested").WriteJSON(w)
	case errors.Is(err, scopedom.ErrExclusionNotPending):
		apierror.Conflict("Scope exclusion is not awaiting approval").WriteJSON(w)
	case errors.Is(err, scopedom.ErrExclusionNotApproved):
		apierror.Conflict("Scope exclusion has not been approved").WriteJSON(w)
	case errors.Is(err, scopedom.ErrExclusionRejected):
		apierror.Conflict("Scope exclusion was rejected").WriteJSON(w)
	case errors.Is(err, shared.ErrForbidden):
		apierror.Forbidden("Access denied").WriteJSON(w)
	default:
		h.logger.Error("service error", "error", err)
		apierror.InternalError(err).WriteJSON(w)
	}
}

// =============================================================================
// Target Handlers
// =============================================================================

// ListTargets handles GET /api/v1/scope/targets
// @Summary      List scope targets
// @Description  Get a paginated list of scope targets for the current tenant
// @Tags         Scope
// @Accept       json
// @Produce      json
// @Param        types     query     string  false  "Filter by target types (comma-separated)"
// @Param        statuses  query     string  false  "Filter by statuses (comma-separated)"
// @Param        tags      query     string  false  "Filter by tags (comma-separated)"
// @Param        search    query     string  false  "Search by pattern"
// @Param        page      query     int     false  "Page number" default(1)
// @Param        per_page  query     int     false  "Items per page" default(20)
// @Success      200  {object}  ListResponse[ScopeTargetResponse]
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scope/targets [get]
func (h *ScopeHandler) ListTargets(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	query := r.URL.Query()

	input := scope.ListTargetsInput{
		TenantID:    tenantID,
		TargetTypes: parseQueryArray(query.Get("types")),
		Statuses:    parseQueryArray(query.Get("statuses")),
		Tags:        parseQueryArray(query.Get("tags")),
		Search:      query.Get("search"),
		Page:        parseQueryInt(query.Get("page"), 1),
		PerPage:     parseQueryIntBounded(query.Get("per_page"), 20, 1, MaxPerPage),
	}

	result, err := h.service.ListTargets(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, "Scope target", err)
		return
	}

	responses := make([]ScopeTargetResponse, len(result.Data))
	for i, target := range result.Data {
		responses[i] = toScopeTargetResponse(target)
	}

	response := ListResponse[ScopeTargetResponse]{
		Data:       responses,
		Total:      result.Total,
		Page:       result.Page,
		PerPage:    result.PerPage,
		TotalPages: result.TotalPages,
		Links:      NewPaginationLinks(r, result.Page, result.PerPage, result.TotalPages),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// CreateTarget handles POST /api/v1/scope/targets
// @Summary      Create scope target
// @Description  Create a scope entry (RFC-054). With attack_surface:scope:approve it needs a recent re-authentication (403 STEP_UP_REQUIRED) and is active at once or pending the organization's approvals; without it, it is a pending request for a one-off entry of one name or address, with a reason
// @Tags         Scope
// @Accept       json
// @Produce      json
// @Param        body  body      CreateScopeTargetRequest  true  "Scope target data"
// @Success      201   {object}  ScopeTargetResponse
// @Failure      400   {object}  apierror.Error
// @Failure      409   {object}  apierror.Error
// @Failure      500   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scope/targets [post]
func (h *ScopeHandler) CreateTarget(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())

	var req CreateScopeTargetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid JSON").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := scope.CreateTargetInput{
		TenantID:      tenantID,
		TargetType:    req.TargetType,
		Pattern:       req.Pattern,
		Description:   req.Description,
		Priority:      req.Priority,
		Tags:          req.Tags,
		CreatedBy:     userID,
		Reason:        req.Reason,
		ExpiresAt:     req.ExpiresAt,
		ExpiresInDays: req.ExpiresInDays,
		MaxTier:       req.MaxTier,
		Actor:         scopeActor(r),
	}

	target, err := h.service.CreateTarget(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, "Scope target", err)
		return
	}
	h.auditTarget(r, audit.ActionScopeTargetCreated, target.ID().String(), nil, target)
	h.reevaluate(tenantID, target)

	// Check for pattern overlaps (non-blocking warnings)
	warnings, overlapErr := h.service.CheckPatternOverlaps(r.Context(), tenantID, req.TargetType, req.Pattern)
	if overlapErr != nil {
		h.logger.Warn("failed to check pattern overlaps", "error", overlapErr)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)

	if len(warnings) > 0 {
		json.NewEncoder(w).Encode(CreateTargetResponseWithWarnings{
			ScopeTargetResponse: toScopeTargetResponse(target),
			Warnings:            warnings,
		})
	} else {
		json.NewEncoder(w).Encode(toScopeTargetResponse(target))
	}
}

// GetTarget handles GET /api/v1/scope/targets/{id}
// @Summary      Get scope target
// @Description  Get a single scope target by ID
// @Tags         Scope
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Target ID"
// @Success      200  {object}  ScopeTargetResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scope/targets/{id} [get]
func (h *ScopeHandler) GetTarget(w http.ResponseWriter, r *http.Request) {
	targetID := chi.URLParam(r, "id")
	tenantID := middleware.MustGetTenantID(r.Context())

	target, err := h.service.GetTarget(r.Context(), tenantID, targetID)
	if err != nil {
		h.handleServiceError(w, "Scope target", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toScopeTargetResponse(target))
}

// UpdateTarget handles PUT /api/v1/scope/targets/{id}
// @Summary      Update scope target
// @Description  Update a scope entry. A later or removed expiry, or a higher tier, widens it: that needs attack_surface:scope:approve and a recent re-authentication (403 STEP_UP_REQUIRED), and sends the entry back to pending when the organization requires approvals (RFC-054)
// @Tags         Scope
// @Accept       json
// @Produce      json
// @Param        id    path      string                    true  "Target ID"
// @Param        body  body      UpdateScopeTargetRequest  true  "Update data"
// @Success      200   {object}  ScopeTargetResponse
// @Failure      400   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Failure      500   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scope/targets/{id} [put]
func (h *ScopeHandler) UpdateTarget(w http.ResponseWriter, r *http.Request) {
	targetID := chi.URLParam(r, "id")
	tenantID := middleware.MustGetTenantID(r.Context())

	var req UpdateScopeTargetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid JSON").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := scope.UpdateTargetInput{
		Description:   req.Description,
		Priority:      req.Priority,
		Tags:          req.Tags,
		Reason:        req.Reason,
		ExpiresAt:     req.ExpiresAt,
		ExpiresInDays: req.ExpiresInDays,
		ClearExpiry:   req.ClearExpiry,
		MaxTier:       req.MaxTier,
		Actor:         scopeActor(r),
	}

	before, ok := h.targetBefore(w, r, tenantID, targetID)
	if !ok {
		return
	}
	target, err := h.service.UpdateTarget(r.Context(), targetID, tenantID, input)
	if err != nil {
		h.handleServiceError(w, "Scope target", err)
		return
	}
	h.auditTarget(r, audit.ActionScopeTargetUpdated, targetID, before, target)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toScopeTargetResponse(target))
}

// DeleteTarget handles DELETE /api/v1/scope/targets/{id}
// @Summary      Delete scope target
// @Description  Delete a scope target
// @Tags         Scope
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Target ID"
// @Success      204  "No Content"
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scope/targets/{id} [delete]
func (h *ScopeHandler) DeleteTarget(w http.ResponseWriter, r *http.Request) {
	targetID := chi.URLParam(r, "id")
	tenantID := middleware.MustGetTenantID(r.Context())

	before, ok := h.targetBefore(w, r, tenantID, targetID)
	if !ok {
		return
	}
	if err := h.service.DeleteTarget(r.Context(), targetID, tenantID); err != nil {
		h.handleServiceError(w, "Scope target", err)
		return
	}
	h.auditTarget(r, audit.ActionScopeTargetDeleted, targetID, before, nil)

	w.WriteHeader(http.StatusNoContent)
}

// ActivateTarget handles POST /api/v1/scope/targets/{id}/activate
// @Summary      Activate scope target
// @Description  Activate a scope entry. Widening: needs attack_surface:scope:approve and a recent re-authentication, then the organization's approvals
// @Tags         Scope
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Target ID"
// @Success      200  {object}  ScopeTargetResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scope/targets/{id}/activate [post]
func (h *ScopeHandler) ActivateTarget(w http.ResponseWriter, r *http.Request) {
	targetID := chi.URLParam(r, "id")
	tenantID := middleware.MustGetTenantID(r.Context())

	before, ok := h.targetBefore(w, r, tenantID, targetID)
	if !ok {
		return
	}
	target, err := h.service.ActivateTarget(r.Context(), targetID, tenantID, scopeActor(r))
	if err != nil {
		h.handleServiceError(w, "Scope target", err)
		return
	}
	h.auditTarget(r, audit.ActionScopeTargetActivated, targetID, before, target)
	h.reevaluate(tenantID, target)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toScopeTargetResponse(target))
}

// DeactivateTarget handles POST /api/v1/scope/targets/{id}/deactivate
// @Summary      Deactivate scope target
// @Description  Deactivate a scope target
// @Tags         Scope
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Target ID"
// @Success      200  {object}  ScopeTargetResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scope/targets/{id}/deactivate [post]
func (h *ScopeHandler) DeactivateTarget(w http.ResponseWriter, r *http.Request) {
	targetID := chi.URLParam(r, "id")
	tenantID := middleware.MustGetTenantID(r.Context())

	before, ok := h.targetBefore(w, r, tenantID, targetID)
	if !ok {
		return
	}
	target, err := h.service.DeactivateTarget(r.Context(), targetID, tenantID)
	if err != nil {
		h.handleServiceError(w, "Scope target", err)
		return
	}
	h.auditTarget(r, audit.ActionScopeTargetDeactivated, targetID, before, target)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toScopeTargetResponse(target))
}

// =============================================================================
// Exclusion Handlers
// =============================================================================

// ListExclusions handles GET /api/v1/scope/exclusions
// @Summary      List scope exclusions
// @Description  Get a paginated list of scope exclusions for the current tenant
// @Tags         Scope
// @Accept       json
// @Produce      json
// @Param        types        query     string  false  "Filter by exclusion types (comma-separated)"
// @Param        statuses     query     string  false  "Filter by statuses (comma-separated)"
// @Param        is_approved  query     bool    false  "Filter by approval status"
// @Param        search       query     string  false  "Search by pattern"
// @Param        page         query     int     false  "Page number" default(1)
// @Param        per_page     query     int     false  "Items per page" default(20)
// @Success      200  {object}  ListResponse[ScopeExclusionResponse]
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scope/exclusions [get]
func (h *ScopeHandler) ListExclusions(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	query := r.URL.Query()

	input := scope.ListExclusionsInput{
		TenantID:       tenantID,
		ExclusionTypes: parseQueryArray(query.Get("types")),
		Statuses:       parseQueryArray(query.Get("statuses")),
		IsApproved:     parseQueryBoolPtr(query.Get("is_approved")),
		Search:         query.Get("search"),
		Page:           parseQueryInt(query.Get("page"), 1),
		PerPage:        parseQueryIntBounded(query.Get("per_page"), 20, 1, MaxPerPage),
	}

	result, err := h.service.ListExclusions(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, "Scope exclusion", err)
		return
	}

	responses := make([]ScopeExclusionResponse, len(result.Data))
	for i, exclusion := range result.Data {
		responses[i] = toScopeExclusionResponse(exclusion)
	}

	response := ListResponse[ScopeExclusionResponse]{
		Data:       responses,
		Total:      result.Total,
		Page:       result.Page,
		PerPage:    result.PerPage,
		TotalPages: result.TotalPages,
		Links:      NewPaginationLinks(r, result.Page, result.PerPage, result.TotalPages),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// CreateExclusion handles POST /api/v1/scope/exclusions
// @Summary      Create scope exclusion
// @Description  Create a scope exclusion. It is created pending and does not affect scanning until another user approves it (attack_surface:scope:exclusions:approve).
// @Tags         Scope
// @Accept       json
// @Produce      json
// @Param        body  body      CreateScopeExclusionRequest  true  "Scope exclusion data"
// @Success      201   {object}  ScopeExclusionResponse
// @Failure      400   {object}  apierror.Error
// @Failure      409   {object}  apierror.Error
// @Failure      500   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scope/exclusions [post]
func (h *ScopeHandler) CreateExclusion(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())

	var req CreateScopeExclusionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid JSON").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := scope.CreateExclusionInput{
		TenantID:      tenantID,
		ExclusionType: req.ExclusionType,
		Pattern:       req.Pattern,
		Reason:        req.Reason,
		ExpiresAt:     req.ExpiresAt,
		CreatedBy:     userID,
	}

	exclusion, err := h.service.CreateExclusion(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, "Scope exclusion", err)
		return
	}
	h.auditExclusion(r, audit.ActionScopeExclusionCreated, exclusion.ID().String(), nil, exclusion)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(toScopeExclusionResponse(exclusion))
}

// GetExclusion handles GET /api/v1/scope/exclusions/{id}
// @Summary      Get scope exclusion
// @Description  Get a single scope exclusion by ID
// @Tags         Scope
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Exclusion ID"
// @Success      200  {object}  ScopeExclusionResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scope/exclusions/{id} [get]
func (h *ScopeHandler) GetExclusion(w http.ResponseWriter, r *http.Request) {
	exclusionID := chi.URLParam(r, "id")
	tenantID := middleware.MustGetTenantID(r.Context())

	exclusion, err := h.service.GetExclusion(r.Context(), tenantID, exclusionID)
	if err != nil {
		h.handleServiceError(w, "Scope exclusion", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toScopeExclusionResponse(exclusion))
}

// UpdateExclusion handles PUT /api/v1/scope/exclusions/{id}
// @Summary      Update scope exclusion
// @Description  Update an existing scope exclusion
// @Tags         Scope
// @Accept       json
// @Produce      json
// @Param        id    path      string                       true  "Exclusion ID"
// @Param        body  body      UpdateScopeExclusionRequest  true  "Update data"
// @Success      200   {object}  ScopeExclusionResponse
// @Failure      400   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Failure      500   {object}  apierror.Error
// @Security     BearerAuth
// @Failure      403  {object}  apierror.Error "Takes an exclusion in effect out of effect or shortens it without the approval permission, or by its requester"
// @Router       /scope/exclusions/{id} [put]
func (h *ScopeHandler) UpdateExclusion(w http.ResponseWriter, r *http.Request) {
	exclusionID := chi.URLParam(r, "id")
	tenantID := middleware.MustGetTenantID(r.Context())

	var req UpdateScopeExclusionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid JSON").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := scope.UpdateExclusionInput{
		Reason:    req.Reason,
		ExpiresAt: req.ExpiresAt,
		Reviewer:  exclusionReviewer(r),
	}

	before, ok := h.exclusionBefore(w, r, tenantID, exclusionID)
	if !ok {
		return
	}
	exclusion, err := h.service.UpdateExclusion(r.Context(), exclusionID, tenantID, input)
	if err != nil {
		h.handleServiceError(w, "Scope exclusion", err)
		return
	}
	h.auditExclusion(r, audit.ActionScopeExclusionUpdated, exclusionID, before, exclusion)
	if req.ExpiresAt != nil && before.InEffect() && before.ShortensWindow(req.ExpiresAt) {
		h.notifyExclusionReduced(tenantID, before, "Scope exclusion shortened")
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toScopeExclusionResponse(exclusion))
}

// exclusionReviewer is the caller as the exclusion rules see them: their id
// and whether they hold the exclusion approval permission (owner and admin
// hold every permission).
func exclusionReviewer(r *http.Request) scopedom.Reviewer {
	return scopedom.Reviewer{
		UserID:     middleware.GetUserID(r.Context()),
		CanApprove: middleware.HasPermission(r.Context(), permission.ScopeExclusionsApprove.String()),
	}
}

// DeleteExclusion handles DELETE /api/v1/scope/exclusions/{id}
// @Summary      Delete scope exclusion
// @Description  Delete a scope exclusion
// @Tags         Scope
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Exclusion ID"
// @Success      204  "No Content"
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Failure      403  {object}  apierror.Error "Takes an exclusion in effect out of effect or shortens it without the approval permission, or by its requester"
// @Router       /scope/exclusions/{id} [delete]
func (h *ScopeHandler) DeleteExclusion(w http.ResponseWriter, r *http.Request) {
	exclusionID := chi.URLParam(r, "id")
	tenantID := middleware.MustGetTenantID(r.Context())

	before, ok := h.exclusionBefore(w, r, tenantID, exclusionID)
	if !ok {
		return
	}
	if err := h.service.DeleteExclusion(r.Context(), exclusionID, tenantID, exclusionReviewer(r)); err != nil {
		h.handleServiceError(w, "Scope exclusion", err)
		return
	}
	h.auditExclusion(r, audit.ActionScopeExclusionDeleted, exclusionID, before, nil)
	if before.InEffect() {
		h.notifyExclusionReduced(tenantID, before, "Scope exclusion removed")
	}

	w.WriteHeader(http.StatusNoContent)
}

// ApproveExclusion handles POST /api/v1/scope/exclusions/{id}/approve
// @Summary      Approve scope exclusion
// @Description  Approve a pending scope exclusion; it takes effect immediately. Requires attack_surface:scope:exclusions:approve. The requester cannot approve their own exclusion.
// @Tags         Scope
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Exclusion ID"
// @Success      200  {object}  ScopeExclusionResponse
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error "The caller requested this exclusion (separation of duties)"
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error "Already approved, or rejected"
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scope/exclusions/{id}/approve [post]
func (h *ScopeHandler) ApproveExclusion(w http.ResponseWriter, r *http.Request) {
	exclusionID := chi.URLParam(r, "id")
	tenantID := middleware.MustGetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())

	before, ok := h.exclusionBefore(w, r, tenantID, exclusionID)
	if !ok {
		return
	}
	exclusion, err := h.service.ApproveExclusion(r.Context(), exclusionID, tenantID, userID)
	if err != nil {
		h.handleServiceError(w, "Scope exclusion", err)
		return
	}
	h.auditExclusion(r, audit.ActionScopeExclusionApproved, exclusionID, before, exclusion)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toScopeExclusionResponse(exclusion))
}

// RejectExclusion handles POST /api/v1/scope/exclusions/{id}/reject
// @Summary      Reject scope exclusion
// @Description  Reject a pending scope exclusion; it never takes effect. Requires attack_surface:scope:exclusions:approve.
// @Tags         Scope
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Exclusion ID"
// @Success      200  {object}  ScopeExclusionResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error "Not awaiting approval"
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scope/exclusions/{id}/reject [post]
func (h *ScopeHandler) RejectExclusion(w http.ResponseWriter, r *http.Request) {
	exclusionID := chi.URLParam(r, "id")
	tenantID := middleware.MustGetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())

	before, ok := h.exclusionBefore(w, r, tenantID, exclusionID)
	if !ok {
		return
	}
	exclusion, err := h.service.RejectExclusion(r.Context(), exclusionID, tenantID, userID)
	if err != nil {
		h.handleServiceError(w, "Scope exclusion", err)
		return
	}
	h.auditExclusion(r, audit.ActionScopeExclusionRejected, exclusionID, before, exclusion)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toScopeExclusionResponse(exclusion))
}

// ActivateExclusion handles POST /api/v1/scope/exclusions/{id}/activate
// @Summary      Activate scope exclusion
// @Description  Put an approved scope exclusion back into effect. A pending or rejected exclusion cannot be activated (409).
// @Tags         Scope
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Exclusion ID"
// @Success      200  {object}  ScopeExclusionResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Failure      409  {object}  apierror.Error "Not approved, or rejected"
// @Router       /scope/exclusions/{id}/activate [post]
func (h *ScopeHandler) ActivateExclusion(w http.ResponseWriter, r *http.Request) {
	exclusionID := chi.URLParam(r, "id")
	tenantID := middleware.MustGetTenantID(r.Context())

	before, ok := h.exclusionBefore(w, r, tenantID, exclusionID)
	if !ok {
		return
	}
	exclusion, err := h.service.ActivateExclusion(r.Context(), exclusionID, tenantID)
	if err != nil {
		h.handleServiceError(w, "Scope exclusion", err)
		return
	}
	h.auditExclusion(r, audit.ActionScopeExclusionActivated, exclusionID, before, exclusion)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toScopeExclusionResponse(exclusion))
}

// DeactivateExclusion handles POST /api/v1/scope/exclusions/{id}/deactivate
// @Summary      Deactivate scope exclusion
// @Description  Deactivate a scope exclusion
// @Tags         Scope
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Exclusion ID"
// @Success      200  {object}  ScopeExclusionResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Failure      403  {object}  apierror.Error "Takes an exclusion in effect out of effect or shortens it without the approval permission, or by its requester"
// @Router       /scope/exclusions/{id}/deactivate [post]
func (h *ScopeHandler) DeactivateExclusion(w http.ResponseWriter, r *http.Request) {
	exclusionID := chi.URLParam(r, "id")
	tenantID := middleware.MustGetTenantID(r.Context())

	before, ok := h.exclusionBefore(w, r, tenantID, exclusionID)
	if !ok {
		return
	}
	exclusion, err := h.service.DeactivateExclusion(r.Context(), exclusionID, tenantID, exclusionReviewer(r))
	if err != nil {
		h.handleServiceError(w, "Scope exclusion", err)
		return
	}
	h.auditExclusion(r, audit.ActionScopeExclusionDeactivated, exclusionID, before, exclusion)
	if before.InEffect() {
		h.notifyExclusionReduced(tenantID, before, "Scope exclusion deactivated")
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toScopeExclusionResponse(exclusion))
}

// =============================================================================
// Stats & Check Handlers
// =============================================================================

// GetStats handles GET /api/v1/scope/stats
// @Summary      Get scope statistics
// @Description  Get aggregate statistics for scope targets and exclusions
// @Tags         Scope
// @Produce      json
// @Success      200  {object}  ScopeStatsResponse
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scope/stats [get]
func (h *ScopeHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	stats, err := h.service.GetStats(r.Context(), tenantID)
	if err != nil {
		h.handleServiceError(w, "Scope stats", err)
		return
	}

	response := ScopeStatsResponse{
		TotalTargets:     stats.TotalTargets,
		ActiveTargets:    stats.ActiveTargets,
		TotalExclusions:  stats.TotalExclusions,
		ActiveExclusions: stats.ActiveExclusions,
		Coverage:         stats.Coverage,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// ScopeDryRunner runs the active-probe gate without dispatching
// (*scan.Service).
type ScopeDryRunner interface {
	DryRunTargets(ctx context.Context, in scansvc.DryRunInput) ([]scansvc.DryRunResult, error)
}

// ScopeCoverage names what covers each target (*easm.ActiveGate).
type ScopeCoverage interface {
	CoverOf(ctx context.Context, tenantID shared.ID, targets []string) (map[string]scopeauth.Via, error)
}

// SetDryRun wires POST /scope/check (RFC-054 §6.4).
func (h *ScopeHandler) SetDryRun(r ScopeDryRunner, c ScopeCoverage) { h.dryRun, h.coverage = r, c }

// CheckScopeRequest asks what the gate would do with each target and
// inventory asset (at least one, at most 200 together).
type CheckScopeRequest struct {
	Targets []string `json:"targets" validate:"omitempty,max=200,dive,min=1,max=500"`
	// AssetIDs are inventory assets, checked by their name as a scan of them
	// would be. An id the caller may not see answers out_of_data_scope.
	AssetIDs []string `json:"asset_ids" validate:"omitempty,max=200,dive,uuid"`
	// SensorPreference: auto (default), tenant or platform.
	SensorPreference string `json:"sensor_preference" validate:"omitempty,oneof=auto tenant platform"`
	// Tier: 0 passive, 1 safe active (default), 2 intrusive.
	Tier *int `json:"tier" validate:"omitempty,min=0,max=2"`
}

// ScopeCheckVia is what authorizes an allowed target.
type ScopeCheckVia struct {
	// Kind: scope_target, seed, verified_domain or internal (zone-gated).
	Kind    string `json:"kind"`
	ID      string `json:"id,omitempty"`
	Pattern string `json:"pattern,omitempty"`
	// Proof: verified or asserted.
	Proof string `json:"proof,omitempty"`
}

// ScopeCheckZone is the scan zone an allowed private target routes to.
type ScopeCheckZone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// ScopeCheckResult is the gate's answer for one target.
type ScopeCheckResult struct {
	// Target is the typed target or the asset's name; for an asset the
	// caller may not see, its id.
	Target string `json:"target"`
	// AssetID is set for an asset_ids entry.
	AssetID string            `json:"asset_id,omitempty"`
	Allowed bool              `json:"allowed"`
	Via     *ScopeCheckVia    `json:"via,omitempty"`
	Zone    *ScopeCheckZone   `json:"zone,omitempty"`
	Code    string            `json:"code,omitempty"`
	Message string            `json:"message,omitempty"`
	Rule    *scopedom.RuleRef `json:"rule,omitempty"`
	Fixes   []scopedom.Fix    `json:"fixes,omitempty"`
}

// CheckScopeResponse lists the answers in input order.
type CheckScopeResponse struct {
	Results []ScopeCheckResult `json:"results"`
}

// CheckScope handles POST /api/v1/scope/check
// @Summary      Dry run of the active-probe gate
// @Description  For each target and inventory asset, what a scan by the caller would do now (RFC-054 §6.4): allowed with what authorizes it, or refused with a code, the caller's own rule that refused it and the fixes the caller may take. Runs the act scope, the target validator, exclusions, ownership and scope authority, the platform guardrails, zones and the proof requirement; dispatches, logs and audits nothing. An asset is checked by its name; one outside the caller's data scope, or not the organization's, answers out_of_data_scope with its id only. At most 200 targets and assets together.
// @Tags         Scope
// @Accept       json
// @Produce      json
// @Param        body  body      CheckScopeRequest  true  "Targets"
// @Success      200   {object}  CheckScopeResponse
// @Failure      400   {object}  apierror.Error
// @Failure      500   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scope/check [post]
func (h *ScopeHandler) CheckScope(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantID := middleware.MustGetTenantID(ctx)
	var req CheckScopeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid JSON").WriteJSON(w)
		return
	}
	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}
	if n := len(req.Targets) + len(req.AssetIDs); n == 0 || n > scansvc.MaxDryRunTargets {
		apierror.BadRequest(fmt.Sprintf("send 1 to %d targets and asset_ids together", scansvc.MaxDryRunTargets)).WriteJSON(w)
		return
	}
	assetIDs := make([]shared.ID, 0, len(req.AssetIDs))
	for _, raw := range req.AssetIDs {
		id, err := shared.IDFromString(raw)
		if err != nil {
			apierror.BadRequest("asset_ids must be UUIDs").WriteJSON(w)
			return
		}
		assetIDs = append(assetIDs, id)
	}
	if h.dryRun == nil || h.coverage == nil {
		apierror.InternalServerError("the scope check is not available").WriteJSON(w)
		return
	}
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		apierror.Unauthorized("Invalid tenant ID").WriteJSON(w)
		return
	}
	tier := 1
	if req.Tier != nil {
		tier = *req.Tier
	}
	results, err := h.dryRun.DryRunTargets(ctx, scansvc.DryRunInput{TenantID: tid, Targets: req.Targets, AssetIDs: assetIDs, SensorPreference: req.SensorPreference, Tier: tier})
	if err != nil {
		h.handleServiceError(w, "Scope check", err)
		return
	}
	explain, err := h.service.NewExplainer(ctx, tenantID)
	if err != nil {
		h.logger.Error("scope check: explain", "error", logger.SanitizeError(err))
		apierror.InternalServerError("the scope check failed").WriteJSON(w)
		return
	}
	var allowed []string
	for _, res := range results {
		if res.Allowed {
			allowed = append(allowed, res.Target)
		}
	}
	cover := map[string]scopeauth.Via{}
	if len(allowed) > 0 {
		if cover, err = h.coverage.CoverOf(ctx, tid, allowed); err != nil {
			h.logger.Error("scope check: coverage", "error", logger.SanitizeError(err))
			apierror.InternalServerError("the scope check failed").WriteJSON(w)
			return
		}
	}
	has := func(p string) bool { return middleware.HasPermission(ctx, p) }
	out := CheckScopeResponse{Results: make([]ScopeCheckResult, 0, len(results))}
	for _, res := range results {
		item := ScopeCheckResult{Target: res.Target, AssetID: res.AssetID, Allowed: res.Allowed}
		if res.Allowed {
			if v, ok := cover[res.Target]; ok {
				item.Via = &ScopeCheckVia{Kind: v.Kind, ID: v.ID, Pattern: v.Pattern, Proof: v.Proof}
			} else {
				item.Via = &ScopeCheckVia{Kind: "internal"}
			}
			if res.ZoneID != "" {
				item.Zone = &ScopeCheckZone{ID: res.ZoneID, Name: res.ZoneName}
			}
			out.Results = append(out.Results, item)
			continue
		}
		code := res.Code
		var rule *scopedom.RuleRef
		switch code {
		case scopedom.RefusalNoEntry:
			code, rule = explain.Uncovered(res.Target)
		case scopedom.RefusalExcluded:
			rule = explain.Exclusion(res.Target)
		case scopedom.RefusalDenyList:
			rule = &scopedom.RuleRef{Kind: scopedom.RulePlatformPolicy}
		}
		ref := scopedom.NewRefusal(res.Target, code, rule, explain.OneOffDays())
		if ref.Message == "" {
			ref.Message = res.Reason
		}
		item.Code, item.Message, item.Rule = ref.Code, ref.Message, ref.Rule
		item.Fixes = scopedom.FilterFixes(ref.Fixes, has)
		out.Results = append(out.Results, item)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// BulkDeleteTargets handles POST /api/v1/scope/targets/bulk/delete
// @Summary      Bulk delete scope targets
// @Description  Delete multiple scope targets in a single operation
// @Tags         Scope
// @Accept       json
// @Produce      json
// @Param        body  body      BulkDeleteTargetsRequest  true  "Target IDs to delete"
// @Success      200   {object}  ScopeBulkOperationResponse
// @Failure      400   {object}  apierror.Error
// @Failure      401   {object}  apierror.Error
// @Failure      500   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scope/targets/bulk/delete [post]
func (h *ScopeHandler) BulkDeleteTargets(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	var req BulkDeleteTargetsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	result := h.bulkDeleteItems(r.Context(), req.TargetIDs, tenantID, func(ctx context.Context, id, tid string) error {
		before, err := h.service.GetTarget(ctx, tid, id)
		if err != nil {
			return err
		}
		if err := h.service.DeleteTarget(ctx, id, tid); err != nil {
			return err
		}
		h.auditTarget(r, audit.ActionScopeTargetDeleted, id, before, nil)
		return nil
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// BulkDeleteExclusions handles POST /api/v1/scope/exclusions/bulk/delete
// @Summary      Bulk delete scope exclusions
// @Description  Delete multiple scope exclusions in a single operation
// @Tags         Scope
// @Accept       json
// @Produce      json
// @Param        body  body      BulkDeleteExclusionsRequest  true  "Exclusion IDs to delete"
// @Success      200   {object}  ScopeBulkOperationResponse
// @Failure      400   {object}  apierror.Error
// @Failure      401   {object}  apierror.Error
// @Failure      500   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scope/exclusions/bulk/delete [post]
func (h *ScopeHandler) BulkDeleteExclusions(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	var req BulkDeleteExclusionsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	result := h.bulkDeleteItems(r.Context(), req.ExclusionIDs, tenantID, func(ctx context.Context, id, tid string) error {
		before, err := h.service.GetExclusion(ctx, tid, id)
		if err != nil {
			return err
		}
		if err := h.service.DeleteExclusion(ctx, id, tid, exclusionReviewer(r)); err != nil {
			return err
		}
		h.auditExclusion(r, audit.ActionScopeExclusionDeleted, id, before, nil)
		return nil
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// bulkDeleteItems is a helper for bulk delete operations.
func (h *ScopeHandler) bulkDeleteItems(
	ctx context.Context,
	ids []string,
	tenantID string,
	deleteFn func(ctx context.Context, id, tenantID string) error,
) ScopeBulkOperationResponse {
	var failedIDs []string
	errs := make(map[string]string)
	affected := 0

	for _, id := range ids {
		if err := deleteFn(ctx, id, tenantID); err != nil {
			failedIDs = append(failedIDs, id)
			errs[id] = err.Error()
		} else {
			affected++
		}
	}

	return ScopeBulkOperationResponse{
		Success:       len(failedIDs) == 0,
		AffectedCount: affected,
		FailedIDs:     failedIDs,
		Errors:        errs,
	}
}
