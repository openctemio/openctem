package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/permissionset"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/validator"
)

// PermissionSetHandler handles permission set related HTTP requests.
type PermissionSetHandler struct {
	service   *app.PermissionService
	validator *validator.Validator
	logger    *logger.Logger
}

// NewPermissionSetHandler creates a new permission set handler.
func NewPermissionSetHandler(svc *app.PermissionService, v *validator.Validator, log *logger.Logger) *PermissionSetHandler {
	return &PermissionSetHandler{
		service:   svc,
		validator: v,
		logger:    log,
	}
}

// =============================================================================
// Response Types
// =============================================================================

// PermissionSetResponse represents a permission set in API responses.
type PermissionSetResponse struct {
	ID          string    `json:"id"`
	TenantID    *string   `json:"tenant_id,omitempty"`
	Name        string    `json:"name"`
	Slug        string    `json:"slug"`
	Description string    `json:"description,omitempty"`
	SetType     string    `json:"set_type"`
	ParentSetID *string   `json:"parent_set_id,omitempty"`
	IsActive    bool      `json:"is_active"`
	IsSystem    bool      `json:"is_system"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// PermissionSetWithItemsResponse includes permission items.
type PermissionSetWithItemsResponse struct {
	PermissionSetResponse
	Items       []PermissionItemResponse `json:"items"`
	Permissions []string                 `json:"permissions"` // Resolved permissions
}

// PermissionItemResponse represents a permission item in API responses.
type PermissionItemResponse struct {
	PermissionID     string `json:"permission_id"`
	ModificationType string `json:"modification_type"`
}

// PermissionSetListResponse represents a paginated list of permission sets.
type PermissionSetListResponse struct {
	PermissionSets []PermissionSetResponse `json:"permission_sets"`
	TotalCount     int64                   `json:"total_count"`
	Limit          int                     `json:"limit"`
	Offset         int                     `json:"offset"`
}

// =============================================================================
// Request Types
// =============================================================================

// CreatePermissionSetRequest represents the request to create a permission set.
type CreatePermissionSetRequest struct {
	Name        string   `json:"name" validate:"required,min=2,max=100"`
	Slug        string   `json:"slug" validate:"required,min=2,max=100,slug"`
	Description string   `json:"description" validate:"max=500"`
	SetType     string   `json:"set_type" validate:"required,oneof=custom extended cloned"`
	ParentSetID *string  `json:"parent_set_id,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
}

// UpdatePermissionSetRequest represents the request to update a permission set.
type UpdatePermissionSetRequest struct {
	Name        *string `json:"name" validate:"omitempty,min=2,max=100"`
	Description *string `json:"description" validate:"omitempty,max=500"`
	IsActive    *bool   `json:"is_active,omitempty"`
}

// AddPermissionRequest represents the request to add a permission to a set.
type AddPermissionRequest struct {
	PermissionID     string `json:"permission_id" validate:"required"`
	ModificationType string `json:"modification_type" validate:"omitempty,oneof=add remove"`
}

// =============================================================================
// Helper Functions
// =============================================================================

func toPermissionSetResponse(ps *permissionset.PermissionSet) PermissionSetResponse {
	resp := PermissionSetResponse{
		ID:          ps.ID().String(),
		Name:        ps.Name(),
		Slug:        ps.Slug(),
		Description: ps.Description(),
		SetType:     ps.SetType().String(),
		IsActive:    ps.IsActive(),
		IsSystem:    ps.IsSystem(),
		CreatedAt:   ps.CreatedAt(),
		UpdatedAt:   ps.UpdatedAt(),
	}

	if ps.TenantID() != nil {
		tid := ps.TenantID().String()
		resp.TenantID = &tid
	}

	if ps.ParentSetID() != nil {
		pid := ps.ParentSetID().String()
		resp.ParentSetID = &pid
	}

	return resp
}

func toPermissionSetWithItemsResponse(ps *permissionset.PermissionSetWithItems, resolvedPerms []string) PermissionSetWithItemsResponse {
	resp := PermissionSetWithItemsResponse{
		PermissionSetResponse: toPermissionSetResponse(ps.PermissionSet),
		Items:                 make([]PermissionItemResponse, 0, len(ps.Items)),
		Permissions:           resolvedPerms,
	}

	for _, item := range ps.Items {
		resp.Items = append(resp.Items, PermissionItemResponse{
			PermissionID:     item.PermissionID(),
			ModificationType: item.ModificationType().String(),
		})
	}

	return resp
}

func (h *PermissionSetHandler) buildAuditContext(r *http.Request) app.AuditContext {
	actx := app.AuditContext{
		ActorIP:   r.RemoteAddr,
		UserAgent: r.UserAgent(),
		RequestID: r.Header.Get("X-Request-ID"),
	}

	if localUser := middleware.GetLocalUser(r.Context()); localUser != nil {
		actx.ActorID = localUser.ID().String()
		actx.ActorEmail = localUser.Email()
	}

	if tenantID := middleware.GetTenantID(r.Context()); tenantID != "" {
		actx.TenantID = tenantID
	}

	return actx
}

func (h *PermissionSetHandler) handleValidationError(w http.ResponseWriter, err error) {
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

func (h *PermissionSetHandler) handleServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Permission set").WriteJSON(w)
	case errors.Is(err, shared.ErrAlreadyExists):
		apierror.Conflict("Permission set already exists").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		msg := err.Error()
		if idx := strings.Index(msg, ": "); idx != -1 {
			msg = msg[idx+2:]
		}
		apierror.BadRequest(msg).WriteJSON(w)
	case errors.Is(err, shared.ErrUnauthorized):
		apierror.Unauthorized(err.Error()).WriteJSON(w)
	case errors.Is(err, shared.ErrForbidden):
		apierror.Forbidden(err.Error()).WriteJSON(w)
	default:
		h.logger.Error("service error", "error", err)
		apierror.InternalError(err).WriteJSON(w)
	}
}

// =============================================================================
// Permission Set CRUD Handlers
// =============================================================================

// CreatePermissionSet handles POST /api/v1/permission-sets
// @Summary Create a new permission set
// @Description Create a new permission set for access control
// @Tags permission-sets
// @Accept json
// @Produce json
// @Param request body CreatePermissionSetRequest true "Permission set details"
// @Success 201 {object} PermissionSetResponse
// @Failure 400 {object} apierror.Error
// @Failure 401 {object} apierror.Error
// @Failure 403 {object} apierror.Error
// @Router /api/v1/permission-sets [post]
func (h *PermissionSetHandler) CreatePermissionSet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	tenantID := middleware.MustGetTenantID(ctx)

	var req CreatePermissionSetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := app.CreatePermissionSetInput{
		TenantID:    tenantID,
		Name:        req.Name,
		Slug:        req.Slug,
		Description: req.Description,
		SetType:     req.SetType,
		ParentSetID: req.ParentSetID,
		Permissions: req.Permissions,
	}

	actx := h.buildAuditContext(r)

	ps, err := h.service.CreatePermissionSet(ctx, input, actx)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(toPermissionSetResponse(ps))
}

// GetPermissionSet handles GET /api/v1/permission-sets/{id}
// @Summary Get a permission set by ID
// @Description Get detailed information about a permission set
// @Tags permission-sets
// @Produce json
// @Param id path string true "Permission set ID"
// @Success 200 {object} PermissionSetWithItemsResponse
// @Failure 404 {object} apierror.Error
// @Router /api/v1/permission-sets/{id} [get]
func (h *PermissionSetHandler) GetPermissionSet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id := r.PathValue("id")
	if id == "" {
		apierror.BadRequest("Permission set ID is required").WriteJSON(w)
		return
	}

	psWithItems, err := h.service.GetPermissionSetWithItems(ctx, id)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// Get resolved permissions
	var resolvedPerms []string
	// For now, just collect the added permissions from items
	for _, item := range psWithItems.Items {
		if item.ModificationType() == permissionset.ModificationAdd {
			resolvedPerms = append(resolvedPerms, item.PermissionID())
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toPermissionSetWithItemsResponse(psWithItems, resolvedPerms))
}

// UpdatePermissionSet handles PUT /api/v1/permission-sets/{id}
// @Summary Update a permission set
// @Description Update an existing permission set
// @Tags permission-sets
// @Accept json
// @Produce json
// @Param id path string true "Permission set ID"
// @Param request body UpdatePermissionSetRequest true "Update details"
// @Success 200 {object} PermissionSetResponse
// @Failure 400 {object} apierror.Error
// @Failure 404 {object} apierror.Error
// @Router /api/v1/permission-sets/{id} [put]
func (h *PermissionSetHandler) UpdatePermissionSet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id := r.PathValue("id")
	if id == "" {
		apierror.BadRequest("Permission set ID is required").WriteJSON(w)
		return
	}

	var req UpdatePermissionSetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := app.UpdatePermissionSetInput{
		Name:        req.Name,
		Description: req.Description,
		IsActive:    req.IsActive,
	}

	actx := h.buildAuditContext(r)

	ps, err := h.service.UpdatePermissionSet(ctx, id, input, actx)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toPermissionSetResponse(ps))
}

// DeletePermissionSet handles DELETE /api/v1/permission-sets/{id}
// @Summary Delete a permission set
// @Description Delete a permission set
// @Tags permission-sets
// @Param id path string true "Permission set ID"
// @Success 204
// @Failure 400 {object} apierror.Error
// @Failure 404 {object} apierror.Error
// @Router /api/v1/permission-sets/{id} [delete]
func (h *PermissionSetHandler) DeletePermissionSet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id := r.PathValue("id")
	if id == "" {
		apierror.BadRequest("Permission set ID is required").WriteJSON(w)
		return
	}

	actx := h.buildAuditContext(r)

	if err := h.service.DeletePermissionSet(ctx, id, actx); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ListPermissionSets handles GET /api/v1/permission-sets
// @Summary List permission sets
// @Description List all permission sets for the tenant
// @Tags permission-sets
// @Produce json
// @Param include_system query bool false "Include system permission sets"
// @Param type query string false "Filter by type"
// @Param search query string false "Search by name"
// @Param limit query int false "Limit results" default(20)
// @Param offset query int false "Offset for pagination" default(0)
// @Success 200 {object} PermissionSetListResponse
// @Router /api/v1/permission-sets [get]
func (h *PermissionSetHandler) ListPermissionSets(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	tenantID := middleware.MustGetTenantID(ctx)

	// Parse query parameters
	limit := 20
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

	input := app.ListPermissionSetsInput{
		TenantID:      tenantID,
		IncludeSystem: r.URL.Query().Get("include_system") == queryParamTrue,
		Search:        r.URL.Query().Get("search"),
		Limit:         limit,
		Offset:        offset,
	}

	if st := r.URL.Query().Get("type"); st != "" {
		input.SetType = &st
	}

	output, err := h.service.ListPermissionSets(ctx, input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	resp := PermissionSetListResponse{
		PermissionSets: make([]PermissionSetResponse, 0, len(output.PermissionSets)),
		TotalCount:     output.TotalCount,
		Limit:          limit,
		Offset:         offset,
	}

	for _, ps := range output.PermissionSets {
		resp.PermissionSets = append(resp.PermissionSets, toPermissionSetResponse(ps))
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// =============================================================================
// Permission Item Handlers
// =============================================================================

// AddPermission handles POST /api/v1/permission-sets/{id}/permissions
// @Summary Add a permission to a set
// @Description Add a permission to a permission set
// @Tags permission-sets
// @Accept json
// @Produce json
// @Param id path string true "Permission set ID"
// @Param request body AddPermissionRequest true "Permission details"
// @Success 201
// @Failure 400 {object} apierror.Error
// @Failure 404 {object} apierror.Error
// @Router /api/v1/permission-sets/{id}/permissions [post]
func (h *PermissionSetHandler) AddPermission(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id := r.PathValue("id")
	if id == "" {
		apierror.BadRequest("Permission set ID is required").WriteJSON(w)
		return
	}

	var req AddPermissionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := app.AddPermissionToSetInput{
		PermissionSetID:  id,
		PermissionID:     req.PermissionID,
		ModificationType: req.ModificationType,
	}

	actx := h.buildAuditContext(r)

	if err := h.service.AddPermissionToSet(ctx, input, actx); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

// RemovePermission handles DELETE /api/v1/permission-sets/{id}/permissions/{permissionId}
// @Summary Remove a permission from a set
// @Description Remove a permission from a permission set
// @Tags permission-sets
// @Param id path string true "Permission set ID"
// @Param permissionId path string true "Permission ID"
// @Success 204
// @Failure 400 {object} apierror.Error
// @Failure 404 {object} apierror.Error
// @Router /api/v1/permission-sets/{id}/permissions/{permissionId} [delete]
func (h *PermissionSetHandler) RemovePermission(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id := r.PathValue("id")
	if id == "" {
		apierror.BadRequest("Permission set ID is required").WriteJSON(w)
		return
	}

	permissionID := r.PathValue("permissionId")
	if permissionID == "" {
		apierror.BadRequest("Permission ID is required").WriteJSON(w)
		return
	}

	actx := h.buildAuditContext(r)

	if err := h.service.RemovePermissionFromSet(ctx, id, permissionID, actx); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// =============================================================================
// System Permission Sets (Read-only listing)
// =============================================================================

// ListSystemPermissionSets handles GET /api/v1/permission-sets/system
// @Summary List system permission sets
// @Description List all system-defined permission sets
// @Tags permission-sets
// @Produce json
// @Success 200 {array} PermissionSetResponse
// @Router /api/v1/permission-sets/system [get]
func (h *PermissionSetHandler) ListSystemPermissionSets(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	tenantID := middleware.MustGetTenantID(ctx)

	input := app.ListPermissionSetsInput{
		TenantID:      tenantID,
		IncludeSystem: true,
		Limit:         100,
		Offset:        0,
	}

	output, err := h.service.ListPermissionSets(ctx, input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// Filter only system sets
	var systemSets []PermissionSetResponse
	for _, ps := range output.PermissionSets {
		if ps.IsSystem() {
			systemSets = append(systemSets, toPermissionSetResponse(ps))
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(systemSets)
}

// =============================================================================
// User Permissions
// =============================================================================

// EffectivePermissionsResponse represents the effective permissions for a user.
type EffectivePermissionsResponse struct {
	UserID      string   `json:"user_id"`
	TenantID    string   `json:"tenant_id"`
	Permissions []string `json:"permissions"`
	GroupCount  int      `json:"group_count"`
}

// GetMyEffectivePermissions handles GET /api/v1/me/permissions
// @Summary Get effective permissions for current user
// @Description Get all effective permissions for the current user based on their group memberships
// @Tags permissions
// @Produce json
// @Success 200 {object} EffectivePermissionsResponse
// @Router /api/v1/me/permissions [get]
func (h *PermissionSetHandler) GetMyEffectivePermissions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	tenantID := middleware.MustGetTenantID(ctx)
	userID := middleware.GetLocalUserID(ctx)
	if userID.IsZero() {
		apierror.Unauthorized("User context required").WriteJSON(w)
		return
	}

	perms, groupCount, err := h.service.ResolveUserPermissionsWithCount(ctx, tenantID, userID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// Convert to strings
	permStrings := make([]string, len(perms))
	for i, p := range perms {
		permStrings[i] = p.String()
	}

	resp := EffectivePermissionsResponse{
		UserID:      userID.String(),
		TenantID:    tenantID,
		Permissions: permStrings,
		GroupCount:  groupCount,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
