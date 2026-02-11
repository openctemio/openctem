package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/role"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/validator"
)

// RoleHandler handles role-related HTTP requests.
type RoleHandler struct {
	service   *app.RoleService
	validator *validator.Validator
	logger    *logger.Logger
}

// NewRoleHandler creates a new role handler.
func NewRoleHandler(svc *app.RoleService, v *validator.Validator, log *logger.Logger) *RoleHandler {
	return &RoleHandler{
		service:   svc,
		validator: v,
		logger:    log,
	}
}

// =============================================================================
// Response Types
// =============================================================================

// RoleResponse represents a role in API responses.
type RoleResponse struct {
	ID                string    `json:"id"`
	TenantID          *string   `json:"tenant_id,omitempty"`
	Slug              string    `json:"slug"`
	Name              string    `json:"name"`
	Description       string    `json:"description,omitempty"`
	IsSystem          bool      `json:"is_system"`
	HierarchyLevel    int       `json:"hierarchy_level"`
	HasFullDataAccess bool      `json:"has_full_data_access"`
	Permissions       []string  `json:"permissions"`
	PermissionCount   int       `json:"permission_count"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// UserRoleResponse represents a user's role assignment.
type UserRoleResponse struct {
	ID         string       `json:"id"`
	UserID     string       `json:"user_id"`
	TenantID   string       `json:"tenant_id"`
	RoleID     string       `json:"role_id"`
	Role       RoleResponse `json:"role"`
	AssignedAt time.Time    `json:"assigned_at"`
	AssignedBy *string      `json:"assigned_by,omitempty"`

	// User details
	Name      string `json:"name,omitempty"`
	Email     string `json:"email,omitempty"`
	AvatarURL string `json:"avatar_url,omitempty"`
}

// ModuleResponse represents a permission module in API responses.
type ModuleResponse struct {
	ID           string               `json:"id"`
	Name         string               `json:"name"`
	Description  string               `json:"description,omitempty"`
	Icon         string               `json:"icon,omitempty"`
	DisplayOrder int                  `json:"display_order"`
	IsActive     bool                 `json:"is_active"`
	Permissions  []PermissionResponse `json:"permissions"`
}

// PermissionResponse represents a permission in API responses.
type PermissionResponse struct {
	ID          string `json:"id"`
	ModuleID    string `json:"module_id,omitempty"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	IsActive    bool   `json:"is_active"`
}

// RoleListResponse represents a list of roles.
type RoleListResponse struct {
	Roles []RoleResponse `json:"roles"`
	Total int            `json:"total"`
}

// =============================================================================
// Request Types
// =============================================================================

// CreateRoleRequest represents the request to create a role.
type CreateRoleRequest struct {
	Slug              string   `json:"slug" validate:"required,min=2,max=50,slug"`
	Name              string   `json:"name" validate:"required,min=2,max=100"`
	Description       string   `json:"description" validate:"max=500"`
	HierarchyLevel    int      `json:"hierarchy_level" validate:"min=0,max=100"`
	HasFullDataAccess bool     `json:"has_full_data_access"`
	Permissions       []string `json:"permissions" validate:"max=200,dive,max=100"`
}

// UpdateRoleRequest represents the request to update a role.
type UpdateRoleRequest struct {
	Name              *string  `json:"name" validate:"omitempty,min=2,max=100"`
	Description       *string  `json:"description" validate:"omitempty,max=500"`
	HierarchyLevel    *int     `json:"hierarchy_level" validate:"omitempty,min=0,max=100"`
	HasFullDataAccess *bool    `json:"has_full_data_access"`
	Permissions       []string `json:"permissions,omitempty" validate:"omitempty,max=200,dive,max=100"`
}

// AssignRoleRequest represents the request to assign a role to a user.
type AssignRoleRequest struct {
	RoleID string `json:"role_id" validate:"required,uuid"`
}

// SetUserRolesRequest represents the request to set all roles for a user.
type SetUserRolesRequest struct {
	RoleIDs []string `json:"role_ids" validate:"required,min=1,max=50,dive,uuid"`
}

// BulkAssignRoleMembersRequest represents the request to assign a role to multiple users.
type BulkAssignRoleMembersRequest struct {
	UserIDs []string `json:"user_ids" validate:"required,min=1,max=100,dive,uuid"`
}

// BulkAssignRoleMembersResponse represents the response for bulk role assignment.
type BulkAssignRoleMembersResponse struct {
	SuccessCount int      `json:"success_count"`
	FailedCount  int      `json:"failed_count"`
	FailedUsers  []string `json:"failed_users,omitempty"`
}

// =============================================================================
// Response Converters
// =============================================================================

func toRoleResponse(r *role.Role) RoleResponse {
	resp := RoleResponse{
		ID:                r.ID().String(),
		Slug:              r.Slug(),
		Name:              r.Name(),
		Description:       r.Description(),
		IsSystem:          r.IsSystem(),
		HierarchyLevel:    r.HierarchyLevel(),
		HasFullDataAccess: r.HasFullDataAccess(),
		Permissions:       r.Permissions(),
		PermissionCount:   r.PermissionCount(),
		CreatedAt:         r.CreatedAt(),
		UpdatedAt:         r.UpdatedAt(),
	}
	if r.TenantID() != nil {
		tid := r.TenantID().String()
		resp.TenantID = &tid
	}
	if resp.Permissions == nil {
		resp.Permissions = []string{}
	}
	return resp
}

func toUserRoleResponse(ur *role.UserRole) UserRoleResponse {
	resp := UserRoleResponse{
		ID:         ur.ID.String(),
		UserID:     ur.UserID.String(),
		TenantID:   ur.TenantID.String(),
		RoleID:     ur.RoleID.String(),
		AssignedAt: ur.AssignedAt,
		Name:       ur.UserName,
		Email:      ur.UserEmail,
		AvatarURL:  ur.UserAvatarURL,
	}
	if ur.AssignedBy != nil {
		ab := ur.AssignedBy.String()
		resp.AssignedBy = &ab
	}
	if ur.Role != nil {
		resp.Role = toRoleResponse(ur.Role)
	}
	return resp
}

func toModuleResponse(m *role.Module) ModuleResponse {
	perms := make([]PermissionResponse, len(m.Permissions))
	for i, p := range m.Permissions {
		perms[i] = toPermissionResponse(p)
	}
	return ModuleResponse{
		ID:           m.ID,
		Name:         m.Name,
		Description:  m.Description,
		Icon:         m.Icon,
		DisplayOrder: m.DisplayOrder,
		IsActive:     m.IsActive,
		Permissions:  perms,
	}
}

func toPermissionResponse(p *role.Permission) PermissionResponse {
	return PermissionResponse{
		ID:          p.ID,
		ModuleID:    p.ModuleID,
		Name:        p.Name,
		Description: p.Description,
		IsActive:    p.IsActive,
	}
}

// =============================================================================
// Helpers
// =============================================================================

func (h *RoleHandler) buildAuditContext(r *http.Request) app.AuditContext {
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

func (h *RoleHandler) handleValidationError(w http.ResponseWriter, err error) {
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

func (h *RoleHandler) handleServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, role.ErrRoleNotFound):
		apierror.NotFound("Role").WriteJSON(w)
	case errors.Is(err, role.ErrUserRoleNotFound):
		apierror.NotFound("User role assignment").WriteJSON(w)
	case errors.Is(err, role.ErrRoleSlugExists):
		apierror.Conflict("Role with this slug already exists").WriteJSON(w)
	case errors.Is(err, role.ErrUserRoleExists):
		apierror.Conflict("User already has this role").WriteJSON(w)
	case errors.Is(err, role.ErrCannotModifySystemRole):
		apierror.Forbidden("Cannot modify system role").WriteJSON(w)
	case errors.Is(err, role.ErrCannotDeleteSystemRole):
		apierror.Forbidden("Cannot delete system role").WriteJSON(w)
	case errors.Is(err, role.ErrRoleInUse):
		apierror.Conflict("Role is assigned to users and cannot be deleted").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		msg := err.Error()
		if idx := strings.Index(msg, ": "); idx != -1 {
			msg = msg[idx+2:]
		}
		apierror.BadRequest(msg).WriteJSON(w)
	case errors.Is(err, shared.ErrForbidden):
		apierror.Forbidden(err.Error()).WriteJSON(w)
	default:
		h.logger.Error("service error", "error", err)
		apierror.InternalError(err).WriteJSON(w)
	}
}

// =============================================================================
// Role CRUD Handlers
// =============================================================================

// CreateRole handles POST /api/v1/roles
func (h *RoleHandler) CreateRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	tenantID := middleware.MustGetTenantID(ctx)
	userID := middleware.GetLocalUserID(ctx)
	if userID.IsZero() {
		apierror.Unauthorized("User context required").WriteJSON(w)
		return
	}

	var req CreateRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := app.CreateRoleInput{
		TenantID:          tenantID,
		Slug:              req.Slug,
		Name:              req.Name,
		Description:       req.Description,
		HierarchyLevel:    req.HierarchyLevel,
		HasFullDataAccess: req.HasFullDataAccess,
		Permissions:       req.Permissions,
	}

	actx := h.buildAuditContext(r)

	ro, err := h.service.CreateRole(ctx, input, userID.String(), actx)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(toRoleResponse(ro))
}

// GetRole handles GET /api/v1/roles/{roleId}
func (h *RoleHandler) GetRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	roleID := chi.URLParam(r, "roleId")

	ro, err := h.service.GetRole(ctx, roleID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toRoleResponse(ro))
}

// ListRoles handles GET /api/v1/roles
func (h *RoleHandler) ListRoles(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	tenantID := middleware.MustGetTenantID(ctx)

	roles, err := h.service.ListRolesForTenant(ctx, tenantID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	resp := make([]RoleResponse, len(roles))
	for i, ro := range roles {
		resp[i] = toRoleResponse(ro)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(RoleListResponse{
		Roles: resp,
		Total: len(resp),
	})
}

// UpdateRole handles PUT /api/v1/roles/{roleId}
func (h *RoleHandler) UpdateRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	roleID := chi.URLParam(r, "roleId")

	var req UpdateRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := app.UpdateRoleInput{
		Name:              req.Name,
		Description:       req.Description,
		HierarchyLevel:    req.HierarchyLevel,
		HasFullDataAccess: req.HasFullDataAccess,
		Permissions:       req.Permissions,
	}

	actx := h.buildAuditContext(r)

	ro, err := h.service.UpdateRole(ctx, roleID, input, actx)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toRoleResponse(ro))
}

// DeleteRole handles DELETE /api/v1/roles/{roleId}
func (h *RoleHandler) DeleteRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	roleID := chi.URLParam(r, "roleId")

	actx := h.buildAuditContext(r)

	if err := h.service.DeleteRole(ctx, roleID, actx); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// =============================================================================
// User Role Assignment Handlers
// =============================================================================

// GetUserRoles handles GET /api/v1/users/{userId}/roles
func (h *RoleHandler) GetUserRoles(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := chi.URLParam(r, "userId")
	tenantID := middleware.MustGetTenantID(ctx)

	roles, err := h.service.GetUserRoles(ctx, tenantID, userID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	resp := make([]RoleResponse, len(roles))
	for i, ro := range roles {
		resp[i] = toRoleResponse(ro)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// AssignRole handles POST /api/v1/users/{userId}/roles
func (h *RoleHandler) AssignRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := chi.URLParam(r, "userId")
	tenantID := middleware.MustGetTenantID(ctx)

	actorID := middleware.GetLocalUserID(ctx)

	var req AssignRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := app.AssignRoleInput{
		TenantID: tenantID,
		UserID:   userID,
		RoleID:   req.RoleID,
	}

	actx := h.buildAuditContext(r)

	if err := h.service.AssignRole(ctx, input, actorID.String(), actx); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// RemoveRole handles DELETE /api/v1/users/{userId}/roles/{roleId}
func (h *RoleHandler) RemoveRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := chi.URLParam(r, "userId")
	roleID := chi.URLParam(r, "roleId")
	tenantID := middleware.MustGetTenantID(ctx)

	actx := h.buildAuditContext(r)

	if err := h.service.RemoveRole(ctx, tenantID, userID, roleID, actx); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// SetUserRoles handles PUT /api/v1/users/{userId}/roles
func (h *RoleHandler) SetUserRoles(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := chi.URLParam(r, "userId")
	tenantID := middleware.MustGetTenantID(ctx)

	actorID := middleware.GetLocalUserID(ctx)

	var req SetUserRolesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := app.SetUserRolesInput{
		TenantID: tenantID,
		UserID:   userID,
		RoleIDs:  req.RoleIDs,
	}

	actx := h.buildAuditContext(r)

	if err := h.service.SetUserRoles(ctx, input, actorID.String(), actx); err != nil {
		h.handleServiceError(w, err)
		return
	}

	// Return updated roles
	roles, err := h.service.GetUserRoles(ctx, tenantID, userID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	resp := make([]RoleResponse, len(roles))
	for i, ro := range roles {
		resp[i] = toRoleResponse(ro)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// =============================================================================
// Role Members Handlers
// =============================================================================

// ListRoleMembers handles GET /api/v1/roles/{roleId}/members
func (h *RoleHandler) ListRoleMembers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	roleID := chi.URLParam(r, "roleId")
	tenantID := middleware.MustGetTenantID(ctx)

	members, err := h.service.ListRoleMembers(ctx, tenantID, roleID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	resp := make([]UserRoleResponse, len(members))
	for i, ur := range members {
		resp[i] = toUserRoleResponse(ur)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// BulkAssignRoleMembers handles POST /api/v1/roles/{roleId}/members/bulk
// Assigns a role to multiple users at once.
func (h *RoleHandler) BulkAssignRoleMembers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	roleID := chi.URLParam(r, "roleId")
	tenantID := middleware.MustGetTenantID(ctx)
	actorID := middleware.GetLocalUserID(ctx)

	var req BulkAssignRoleMembersRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := app.BulkAssignRoleToUsersInput{
		TenantID: tenantID,
		RoleID:   roleID,
		UserIDs:  req.UserIDs,
	}

	actx := h.buildAuditContext(r)

	result, err := h.service.BulkAssignRoleToUsers(ctx, input, actorID.String(), actx)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	resp := BulkAssignRoleMembersResponse{
		SuccessCount: result.SuccessCount,
		FailedCount:  result.FailedCount,
		FailedUsers:  result.FailedUsers,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

// =============================================================================
// Permission Handlers
// =============================================================================

// ListModulesWithPermissions handles GET /api/v1/permissions/modules
func (h *RoleHandler) ListModulesWithPermissions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	modules, err := h.service.ListModulesWithPermissions(ctx)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	resp := make([]ModuleResponse, len(modules))
	for i, m := range modules {
		resp[i] = toModuleResponse(m)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// ListPermissions handles GET /api/v1/permissions
func (h *RoleHandler) ListPermissions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	permissions, err := h.service.ListPermissions(ctx)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	resp := make([]PermissionResponse, len(permissions))
	for i, p := range permissions {
		resp[i] = toPermissionResponse(p)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// =============================================================================
// Current User Handlers
// =============================================================================

// GetMyRoles handles GET /api/v1/me/roles
func (h *RoleHandler) GetMyRoles(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantID := middleware.MustGetTenantID(ctx)
	userID := middleware.GetLocalUserID(ctx)
	if userID.IsZero() {
		apierror.Unauthorized("User context required").WriteJSON(w)
		return
	}

	roles, err := h.service.GetUserRoles(ctx, tenantID, userID.String())
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	resp := make([]RoleResponse, len(roles))
	for i, ro := range roles {
		resp[i] = toRoleResponse(ro)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// GetMyPermissions handles GET /api/v1/me/permissions
func (h *RoleHandler) GetMyPermissions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantID := middleware.MustGetTenantID(ctx)
	userID := middleware.GetLocalUserID(ctx)
	if userID.IsZero() {
		apierror.Unauthorized("User context required").WriteJSON(w)
		return
	}

	permissions, err := h.service.GetUserPermissions(ctx, tenantID, userID.String())
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	resp := map[string]any{
		"permissions": permissions,
		"count":       len(permissions),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
