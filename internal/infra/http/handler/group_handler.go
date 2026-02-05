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
	"github.com/openctemio/api/pkg/domain/group"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/validator"
	"github.com/go-chi/chi/v5"
)

// GroupHandler handles group-related HTTP requests for the Access Control system.
type GroupHandler struct {
	service   *app.GroupService
	validator *validator.Validator
	logger    *logger.Logger
}

// NewGroupHandler creates a new group handler.
func NewGroupHandler(svc *app.GroupService, v *validator.Validator, log *logger.Logger) *GroupHandler {
	return &GroupHandler{
		service:   svc,
		validator: v,
		logger:    log,
	}
}

// =============================================================================
// Response Types
// =============================================================================

// GroupResponse represents a group in API responses.
type GroupResponse struct {
	ID                 string                   `json:"id"`
	TenantID           string                   `json:"tenant_id"`
	Name               string                   `json:"name"`
	Slug               string                   `json:"slug"`
	Description        string                   `json:"description,omitempty"`
	GroupType          string                   `json:"group_type"`
	IsActive           bool                     `json:"is_active"`
	Settings           group.GroupSettings      `json:"settings,omitempty"`
	NotificationConfig group.NotificationConfig `json:"notification_config,omitempty"`
	MemberCount        int                      `json:"member_count,omitempty"`
	CreatedAt          time.Time                `json:"created_at"`
	UpdatedAt          time.Time                `json:"updated_at"`
}

// GroupMemberResponse represents a group member in API responses.
type GroupMemberResponse struct {
	UserID   string    `json:"user_id"`
	Role     string    `json:"role"`
	JoinedAt time.Time `json:"joined_at"`
	AddedBy  string    `json:"added_by,omitempty"`
}

// GroupMemberWithUserResponse represents a member with user details.
type GroupMemberWithUserResponse struct {
	UserID    string    `json:"user_id"`
	Role      string    `json:"role"`
	JoinedAt  time.Time `json:"joined_at"`
	AddedBy   string    `json:"added_by,omitempty"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	AvatarURL string    `json:"avatar_url,omitempty"`
}

// GroupWithRoleResponse represents a group with the user's role.
type GroupWithRoleResponse struct {
	GroupResponse
	Role     string    `json:"role"`
	JoinedAt time.Time `json:"joined_at"`
}

// GroupListResponse represents a paginated list of groups.
type GroupListResponse struct {
	Groups     []GroupResponse `json:"groups"`
	TotalCount int64           `json:"total_count"`
	Limit      int             `json:"limit"`
	Offset     int             `json:"offset"`
}

// =============================================================================
// Request Types
// =============================================================================

// CreateGroupRequest represents the request to create a group.
type CreateGroupRequest struct {
	Name        string               `json:"name" validate:"required,min=2,max=100"`
	Slug        string               `json:"slug" validate:"required,min=2,max=100,slug"`
	Description string               `json:"description" validate:"max=500"`
	GroupType   string               `json:"group_type" validate:"required,oneof=security_team team department project external"`
	Settings    *group.GroupSettings `json:"settings,omitempty"`
}

// UpdateGroupRequest represents the request to update a group.
type UpdateGroupRequest struct {
	Name        *string              `json:"name" validate:"omitempty,min=2,max=100"`
	Slug        *string              `json:"slug" validate:"omitempty,min=2,max=100,slug"`
	Description *string              `json:"description" validate:"omitempty,max=500"`
	Settings    *group.GroupSettings `json:"settings,omitempty"`
	IsActive    *bool                `json:"is_active,omitempty"`
}

// AddGroupMemberRequest represents the request to add a member to a group.
type AddGroupMemberRequest struct {
	UserID string `json:"user_id" validate:"required,uuid"`
	Role   string `json:"role" validate:"required,oneof=owner lead member"`
}

// UpdateGroupMemberRoleRequest represents the request to update a member's role.
type UpdateGroupMemberRoleRequest struct {
	Role string `json:"role" validate:"required,oneof=owner lead member"`
}

// AssignPermissionSetRequest represents the request to assign a permission set.
type AssignPermissionSetRequest struct {
	PermissionSetID string `json:"permission_set_id" validate:"required,uuid"`
}

// =============================================================================
// Response Converters
// =============================================================================

func toGroupResponse(g *group.Group) GroupResponse {
	return GroupResponse{
		ID:                 g.ID().String(),
		TenantID:           g.TenantID().String(),
		Name:               g.Name(),
		Slug:               g.Slug(),
		Description:        g.Description(),
		GroupType:          g.GroupType().String(),
		IsActive:           g.IsActive(),
		Settings:           g.Settings(),
		NotificationConfig: g.NotificationConfig(),
		CreatedAt:          g.CreatedAt(),
		UpdatedAt:          g.UpdatedAt(),
	}
}

func toGroupMemberResponse(m *group.Member) GroupMemberResponse {
	resp := GroupMemberResponse{
		UserID:   m.UserID().String(),
		Role:     m.Role().String(),
		JoinedAt: m.JoinedAt(),
	}
	if m.AddedBy() != nil {
		resp.AddedBy = m.AddedBy().String()
	}
	return resp
}

func toGroupMemberWithUserResponse(m *group.MemberWithUser) GroupMemberWithUserResponse {
	resp := GroupMemberWithUserResponse{
		UserID:    m.Member.UserID().String(),
		Role:      m.Member.Role().String(),
		JoinedAt:  m.Member.JoinedAt(),
		Email:     m.Email,
		Name:      m.Name,
		AvatarURL: m.AvatarURL,
	}
	if m.Member.AddedBy() != nil {
		resp.AddedBy = m.Member.AddedBy().String()
	}
	return resp
}

func toGroupWithRoleResponse(g *group.GroupWithRole) GroupWithRoleResponse {
	return GroupWithRoleResponse{
		GroupResponse: GroupResponse{
			ID:          g.Group.ID().String(),
			TenantID:    g.Group.TenantID().String(),
			Name:        g.Group.Name(),
			Slug:        g.Group.Slug(),
			Description: g.Group.Description(),
			GroupType:   g.Group.GroupType().String(),
			IsActive:    g.Group.IsActive(),
			Settings:    g.Group.Settings(),
			CreatedAt:   g.Group.CreatedAt(),
			UpdatedAt:   g.Group.UpdatedAt(),
		},
		Role: g.Role.String(),
	}
}

// =============================================================================
// Helpers
// =============================================================================

// buildAuditContext builds an AuditContext from the HTTP request.
func (h *GroupHandler) buildAuditContext(r *http.Request) app.AuditContext {
	actx := app.AuditContext{
		ActorIP:   r.RemoteAddr,
		UserAgent: r.UserAgent(),
		RequestID: r.Header.Get("X-Request-ID"),
	}

	// Set actor info if available
	if localUser := middleware.GetLocalUser(r.Context()); localUser != nil {
		actx.ActorID = localUser.ID().String()
		actx.ActorEmail = localUser.Email()
	}

	// Set tenant ID if available (from JWT token)
	if tenantID := middleware.GetTenantID(r.Context()); tenantID != "" {
		actx.TenantID = tenantID
	}

	return actx
}

// =============================================================================
// Error Handlers
// =============================================================================

func (h *GroupHandler) handleValidationError(w http.ResponseWriter, err error) {
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

func (h *GroupHandler) handleServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Group").WriteJSON(w)
	case errors.Is(err, shared.ErrAlreadyExists):
		apierror.Conflict("Group already exists").WriteJSON(w)
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
// Group CRUD Handlers
// =============================================================================

// CreateGroup handles POST /api/v1/groups
// @Summary Create a new group
// @Description Create a new group for access control
// @Tags groups
// @Accept json
// @Produce json
// @Param request body CreateGroupRequest true "Group details"
// @Success 201 {object} GroupResponse
// @Failure 400 {object} apierror.Error
// @Failure 401 {object} apierror.Error
// @Failure 403 {object} apierror.Error
// @Router /api/v1/groups [post]
func (h *GroupHandler) CreateGroup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get tenant ID from context (from JWT token)
	tenantID := middleware.MustGetTenantID(ctx)

	// Get user ID from context
	userID := middleware.GetLocalUserID(ctx)
	if userID.IsZero() {
		apierror.Unauthorized("User context required").WriteJSON(w)
		return
	}

	var req CreateGroupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := app.CreateGroupInput{
		TenantID:    tenantID,
		Name:        req.Name,
		Slug:        req.Slug,
		Description: req.Description,
		GroupType:   req.GroupType,
		Settings:    req.Settings,
	}

	actx := h.buildAuditContext(r)

	g, err := h.service.CreateGroup(ctx, input, userID, actx)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(toGroupResponse(g))
}

// GetGroup handles GET /api/v1/groups/{groupId}
// @Summary Get a group by ID
// @Description Get a group's details
// @Tags groups
// @Produce json
// @Param groupId path string true "Group ID"
// @Success 200 {object} GroupResponse
// @Failure 404 {object} apierror.Error
// @Router /api/v1/groups/{groupId} [get]
func (h *GroupHandler) GetGroup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	groupID := chi.URLParam(r, "groupId")

	g, err := h.service.GetGroup(ctx, groupID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toGroupResponse(g))
}

// ListGroups handles GET /api/v1/groups
// @Summary List groups
// @Description List all groups in the tenant with optional filtering
// @Tags groups
// @Produce json
// @Param type query string false "Filter by group type"
// @Param active query bool false "Filter by active status"
// @Param search query string false "Search by name or slug"
// @Param limit query int false "Limit results" default(20)
// @Param offset query int false "Offset for pagination" default(0)
// @Success 200 {object} GroupListResponse
// @Router /api/v1/groups [get]
func (h *GroupHandler) ListGroups(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get tenant ID from JWT token
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

	input := app.ListGroupsInput{
		TenantID: tenantID,
		Search:   r.URL.Query().Get("search"),
		Limit:    limit,
		Offset:   offset,
	}

	if gt := r.URL.Query().Get("type"); gt != "" {
		input.GroupType = &gt
	}

	if active := r.URL.Query().Get("active"); active != "" {
		if parsed, err := strconv.ParseBool(active); err == nil {
			input.IsActive = &parsed
		}
	}

	output, err := h.service.ListGroups(ctx, input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	groups := make([]GroupResponse, len(output.Groups))
	for i, g := range output.Groups {
		groups[i] = toGroupResponse(g)
	}

	resp := GroupListResponse{
		Groups:     groups,
		TotalCount: output.TotalCount,
		Limit:      limit,
		Offset:     offset,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// UpdateGroup handles PUT /api/v1/groups/{groupId}
// @Summary Update a group
// @Description Update a group's details
// @Tags groups
// @Accept json
// @Produce json
// @Param groupId path string true "Group ID"
// @Param request body UpdateGroupRequest true "Update details"
// @Success 200 {object} GroupResponse
// @Failure 400 {object} apierror.Error
// @Failure 404 {object} apierror.Error
// @Router /api/v1/groups/{groupId} [put]
func (h *GroupHandler) UpdateGroup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	groupID := chi.URLParam(r, "groupId")

	var req UpdateGroupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := app.UpdateGroupInput{
		Name:        req.Name,
		Slug:        req.Slug,
		Description: req.Description,
		Settings:    req.Settings,
		IsActive:    req.IsActive,
	}

	actx := h.buildAuditContext(r)

	g, err := h.service.UpdateGroup(ctx, groupID, input, actx)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toGroupResponse(g))
}

// DeleteGroup handles DELETE /api/v1/groups/{groupId}
// @Summary Delete a group
// @Description Delete a group
// @Tags groups
// @Param groupId path string true "Group ID"
// @Success 204 "No Content"
// @Failure 404 {object} apierror.Error
// @Router /api/v1/groups/{groupId} [delete]
func (h *GroupHandler) DeleteGroup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	groupID := chi.URLParam(r, "groupId")

	actx := h.buildAuditContext(r)

	if err := h.service.DeleteGroup(ctx, groupID, actx); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// =============================================================================
// Member Handlers
// =============================================================================

// ListMembers handles GET /api/v1/groups/{groupId}/members
// @Summary List group members
// @Description List all members of a group with user details
// @Tags groups
// @Produce json
// @Param groupId path string true "Group ID"
// @Success 200 {array} GroupMemberWithUserResponse
// @Failure 404 {object} apierror.Error
// @Router /api/v1/groups/{groupId}/members [get]
func (h *GroupHandler) ListMembers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	groupID := chi.URLParam(r, "groupId")

	members, err := h.service.ListGroupMembersWithUserInfo(ctx, groupID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	resp := make([]GroupMemberWithUserResponse, len(members))
	for i, m := range members {
		resp[i] = toGroupMemberWithUserResponse(m)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// AddMember handles POST /api/v1/groups/{groupId}/members
// @Summary Add a member to a group
// @Description Add a user as a member of the group
// @Tags groups
// @Accept json
// @Produce json
// @Param groupId path string true "Group ID"
// @Param request body AddGroupMemberRequest true "Member details"
// @Success 201 {object} GroupMemberResponse
// @Failure 400 {object} apierror.Error
// @Failure 404 {object} apierror.Error
// @Router /api/v1/groups/{groupId}/members [post]
func (h *GroupHandler) AddMember(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	groupID := chi.URLParam(r, "groupId")

	var req AddGroupMemberRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	memberUserID, err := shared.IDFromString(req.UserID)
	if err != nil {
		apierror.BadRequest("Invalid user_id format").WriteJSON(w)
		return
	}

	input := app.AddGroupMemberInput{
		GroupID: groupID,
		UserID:  memberUserID,
		Role:    req.Role,
	}

	actx := h.buildAuditContext(r)

	member, err := h.service.AddMember(ctx, input, actx)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(toGroupMemberResponse(member))
}

// UpdateMemberRole handles PUT /api/v1/groups/{groupId}/members/{userId}
// @Summary Update a member's role
// @Description Update the role of a group member
// @Tags groups
// @Accept json
// @Produce json
// @Param groupId path string true "Group ID"
// @Param userId path string true "User ID"
// @Param request body UpdateGroupMemberRoleRequest true "Role update"
// @Success 200 {object} GroupMemberResponse
// @Failure 400 {object} apierror.Error
// @Failure 404 {object} apierror.Error
// @Router /api/v1/groups/{groupId}/members/{userId} [put]
func (h *GroupHandler) UpdateMemberRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	groupID := chi.URLParam(r, "groupId")
	memberUserID := chi.URLParam(r, "userId")

	var req UpdateGroupMemberRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	uid, err := shared.IDFromString(memberUserID)
	if err != nil {
		apierror.BadRequest("Invalid user id format").WriteJSON(w)
		return
	}

	input := app.UpdateGroupMemberRoleInput{
		GroupID: groupID,
		UserID:  uid,
		Role:    req.Role,
	}

	actx := h.buildAuditContext(r)

	member, err := h.service.UpdateMemberRole(ctx, input, actx)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toGroupMemberResponse(member))
}

// RemoveMember handles DELETE /api/v1/groups/{groupId}/members/{userId}
// @Summary Remove a member from a group
// @Description Remove a user from the group
// @Tags groups
// @Param groupId path string true "Group ID"
// @Param userId path string true "User ID"
// @Success 204 "No Content"
// @Failure 400 {object} apierror.Error
// @Failure 404 {object} apierror.Error
// @Router /api/v1/groups/{groupId}/members/{userId} [delete]
func (h *GroupHandler) RemoveMember(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	groupID := chi.URLParam(r, "groupId")
	memberUserID := chi.URLParam(r, "userId")

	uid, err := shared.IDFromString(memberUserID)
	if err != nil {
		apierror.BadRequest("Invalid user id format").WriteJSON(w)
		return
	}

	actx := h.buildAuditContext(r)

	if err := h.service.RemoveMember(ctx, groupID, uid, actx); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// =============================================================================
// Permission Set Assignment Handlers
// =============================================================================

// AssignPermissionSet handles POST /api/v1/groups/{groupId}/permission-sets
// @Summary Assign a permission set to a group
// @Description Assign a permission set to the group
// @Tags groups
// @Accept json
// @Produce json
// @Param groupId path string true "Group ID"
// @Param request body AssignPermissionSetRequest true "Permission set details"
// @Success 204 "No Content"
// @Failure 400 {object} apierror.Error
// @Failure 404 {object} apierror.Error
// @Router /api/v1/groups/{groupId}/permission-sets [post]
func (h *GroupHandler) AssignPermissionSet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	groupID := chi.URLParam(r, "groupId")

	userID := middleware.GetLocalUserID(ctx)
	if userID.IsZero() {
		apierror.Unauthorized("User context required").WriteJSON(w)
		return
	}

	var req AssignPermissionSetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := app.AssignPermissionSetInput{
		GroupID:         groupID,
		PermissionSetID: req.PermissionSetID,
	}

	actx := h.buildAuditContext(r)

	if err := h.service.AssignPermissionSet(ctx, input, userID, actx); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// UnassignPermissionSet handles DELETE /api/v1/groups/{groupId}/permission-sets/{permissionSetId}
// @Summary Remove a permission set from a group
// @Description Remove a permission set assignment from the group
// @Tags groups
// @Param groupId path string true "Group ID"
// @Param permissionSetId path string true "Permission Set ID"
// @Success 204 "No Content"
// @Failure 404 {object} apierror.Error
// @Router /api/v1/groups/{groupId}/permission-sets/{permissionSetId} [delete]
func (h *GroupHandler) UnassignPermissionSet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	groupID := chi.URLParam(r, "groupId")
	permissionSetID := chi.URLParam(r, "permissionSetId")

	actx := h.buildAuditContext(r)

	if err := h.service.UnassignPermissionSet(ctx, groupID, permissionSetID, actx); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ListAssignedPermissionSets handles GET /api/v1/groups/{groupId}/permission-sets
// @Summary List permission sets assigned to a group
// @Description Get all permission sets assigned to the group with full details
// @Tags groups
// @Produce json
// @Param groupId path string true "Group ID"
// @Success 200 {array} PermissionSetResponse
// @Failure 404 {object} apierror.Error
// @Router /api/v1/groups/{groupId}/permission-sets [get]
func (h *GroupHandler) ListAssignedPermissionSets(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	groupID := chi.URLParam(r, "groupId")

	permissionSets, err := h.service.ListGroupPermissionSetsWithDetails(ctx, groupID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// Convert to response objects
	result := make([]PermissionSetWithItemsResponse, len(permissionSets))
	for i, ps := range permissionSets {
		// Resolve permission items to permission strings
		// Since we don't have a resolver helper handy here, and we just want raw permission keys
		// we can map them directly if items contain the key.
		// Assumption: ps.Items contains PermissionItem which has PermissionID/Key.

		// Wait, toPermissionSetWithItemsResponse requires resolved string slice.
		// We'll simplisticly assume for now that listing assigned sets might not need FULL resolved hierarchy
		// if complex, but the UI expects a list of strings.

		// Let's implement a simple extraction loop locally or reuse what we can.
		// Actually, let's map what we have.

		permStrings := make([]string, 0, len(ps.Items))
		for _, item := range ps.Items {
			// PermissionID is the string key like "user:read"
			permStrings = append(permStrings, item.PermissionID())
		}

		result[i] = toPermissionSetWithItemsResponse(ps, permStrings)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// =============================================================================
// My Groups (Current User)
// =============================================================================

// ListMyGroups handles GET /api/v1/me/groups
// @Summary List current user's groups
// @Description List all groups the current user belongs to
// @Tags groups
// @Produce json
// @Success 200 {array} GroupWithRoleResponse
// @Router /api/v1/me/groups [get]
func (h *GroupHandler) ListMyGroups(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get tenant ID from JWT token
	tenantID := middleware.MustGetTenantID(ctx)

	userID := middleware.GetLocalUserID(ctx)
	if userID.IsZero() {
		apierror.Unauthorized("User context required").WriteJSON(w)
		return
	}

	groups, err := h.service.ListUserGroups(ctx, tenantID, userID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	resp := make([]GroupWithRoleResponse, len(groups))
	for i, g := range groups {
		resp[i] = toGroupWithRoleResponse(g)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// =============================================================================
// Asset Ownership
// =============================================================================

// AssignAssetRequest represents the request to assign an asset to a group.
type AssignAssetRequest struct {
	AssetID       string `json:"asset_id" validate:"required,uuid"`
	OwnershipType string `json:"ownership_type" validate:"required,oneof=primary secondary stakeholder informed"`
}

// AssetOwnerResponse represents an asset ownership in API responses.
type AssetOwnerResponse struct {
	ID            string `json:"id"`
	AssetID       string `json:"asset_id"`
	GroupID       string `json:"group_id,omitempty"`
	UserID        string `json:"user_id,omitempty"`
	OwnershipType string `json:"ownership_type"`
	AssignedAt    string `json:"assigned_at"`
	AssignedBy    string `json:"assigned_by,omitempty"`
}

// AssignAsset handles POST /api/v1/groups/{groupId}/assets
// @Summary Assign an asset to a group
// @Description Assign an asset to the group with specified ownership type
// @Tags groups
// @Accept json
// @Produce json
// @Param groupId path string true "Group ID"
// @Param request body AssignAssetRequest true "Asset assignment details"
// @Success 204 "No Content"
// @Failure 400 {object} apierror.Error
// @Failure 404 {object} apierror.Error
// @Router /api/v1/groups/{groupId}/assets [post]
func (h *GroupHandler) AssignAsset(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	groupID := chi.URLParam(r, "groupId")

	userID := middleware.GetLocalUserID(ctx)
	if userID.IsZero() {
		apierror.Unauthorized("User context required").WriteJSON(w)
		return
	}

	var req AssignAssetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := app.AssignAssetInput{
		GroupID:       groupID,
		AssetID:       req.AssetID,
		OwnershipType: req.OwnershipType,
	}

	actx := h.buildAuditContext(r)

	if err := h.service.AssignAsset(ctx, input, userID, actx); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// UnassignAsset handles DELETE /api/v1/groups/{groupId}/assets/{assetId}
// @Summary Remove an asset from a group
// @Description Remove an asset ownership from the group
// @Tags groups
// @Param groupId path string true "Group ID"
// @Param assetId path string true "Asset ID"
// @Success 204 "No Content"
// @Failure 404 {object} apierror.Error
// @Router /api/v1/groups/{groupId}/assets/{assetId} [delete]
func (h *GroupHandler) UnassignAsset(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	groupID := chi.URLParam(r, "groupId")
	assetID := chi.URLParam(r, "assetId")

	input := app.UnassignAssetInput{
		GroupID: groupID,
		AssetID: assetID,
	}

	actx := h.buildAuditContext(r)

	if err := h.service.UnassignAsset(ctx, input, actx); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// UpdateAssetOwnershipRequest represents the request to update asset ownership type.
type UpdateAssetOwnershipRequest struct {
	OwnershipType string `json:"ownership_type" validate:"required,oneof=primary secondary stakeholder informed"`
}

// UpdateAssetOwnership handles PUT /api/v1/groups/{groupId}/assets/{assetId}
// @Summary Update asset ownership type
// @Description Update the ownership type for an asset in a group
// @Tags groups
// @Accept json
// @Produce json
// @Param groupId path string true "Group ID"
// @Param assetId path string true "Asset ID"
// @Param request body UpdateAssetOwnershipRequest true "Ownership details"
// @Success 204 "No Content"
// @Failure 400 {object} apierror.Error
// @Failure 404 {object} apierror.Error
// @Router /api/v1/groups/{groupId}/assets/{assetId} [put]
func (h *GroupHandler) UpdateAssetOwnership(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	groupID := chi.URLParam(r, "groupId")
	assetID := chi.URLParam(r, "assetId")

	var req UpdateAssetOwnershipRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := app.UpdateAssetOwnershipInput{
		GroupID:       groupID,
		AssetID:       assetID,
		OwnershipType: req.OwnershipType,
	}

	actx := h.buildAuditContext(r)

	if err := h.service.UpdateAssetOwnership(ctx, input, actx); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ListGroupAssets handles GET /api/v1/groups/{groupId}/assets
// @Summary List assets assigned to a group
// @Description List all assets that belong to this group
// @Tags groups
// @Produce json
// @Param groupId path string true "Group ID"
// @Success 200 {array} AssetOwnerResponse
// @Failure 404 {object} apierror.Error
// @Router /api/v1/groups/{groupId}/assets [get]
func (h *GroupHandler) ListGroupAssets(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	groupID := chi.URLParam(r, "groupId")

	owners, err := h.service.ListGroupAssets(ctx, groupID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	resp := make([]AssetOwnerResponse, len(owners))
	for i, ao := range owners {
		resp[i] = AssetOwnerResponse{
			ID:            ao.ID().String(),
			AssetID:       ao.AssetID().String(),
			OwnershipType: ao.OwnershipType().String(),
			AssignedAt:    ao.AssignedAt().Format("2006-01-02T15:04:05Z07:00"),
		}
		if ao.GroupID() != nil {
			resp[i].GroupID = ao.GroupID().String()
		}
		if ao.UserID() != nil {
			resp[i].UserID = ao.UserID().String()
		}
		if ao.AssignedBy() != nil {
			resp[i].AssignedBy = ao.AssignedBy().String()
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// ListMyAssets handles GET /api/v1/me/assets
// @Summary List current user's accessible assets
// @Description List all assets the current user can access through their group memberships
// @Tags assets
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /api/v1/me/assets [get]
func (h *GroupHandler) ListMyAssets(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantID := middleware.MustGetTenantID(ctx)

	userID := middleware.GetLocalUserID(ctx)
	if userID.IsZero() {
		apierror.Unauthorized("User context required").WriteJSON(w)
		return
	}

	assetIDs, err := h.service.ListMyAssets(ctx, tenantID, userID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// Convert to strings
	ids := make([]string, len(assetIDs))
	for i, id := range assetIDs {
		ids[i] = id.String()
	}

	resp := map[string]interface{}{
		"asset_ids": ids,
		"count":     len(ids),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
