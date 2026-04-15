package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/audit"
	moduleTypes "github.com/openctemio/api/pkg/domain/module"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/tenant"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/validator"
)

// recalculateCooldown is the minimum interval between recalculations per tenant.
const recalculateCooldown = 5 * time.Minute

// recalculateLastRun tracks the last recalculation time per tenant ID.
var recalculateLastRun sync.Map

// TenantHandler handles tenant-related HTTP requests.
// Note: "Team" is the UI-facing name for tenants.
type TenantHandler struct {
	service       *app.TenantService
	roleService   *app.RoleService
	assetService  *app.AssetService
	moduleService *app.ModuleService
	validator     *validator.Validator
	logger        *logger.Logger
}

// NewTenantHandler creates a new tenant handler.
func NewTenantHandler(svc *app.TenantService, v *validator.Validator, log *logger.Logger) *TenantHandler {
	return &TenantHandler{
		service:   svc,
		validator: v,
		logger:    log,
	}
}

// SetRoleService sets the role service for fetching RBAC roles.
func (h *TenantHandler) SetRoleService(svc *app.RoleService) {
	h.roleService = svc
}

// SetAssetService sets the asset service for risk scoring operations.
func (h *TenantHandler) SetAssetService(svc *app.AssetService) {
	h.assetService = svc
}

// SetModuleService sets the module service for module management.
func (h *TenantHandler) SetModuleService(svc *app.ModuleService) {
	h.moduleService = svc
}

// =============================================================================
// Response Types
// =============================================================================

// TenantResponse represents a tenant in API responses.
type TenantResponse struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Slug        string         `json:"slug"`
	Description string         `json:"description,omitempty"`
	LogoURL     string         `json:"logo_url,omitempty"`
	Plan        string         `json:"plan"`
	Settings    map[string]any `json:"settings,omitempty"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
}

// TenantWithRoleResponse represents a tenant with the user's role.
type TenantWithRoleResponse struct {
	TenantResponse
	Role     string    `json:"role"`
	JoinedAt time.Time `json:"joined_at"`
}

// MemberResponse represents a tenant member in API responses.
type MemberResponse struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Role      string    `json:"role"`
	InvitedBy string    `json:"invited_by,omitempty"`
	JoinedAt  time.Time `json:"joined_at"`
}

// MemberWithUserResponse represents a member with user details.
type MemberWithUserResponse struct {
	ID          string     `json:"id"`
	UserID      string     `json:"user_id"`
	Role        string     `json:"role"`
	InvitedBy   string     `json:"invited_by,omitempty"`
	JoinedAt    time.Time  `json:"joined_at"`
	Email       string     `json:"email"`
	Name        string     `json:"name"`
	AvatarURL   string     `json:"avatar_url,omitempty"`
	Status      string     `json:"status"`
	LastLoginAt *time.Time `json:"last_login_at,omitempty"`
	// RBAC roles (included when ?include=roles)
	RBACRoles []MemberRBACRoleResponse `json:"rbac_roles,omitempty"`
}

// MemberRBACRoleResponse represents a simplified RBAC role in member response.
type MemberRBACRoleResponse struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Slug     string `json:"slug"`
	IsSystem bool   `json:"is_system"`
}

// MemberStatsResponse represents member statistics.
type MemberStatsResponse struct {
	TotalMembers   int            `json:"total_members"`
	ActiveMembers  int            `json:"active_members"`
	PendingInvites int            `json:"pending_invites"`
	RoleCounts     map[string]int `json:"role_counts"`
}

// InvitationResponse represents an invitation in API responses.
type InvitationResponse struct {
	ID          string    `json:"id"`
	Email       string    `json:"email"`
	Role        string    `json:"role"`     // Deprecated: always "member", use RoleIDs instead
	RoleIDs     []string  `json:"role_ids"` // RBAC role IDs assigned to invitation
	Token       string    `json:"token,omitempty"`
	InvitedBy   string    `json:"invited_by"`
	InviterName string    `json:"inviter_name,omitempty"`
	ExpiresAt   time.Time `json:"expires_at"`
	CreatedAt   time.Time `json:"created_at"`
	Pending     bool      `json:"pending"`
}

// =============================================================================
// Request Types
// =============================================================================

// CreateTenantRequest represents the request to create a tenant.
type CreateTenantRequest struct {
	Name        string `json:"name" validate:"required,min=2,max=100"`
	Slug        string `json:"slug" validate:"required,min=3,max=100,slug"`
	Description string `json:"description" validate:"max=500"`
}

// UpdateTenantRequest represents the request to update a tenant.
type UpdateTenantRequest struct {
	Name        *string `json:"name" validate:"omitempty,min=2,max=100"`
	Slug        *string `json:"slug" validate:"omitempty,min=3,max=100,slug"`
	Description *string `json:"description" validate:"omitempty,max=500"`
	LogoURL     *string `json:"logo_url" validate:"omitempty,url,max=500"`
}

// AddMemberRequest represents the request to add a member.
type AddMemberRequest struct {
	UserID string `json:"user_id" validate:"required"`
	Role   string `json:"role" validate:"required,oneof=admin member viewer"`
}

// UpdateMemberRoleRequest represents the request to update a member's role.
type UpdateMemberRoleRequest struct {
	Role string `json:"role" validate:"required,oneof=admin member viewer"`
}

// CreateInvitationRequest represents the request to create an invitation.
// Note: In simplified model, all invited users are "member". Permissions come from RBAC roles.
type CreateInvitationRequest struct {
	Email   string   `json:"email" validate:"required,email,max=254"`
	RoleIDs []string `json:"role_ids" validate:"required,min=1,max=10"` // RBAC roles to assign (required, max 10)
}

// =============================================================================
// Response Converters
// =============================================================================

func toTenantResponse(t *tenant.Tenant) TenantResponse {
	return TenantResponse{
		ID:          t.ID().String(),
		Name:        t.Name(),
		Slug:        t.Slug(),
		Description: t.Description(),
		LogoURL:     t.LogoURL(),
		Plan:        t.Plan().String(),
		Settings:    t.Settings(),
		CreatedAt:   t.CreatedAt(),
		UpdatedAt:   t.UpdatedAt(),
	}
}

func toTenantWithRoleResponse(twr *tenant.TenantWithRole) TenantWithRoleResponse {
	return TenantWithRoleResponse{
		TenantResponse: toTenantResponse(twr.Tenant),
		Role:           twr.Role.String(),
		JoinedAt:       twr.JoinedAt,
	}
}

func toMemberResponse(m *tenant.Membership) MemberResponse {
	var invitedBy string
	if m.InvitedBy() != nil {
		invitedBy = m.InvitedBy().String()
	}
	return MemberResponse{
		ID:        m.ID().String(),
		UserID:    m.UserID().String(),
		Role:      m.Role().String(),
		InvitedBy: invitedBy,
		JoinedAt:  m.JoinedAt(),
	}
}

func toInvitationResponse(inv *tenant.Invitation, includeToken bool) InvitationResponse {
	roleIDs := inv.RoleIDs()
	if roleIDs == nil {
		roleIDs = []string{}
	}
	resp := InvitationResponse{
		ID:        inv.ID().String(),
		Email:     inv.Email(),
		Role:      inv.Role().String(),
		RoleIDs:   roleIDs,
		InvitedBy: inv.InvitedBy().String(),
		ExpiresAt: inv.ExpiresAt(),
		CreatedAt: inv.CreatedAt(),
		Pending:   inv.IsPending(),
	}
	if includeToken {
		resp.Token = inv.Token()
	}
	return resp
}

// =============================================================================
// Helpers
// =============================================================================

// buildAuditContext builds an AuditContext from the HTTP request.
func (h *TenantHandler) buildAuditContext(r *http.Request) app.AuditContext {
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

	// Set tenant ID if available
	if tenantID := middleware.GetTeamID(r.Context()); !tenantID.IsZero() {
		actx.TenantID = tenantID.String()
	}

	return actx
}

// =============================================================================
// Error Handlers
// =============================================================================

func (h *TenantHandler) handleValidationError(w http.ResponseWriter, err error) {
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

func (h *TenantHandler) handleServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Tenant").WriteJSON(w)
	case errors.Is(err, shared.ErrAlreadyExists):
		apierror.Conflict("Tenant already exists").WriteJSON(w)
	case errors.Is(err, shared.ErrConflict):
		apierror.Conflict(err.Error()).WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		// Extract just the message without the wrapped error prefix
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
// Tenant Handlers
// =============================================================================

// Create handles POST /api/v1/tenants
func (h *TenantHandler) Create(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetLocalUserID(r.Context())
	if userID.IsZero() {
		apierror.Unauthorized("Authentication required").WriteJSON(w)
		return
	}

	var req CreateTenantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := app.CreateTenantInput{
		Name:        req.Name,
		Slug:        req.Slug,
		Description: req.Description,
	}

	actx := h.buildAuditContext(r)
	t, err := h.service.CreateTenant(r.Context(), input, userID, actx)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(toTenantResponse(t))
}

// List handles GET /api/v1/tenants (lists user's tenants)
func (h *TenantHandler) List(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetLocalUserID(r.Context())
	if userID.IsZero() {
		apierror.Unauthorized("Authentication required").WriteJSON(w)
		return
	}

	tenants, err := h.service.ListUserTenants(r.Context(), userID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	response := make([]TenantWithRoleResponse, len(tenants))
	for i, t := range tenants {
		response[i] = toTenantWithRoleResponse(t)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"data":  response,
		"total": len(response),
	})
}

// Get handles GET /api/v1/tenants/{tenant}
func (h *TenantHandler) Get(w http.ResponseWriter, r *http.Request) {
	tenantParam := r.PathValue("tenant")
	if tenantParam == "" {
		apierror.BadRequest("Tenant ID or slug is required").WriteJSON(w)
		return
	}

	var t *tenant.Tenant
	var err error

	// Try to parse as UUID first
	if tenantID, parseErr := shared.IDFromString(tenantParam); parseErr == nil {
		t, err = h.service.GetTenant(r.Context(), tenantID.String())
	} else {
		t, err = h.service.GetTenantBySlug(r.Context(), tenantParam)
	}

	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toTenantResponse(t))
}

// Update handles PATCH /api/v1/tenants/{tenant}
func (h *TenantHandler) Update(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTeamID(r.Context())
	if tenantID.IsZero() {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}

	var req UpdateTenantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := app.UpdateTenantInput{
		Name:        req.Name,
		Slug:        req.Slug,
		Description: req.Description,
		LogoURL:     req.LogoURL,
	}

	t, err := h.service.UpdateTenant(r.Context(), tenantID.String(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toTenantResponse(t))
}

// Delete handles DELETE /api/v1/tenants/{tenant}
func (h *TenantHandler) Delete(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTeamID(r.Context())
	if tenantID.IsZero() {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}

	if err := h.service.DeleteTenant(r.Context(), tenantID.String()); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// =============================================================================
// Member Handlers
// =============================================================================

// ListMembers handles GET /api/v1/tenants/{tenant}/members
// Query parameters:
//   - include: comma-separated list (user, roles)
//   - search: search term for name or email (requires include=user)
//   - limit: max results (default 10, max 100)
//   - offset: pagination offset
func (h *TenantHandler) ListMembers(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTeamID(r.Context())
	if tenantID.IsZero() {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}

	// Parse include parameter (supports: user, roles, or both: user,roles)
	includeParam := r.URL.Query().Get("include")
	includes := make(map[string]bool)
	if includeParam != "" {
		for _, inc := range strings.Split(includeParam, ",") {
			includes[strings.TrimSpace(inc)] = true
		}
	}

	includeUser := includes["user"]
	includeRoles := includes["roles"]

	// Parse search/pagination parameters. We always go through the
	// paginated SearchMembersWithUserInfo path when include=user is
	// set, even if the client did not pass an explicit limit — the
	// default cap protects the API from accidentally returning every
	// member of a 50k-tenant in one response. Clients that want more
	// results must opt in by passing limit=N (capped server-side).
	const (
		defaultMemberLimit = 100
		maxMemberLimit     = 500
	)
	search := r.URL.Query().Get("search")
	limit := defaultMemberLimit
	offset := 0
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 {
			if parsed > maxMemberLimit {
				parsed = maxMemberLimit
			}
			limit = parsed
		}
	}
	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if parsed, err := strconv.Atoi(offsetStr); err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	if includeUser {
		// Always paginate when include=user. The legacy unpaginated
		// path was a memory hazard for large tenants.
		filters := tenant.MemberSearchFilters{
			Search: search,
			Limit:  limit,
			Offset: offset,
		}
		result, err := h.service.SearchMembersWithUserInfo(r.Context(), tenantID.String(), filters)
		if err != nil {
			h.handleServiceError(w, err)
			return
		}
		members := result.Members
		total := result.Total

		response := make([]MemberWithUserResponse, len(members))
		for i, m := range members {
			var invitedBy string
			if m.InvitedBy != nil {
				invitedBy = m.InvitedBy.String()
			}
			response[i] = MemberWithUserResponse{
				ID:          m.ID.String(),
				UserID:      m.UserID.String(),
				Role:        m.Role.String(),
				InvitedBy:   invitedBy,
				JoinedAt:    m.JoinedAt,
				Email:       m.Email,
				Name:        m.Name,
				AvatarURL:   m.AvatarURL,
				Status:      m.Status,
				LastLoginAt: m.LastLoginAt,
			}
		}

		// Fetch RBAC roles for all members if requested
		if includeRoles && h.roleService != nil {
			h.enrichMembersWithRoles(r.Context(), tenantID.String(), response)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data":  response,
			"total": total,
		})
		return
	}

	// Basic member list
	members, err := h.service.ListMembers(r.Context(), tenantID.String())
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	response := make([]MemberResponse, len(members))
	for i, m := range members {
		response[i] = toMemberResponse(m)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"data":  response,
		"total": len(response),
	})
}

// enrichMembersWithRoles fetches RBAC roles for all members in ONE
// batch query, then attaches the role list to each MemberWithUserResponse.
//
// The previous implementation looped over members and called
// GetUserRoles per user — N+1: a tenant with 100 members made 101 DB
// queries (1 to fetch members + 100 for roles). Now it makes 2:
// one to load all members, one to load all their roles.
func (h *TenantHandler) enrichMembersWithRoles(ctx context.Context, tenantID string, members []MemberWithUserResponse) {
	if h.roleService == nil || len(members) == 0 {
		return
	}

	userIDs := make([]string, 0, len(members))
	for i := range members {
		userIDs = append(userIDs, members[i].UserID)
	}

	rolesByUser, err := h.roleService.GetUsersRoles(ctx, tenantID, userIDs)
	if err != nil {
		h.logger.Warn("failed to batch-fetch roles for members",
			"tenant_id", tenantID, "count", len(userIDs), "error", err)
		return
	}

	for i := range members {
		userRoles := rolesByUser[members[i].UserID]
		rbacRoles := make([]MemberRBACRoleResponse, 0, len(userRoles))
		for _, r := range userRoles {
			rbacRoles = append(rbacRoles, MemberRBACRoleResponse{
				ID:       r.ID().String(),
				Name:     r.Name(),
				Slug:     r.Slug(),
				IsSystem: r.IsSystem(),
			})
		}
		members[i].RBACRoles = rbacRoles
	}
}

// GetMemberStats handles GET /api/v1/tenants/{tenant}/members/stats
func (h *TenantHandler) GetMemberStats(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTeamID(r.Context())
	if tenantID.IsZero() {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}

	stats, err := h.service.GetMemberStats(r.Context(), tenantID.String())
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	response := MemberStatsResponse{
		TotalMembers:   stats.TotalMembers,
		ActiveMembers:  stats.ActiveMembers,
		PendingInvites: stats.PendingInvites,
		RoleCounts:     stats.RoleCounts,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

// AddMember handles POST /api/v1/tenants/{tenant}/members
func (h *TenantHandler) AddMember(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTeamID(r.Context())
	if tenantID.IsZero() {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}

	inviterID := middleware.GetLocalUserID(r.Context())
	if inviterID.IsZero() {
		apierror.Unauthorized("Authentication required").WriteJSON(w)
		return
	}

	var req AddMemberRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	// Parse user ID as UUID
	userID, err := shared.IDFromString(req.UserID)
	if err != nil {
		apierror.BadRequest("Invalid user ID format").WriteJSON(w)
		return
	}

	input := app.AddMemberInput{
		UserID: userID,
		Role:   req.Role,
	}

	actx := h.buildAuditContext(r)
	membership, err := h.service.AddMember(r.Context(), tenantID.String(), input, inviterID, actx)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(toMemberResponse(membership))
}

// UpdateMemberRole handles PATCH /api/v1/tenants/{tenant}/members/{memberId}
func (h *TenantHandler) UpdateMemberRole(w http.ResponseWriter, r *http.Request) {
	memberID := r.PathValue("userId")
	if memberID == "" {
		apierror.BadRequest("Member ID is required").WriteJSON(w)
		return
	}

	var req UpdateMemberRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := app.UpdateMemberRoleInput{
		Role: req.Role,
	}

	actx := h.buildAuditContext(r)
	membership, err := h.service.UpdateMemberRole(r.Context(), memberID, input, actx)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toMemberResponse(membership))
}

// RemoveMember handles DELETE /api/v1/tenants/{tenant}/members/{memberId}
func (h *TenantHandler) RemoveMember(w http.ResponseWriter, r *http.Request) {
	memberID := r.PathValue("userId")
	if memberID == "" {
		apierror.BadRequest("Member ID is required").WriteJSON(w)
		return
	}

	actx := h.buildAuditContext(r)
	if err := h.service.RemoveMember(r.Context(), memberID, actx); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// SuspendMember handles POST /api/v1/tenants/{tenant}/members/{memberId}/suspend
func (h *TenantHandler) SuspendMember(w http.ResponseWriter, r *http.Request) {
	memberID := r.PathValue("userId")
	if memberID == "" {
		apierror.BadRequest("Member ID is required").WriteJSON(w)
		return
	}

	actx := h.buildAuditContext(r)
	if err := h.service.SuspendMember(r.Context(), memberID, actx); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"message": "Member suspended"})
}

// ReactivateMember handles POST /api/v1/tenants/{tenant}/members/{memberId}/reactivate
func (h *TenantHandler) ReactivateMember(w http.ResponseWriter, r *http.Request) {
	memberID := r.PathValue("userId")
	if memberID == "" {
		apierror.BadRequest("Member ID is required").WriteJSON(w)
		return
	}

	actx := h.buildAuditContext(r)
	if err := h.service.ReactivateMember(r.Context(), memberID, actx); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"message": "Member reactivated"})
}

// =============================================================================
// Invitation Handlers
// =============================================================================

// ListInvitations handles GET /api/v1/tenants/{tenant}/invitations
func (h *TenantHandler) ListInvitations(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTeamID(r.Context())
	if tenantID.IsZero() {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}

	invitations, err := h.service.ListPendingInvitations(r.Context(), tenantID.String())
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	response := make([]InvitationResponse, len(invitations))
	for i, inv := range invitations {
		// Include token for admins to copy invitation link
		response[i] = toInvitationResponse(inv, true)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"data":  response,
		"total": len(response),
	})
}

// CreateInvitation handles POST /api/v1/tenants/{tenant}/invitations
func (h *TenantHandler) CreateInvitation(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTeamID(r.Context())
	if tenantID.IsZero() {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}

	inviterID := middleware.GetLocalUserID(r.Context())
	if inviterID.IsZero() {
		apierror.Unauthorized("Authentication required").WriteJSON(w)
		return
	}

	var req CreateInvitationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	// In simplified model, all invited users are "member"
	// Permissions come from RBAC roles (roleIDs)
	input := app.CreateInvitationInput{
		Email:   req.Email,
		Role:    "member", // Always "member" - owner is never created via invitation
		RoleIDs: req.RoleIDs,
	}

	actx := h.buildAuditContext(r)
	invitation, err := h.service.CreateInvitation(r.Context(), tenantID.String(), input, inviterID, actx)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(toInvitationResponse(invitation, true)) // Include token for creator
}

// DeleteInvitation handles DELETE /api/v1/tenants/{tenant}/invitations/{invitationId}
func (h *TenantHandler) DeleteInvitation(w http.ResponseWriter, r *http.Request) {
	invitationID := r.PathValue("invitationId")
	if invitationID == "" {
		apierror.BadRequest("Invitation ID is required").WriteJSON(w)
		return
	}

	if err := h.service.DeleteInvitation(r.Context(), invitationID); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ResendInvitation handles POST /api/v1/tenants/{tenant}/invitations/{invitationId}/resend
//
// Re-sends the invitation email for a pending (unaccepted, unexpired)
// invitation. Does NOT change the token, expiry, or any other metadata.
// Idempotent — calling it 3 times sends 3 emails, all containing the
// same token link. The existing link in the user's inbox stays valid.
//
// Returns 200 on success, 400 if the invitation was already accepted
// or has expired, 404 if the invitation doesn't exist or belongs to a
// different tenant.
func (h *TenantHandler) ResendInvitation(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	invitationID := r.PathValue("invitationId")
	if invitationID == "" {
		apierror.BadRequest("Invitation ID is required").WriteJSON(w)
		return
	}

	actx := h.buildAuditContext(r)
	if err := h.service.ResendInvitation(r.Context(), tenantID, invitationID, actx); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"message": "Invitation email resent",
	})
}

// GetInvitation handles GET /api/v1/invitations/{token}
func (h *TenantHandler) GetInvitation(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	if token == "" {
		apierror.BadRequest("Invitation token is required").WriteJSON(w)
		return
	}

	invitation, err := h.service.GetInvitationByToken(r.Context(), token)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// Get the tenant info to include in response
	t, err := h.service.GetTenant(r.Context(), invitation.TenantID().String())
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// Get inviter name for better UX
	inviterName := h.service.GetUserDisplayName(r.Context(), invitation.InvitedBy())

	invResp := toInvitationResponse(invitation, false)
	invResp.InviterName = inviterName

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"invitation": invResp,
		"tenant":     toTenantResponse(t),
	})
}

// GetInvitationPreview handles GET /api/v1/invitations/{token}/preview (public)
// Returns limited invitation info without requiring authentication.
// This allows users to see what team they're invited to before logging in.
func (h *TenantHandler) GetInvitationPreview(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	if token == "" || strings.ContainsRune(token, 0) || len(token) < 40 || len(token) > 100 {
		apierror.BadRequest("Invalid invitation token").WriteJSON(w)
		return
	}

	invitation, err := h.service.GetInvitationByToken(r.Context(), token)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// Get the tenant info
	t, err := h.service.GetTenant(r.Context(), invitation.TenantID().String())
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// Get inviter name for better UX
	inviterName := h.service.GetUserDisplayName(r.Context(), invitation.InvitedBy())

	// Return limited info (no sensitive data like token)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"invitation": map[string]any{
			"id":           invitation.ID().String(),
			"email":        invitation.Email(),
			"role":         invitation.Role().String(),
			"pending":      invitation.IsPending(),
			"expires_at":   invitation.ExpiresAt(),
			"inviter_name": inviterName,
		},
		"tenant": map[string]any{
			"id":   t.ID().String(),
			"name": t.Name(),
			"slug": t.Slug(),
		},
	})
}

// AcceptInvitation handles POST /api/v1/invitations/{token}/accept
func (h *TenantHandler) AcceptInvitation(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	if token == "" {
		apierror.BadRequest("Invitation token is required").WriteJSON(w)
		return
	}

	localUser := middleware.GetLocalUser(r.Context())
	if localUser == nil {
		apierror.Unauthorized("Authentication required").WriteJSON(w)
		return
	}

	actx := h.buildAuditContext(r)
	membership, err := h.service.AcceptInvitation(r.Context(), token, localUser.ID(), localUser.Email(), actx)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toMemberResponse(membership))
}

// DeclineInvitation handles POST /api/v1/invitations/{token}/decline
// This is a public endpoint - having the token is authorization to decline.
// Similar to email unsubscribe links.
func (h *TenantHandler) DeclineInvitation(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	if token == "" {
		apierror.BadRequest("Invitation token is required").WriteJSON(w)
		return
	}

	// Get invitation to verify it exists
	invitation, err := h.service.GetInvitationByToken(r.Context(), token)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// Delete the invitation
	if err := h.service.DeleteInvitation(r.Context(), invitation.ID().String()); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// =============================================================================
// Settings Handlers
// =============================================================================

// SettingsResponse represents tenant settings in API responses.
type SettingsResponse struct {
	General     GeneralSettingsResponse    `json:"general"`
	Security    SecuritySettingsResponse   `json:"security"`
	API         APISettingsResponse        `json:"api"`
	Branding    BrandingSettingsResponse   `json:"branding"`
	RiskScoring tenant.RiskScoringSettings `json:"risk_scoring"`
	Pentest     tenant.PentestSettings     `json:"pentest"`
}

// GeneralSettingsResponse represents general settings.
type GeneralSettingsResponse struct {
	Timezone string `json:"timezone"`
	Language string `json:"language"`
	Industry string `json:"industry"`
	Website  string `json:"website"`
}

// SecuritySettingsResponse represents security settings.
type SecuritySettingsResponse struct {
	SSOEnabled            bool     `json:"sso_enabled"`
	SSOProvider           string   `json:"sso_provider,omitempty"`
	MFARequired           bool     `json:"mfa_required"`
	SessionTimeoutMin     int      `json:"session_timeout_min"`
	IPWhitelist           []string `json:"ip_whitelist"`
	AllowedDomains        []string `json:"allowed_domains"`
	EmailVerificationMode string   `json:"email_verification_mode"`
}

// APISettingsResponse represents API settings.
type APISettingsResponse struct {
	APIKeyEnabled bool     `json:"api_key_enabled"`
	WebhookURL    string   `json:"webhook_url,omitempty"`
	WebhookEvents []string `json:"webhook_events"`
}

// BrandingSettingsResponse represents branding settings.
type BrandingSettingsResponse struct {
	PrimaryColor string `json:"primary_color"`
	LogoDarkURL  string `json:"logo_dark_url,omitempty"`
	LogoData     string `json:"logo_data,omitempty"`
}

func toSettingsResponse(s *tenant.Settings) SettingsResponse {
	webhookEvents := make([]string, len(s.API.WebhookEvents))
	for i, e := range s.API.WebhookEvents {
		webhookEvents[i] = string(e)
	}

	return SettingsResponse{
		General: GeneralSettingsResponse{
			Timezone: s.General.Timezone,
			Language: s.General.Language,
			Industry: s.General.Industry,
			Website:  s.General.Website,
		},
		Security: SecuritySettingsResponse{
			SSOEnabled:            s.Security.SSOEnabled,
			SSOProvider:           s.Security.SSOProvider,
			MFARequired:           s.Security.MFARequired,
			SessionTimeoutMin:     s.Security.SessionTimeoutMin,
			IPWhitelist:           s.Security.IPWhitelist,
			AllowedDomains:        s.Security.AllowedDomains,
			EmailVerificationMode: string(s.Security.EmailVerificationMode),
		},
		API: APISettingsResponse{
			APIKeyEnabled: s.API.APIKeyEnabled,
			WebhookURL:    s.API.WebhookURL,
			WebhookEvents: webhookEvents,
		},
		Branding: BrandingSettingsResponse{
			PrimaryColor: s.Branding.PrimaryColor,
			LogoDarkURL:  s.Branding.LogoDarkURL,
			LogoData:     s.Branding.LogoData,
		},
		RiskScoring: s.RiskScoring,
		Pentest:     pentestWithDefaults(s.Pentest),
	}
}

// pentestWithDefaults returns pentest settings with system defaults for empty fields.
func pentestWithDefaults(ps tenant.PentestSettings) tenant.PentestSettings {
	defaults := tenant.DefaultSettings().Pentest
	if len(ps.CampaignTypes) == 0 {
		ps.CampaignTypes = defaults.CampaignTypes
	}
	if len(ps.Methodologies) == 0 {
		ps.Methodologies = defaults.Methodologies
	}
	return ps
}

// GetSettings handles GET /api/v1/tenants/{tenant}/settings
func (h *TenantHandler) GetSettings(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTeamID(r.Context())
	if tenantID.IsZero() {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}

	settings, err := h.service.GetTenantSettings(r.Context(), tenantID.String())
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toSettingsResponse(settings))
}

// UpdateGeneralSettingsRequest represents the request to update general settings.
type UpdateGeneralSettingsRequest struct {
	Timezone string `json:"timezone"`
	Language string `json:"language" validate:"omitempty,oneof=en vi ja ko zh"`
	Industry string `json:"industry" validate:"max=100"`
	Website  string `json:"website" validate:"omitempty,url,max=500"`
}

// UpdateGeneralSettings handles PATCH /api/v1/tenants/{tenant}/settings/general
func (h *TenantHandler) UpdateGeneralSettings(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTeamID(r.Context())
	if tenantID.IsZero() {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}

	var req UpdateGeneralSettingsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := app.UpdateGeneralSettingsInput{
		Timezone: req.Timezone,
		Language: req.Language,
		Industry: req.Industry,
		Website:  req.Website,
	}

	actx := h.buildAuditContext(r)
	settings, err := h.service.UpdateGeneralSettings(r.Context(), tenantID.String(), input, actx)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toSettingsResponse(settings))
}

// UpdateSecuritySettingsRequest represents the request to update security settings.
type UpdateSecuritySettingsRequest struct {
	SSOEnabled            bool     `json:"sso_enabled"`
	SSOProvider           string   `json:"sso_provider" validate:"omitempty,oneof=saml oidc"`
	SSOConfigURL          string   `json:"sso_config_url" validate:"omitempty,url"`
	MFARequired           bool     `json:"mfa_required"`
	SessionTimeoutMin     int      `json:"session_timeout_min" validate:"omitempty,min=15,max=480"`
	IPWhitelist           []string `json:"ip_whitelist"`
	AllowedDomains        []string `json:"allowed_domains"`
	EmailVerificationMode string   `json:"email_verification_mode" validate:"omitempty,oneof=auto always never"`
}

// UpdateSecuritySettings handles PATCH /api/v1/tenants/{tenant}/settings/security
func (h *TenantHandler) UpdateSecuritySettings(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTeamID(r.Context())
	if tenantID.IsZero() {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}

	var req UpdateSecuritySettingsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := app.UpdateSecuritySettingsInput{
		SSOEnabled:            req.SSOEnabled,
		SSOProvider:           req.SSOProvider,
		SSOConfigURL:          req.SSOConfigURL,
		MFARequired:           req.MFARequired,
		SessionTimeoutMin:     req.SessionTimeoutMin,
		IPWhitelist:           req.IPWhitelist,
		AllowedDomains:        req.AllowedDomains,
		EmailVerificationMode: req.EmailVerificationMode,
	}

	actx := h.buildAuditContext(r)
	settings, err := h.service.UpdateSecuritySettings(r.Context(), tenantID.String(), input, actx)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toSettingsResponse(settings))
}

// UpdateAPISettingsRequest represents the request to update API settings.
type UpdateAPISettingsRequest struct {
	APIKeyEnabled bool     `json:"api_key_enabled"`
	WebhookURL    string   `json:"webhook_url" validate:"omitempty,url"`
	WebhookSecret string   `json:"webhook_secret"`
	WebhookEvents []string `json:"webhook_events"`
}

// UpdateAPISettings handles PATCH /api/v1/tenants/{tenant}/settings/api
func (h *TenantHandler) UpdateAPISettings(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTeamID(r.Context())
	if tenantID.IsZero() {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}

	var req UpdateAPISettingsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := app.UpdateAPISettingsInput{
		APIKeyEnabled: req.APIKeyEnabled,
		WebhookURL:    req.WebhookURL,
		WebhookSecret: req.WebhookSecret,
		WebhookEvents: req.WebhookEvents,
	}

	actx := h.buildAuditContext(r)
	settings, err := h.service.UpdateAPISettings(r.Context(), tenantID.String(), input, actx)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toSettingsResponse(settings))
}

// UpdateBrandingSettingsRequest represents the request to update branding settings.
type UpdateBrandingSettingsRequest struct {
	PrimaryColor string `json:"primary_color"`
	LogoDarkURL  string `json:"logo_dark_url" validate:"omitempty,url"`
	LogoData     string `json:"logo_data"` // Base64 encoded logo (max 150KB)
}

// UpdateBrandingSettings handles PATCH /api/v1/tenants/{tenant}/settings/branding
func (h *TenantHandler) UpdateBrandingSettings(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTeamID(r.Context())
	if tenantID.IsZero() {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}

	var req UpdateBrandingSettingsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := app.UpdateBrandingSettingsInput{
		PrimaryColor: req.PrimaryColor,
		LogoDarkURL:  req.LogoDarkURL,
		LogoData:     req.LogoData,
	}

	actx := h.buildAuditContext(r)
	settings, err := h.service.UpdateBrandingSettings(r.Context(), tenantID.String(), input, actx)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toSettingsResponse(settings))
}

// UpdateBranchSettingsRequest represents the request to update branch naming convention settings.
type UpdateBranchSettingsRequest struct {
	TypeRules []app.BranchTypeRuleInput `json:"type_rules" validate:"dive"`
}

// UpdateBranchSettings handles PATCH /api/v1/tenants/{tenant}/settings/branch
func (h *TenantHandler) UpdateBranchSettings(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTeamID(r.Context())
	if tenantID.IsZero() {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}

	var req UpdateBranchSettingsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := app.UpdateBranchSettingsInput{
		TypeRules: req.TypeRules,
	}

	actx := h.buildAuditContext(r)
	settings, err := h.service.UpdateBranchSettings(r.Context(), tenantID.String(), input, actx)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toSettingsResponse(settings))
}

// =============================================================================
// Pentest Settings Endpoints
// =============================================================================

// UpdatePentestSettingsRequest represents the request to update pentest settings.
type UpdatePentestSettingsRequest struct {
	CampaignTypes []tenant.ConfigOption `json:"campaign_types" validate:"dive"`
	Methodologies []tenant.ConfigOption `json:"methodologies" validate:"dive"`
}

// GetPentestSettings handles GET /api/v1/tenants/{tenant}/settings/pentest
func (h *TenantHandler) GetPentestSettings(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTeamID(r.Context())
	if tenantID.IsZero() {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}

	ps, err := h.service.GetPentestSettings(r.Context(), tenantID.String())
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ps)
}

// UpdatePentestSettings handles PATCH /api/v1/tenants/{tenant}/settings/pentest
func (h *TenantHandler) UpdatePentestSettings(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTeamID(r.Context())
	if tenantID.IsZero() {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}

	var req UpdatePentestSettingsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := app.UpdatePentestSettingsInput{
		CampaignTypes: req.CampaignTypes,
		Methodologies: req.Methodologies,
	}

	actx := h.buildAuditContext(r)
	settings, err := h.service.UpdatePentestSettings(r.Context(), tenantID.String(), input, actx)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toSettingsResponse(settings))
}

// =============================================================================
// Risk Scoring Settings Endpoints
// =============================================================================

// GetRiskScoringSettings handles GET /api/v1/tenants/{tenant}/settings/risk-scoring
func (h *TenantHandler) GetRiskScoringSettings(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTeamID(r.Context())
	if tenantID.IsZero() {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}

	rs, err := h.service.GetRiskScoringSettings(r.Context(), tenantID.String())
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(rs)
}

// UpdateRiskScoringSettings handles PATCH /api/v1/tenants/{tenant}/settings/risk-scoring
func (h *TenantHandler) UpdateRiskScoringSettings(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTeamID(r.Context())
	if tenantID.IsZero() {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}

	var req tenant.RiskScoringSettings
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := req.Validate(); err != nil {
		apierror.BadRequest(err.Error()).WriteJSON(w)
		return
	}

	actx := h.buildAuditContext(r)
	settings, err := h.service.UpdateRiskScoringSettings(r.Context(), tenantID.String(), req, actx)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// Invalidate scoring config cache so new formula takes effect immediately
	if h.assetService != nil {
		h.assetService.InvalidateScoringConfigCache(tenantID)
	}

	// Auto-recalculate all asset risk scores after saving new config
	var assetsUpdated int
	if h.assetService != nil {
		updated, recalcErr := h.assetService.RecalculateAllRiskScores(r.Context(), tenantID)
		if recalcErr != nil {
			h.logger.Warn("auto-recalculate after config save failed",
				"tenant_id", tenantID.String(), "error", recalcErr)
		} else {
			assetsUpdated = updated
			// Record recalculation time for rate limiting on the dedicated endpoint
			recalculateLastRun.Store(tenantID.String(), time.Now())
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"config":         settings.RiskScoring,
		"assets_updated": assetsUpdated,
	})
}

// PreviewRiskScoringChanges handles POST /api/v1/tenants/{tenant}/settings/risk-scoring/preview
func (h *TenantHandler) PreviewRiskScoringChanges(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTeamID(r.Context())
	if tenantID.IsZero() {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}

	if h.assetService == nil {
		apierror.InternalServerError("Asset service not configured").WriteJSON(w)
		return
	}

	var req tenant.RiskScoringSettings
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := req.Validate(); err != nil {
		apierror.BadRequest(err.Error()).WriteJSON(w)
		return
	}

	config := app.MapTenantToAssetScoringConfig(&req)
	items, totalAssets, err := h.assetService.PreviewRiskScoreChanges(r.Context(), tenantID, config)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"assets":       items,
		"sample_count": len(items),
		"total_assets": totalAssets,
	})
}

// RecalculateRiskScores handles POST /api/v1/tenants/{tenant}/settings/risk-scoring/recalculate
func (h *TenantHandler) RecalculateRiskScores(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTeamID(r.Context())
	if tenantID.IsZero() {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}

	if h.assetService == nil {
		apierror.InternalServerError("Asset service not configured").WriteJSON(w)
		return
	}

	// Rate limit: max 1 recalculation per 5 minutes per tenant
	tenantKey := tenantID.String()
	now := time.Now()
	if lastRun, ok := recalculateLastRun.Load(tenantKey); ok {
		lastTime := lastRun.(time.Time)
		elapsed := now.Sub(lastTime)
		if elapsed < recalculateCooldown {
			retryAfter := int(math.Ceil(recalculateCooldown.Seconds() - elapsed.Seconds()))
			w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
			apierror.TooManyRequests(
				fmt.Sprintf("Risk score recalculation is limited to once every %d minutes. Try again in %d seconds.",
					int(recalculateCooldown.Minutes()), retryAfter),
			).WriteJSON(w)
			return
		}
	}

	actx := h.buildAuditContext(r)

	updated, err := h.assetService.RecalculateAllRiskScores(r.Context(), tenantID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// Record successful recalculation time for rate limiting
	recalculateLastRun.Store(tenantKey, time.Now())

	// Audit log the recalculation
	event := app.NewSuccessEvent(audit.ActionTenantRiskScoresRecalculated, audit.ResourceTypeTenant, tenantKey).
		WithMessage(fmt.Sprintf("Risk scores recalculated for %d assets", updated)).
		WithMetadata("assets_updated", updated).
		WithSeverity(audit.SeverityMedium)
	h.service.LogAuditEvent(r.Context(), actx, event)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"assets_updated": updated,
	})
}

// GetRiskScoringPresets handles GET /api/v1/tenants/{tenant}/settings/risk-scoring/presets
func (h *TenantHandler) GetRiskScoringPresets(w http.ResponseWriter, r *http.Request) {
	presets := tenant.AllRiskScoringPresets

	type presetResponse struct {
		Name   string                     `json:"name"`
		Config tenant.RiskScoringSettings `json:"config"`
	}

	result := make([]presetResponse, 0, len(presets))
	for name, config := range presets {
		result = append(result, presetResponse{
			Name:   name,
			Config: config,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

// =============================================================================
// Module Management
// =============================================================================

// TenantModuleResponse represents a module with tenant-specific state.
type TenantModuleResponse struct {
	ID            string                    `json:"id"`
	Name          string                    `json:"name"`
	Description   string                    `json:"description,omitempty"`
	Icon          string                    `json:"icon,omitempty"`
	Category      string                    `json:"category"`
	DisplayOrder  int                       `json:"display_order"`
	IsCore        bool                      `json:"is_core"`
	IsEnabled     bool                      `json:"is_enabled"`
	ReleaseStatus string                    `json:"release_status"`
	SubModules    []TenantSubModuleResponse `json:"sub_modules,omitempty"`
}

// TenantSubModuleResponse represents a sub-module in the response.
type TenantSubModuleResponse struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Description   string `json:"description,omitempty"`
	Icon          string `json:"icon,omitempty"`
	ReleaseStatus string `json:"release_status"`
	IsEnabled     bool   `json:"is_enabled"`
}

// TenantModuleListResponse wraps the module list with summary.
type TenantModuleListResponse struct {
	Modules []TenantModuleResponse `json:"modules"`
	Summary TenantModuleSummaryResponse `json:"summary"`
}

// TenantModuleSummaryResponse provides module counts.
type TenantModuleSummaryResponse struct {
	Total    int `json:"total"`
	Enabled  int `json:"enabled"`
	Disabled int `json:"disabled"`
	Core     int `json:"core"`
}

// UpdateTenantModulesRequest is the request body for toggling modules.
type UpdateTenantModulesRequest struct {
	Modules []ModuleToggleRequest `json:"modules" validate:"required,min=1,dive"`
}

// ModuleToggleRequest represents a single module toggle.
type ModuleToggleRequest struct {
	ModuleID  string `json:"module_id" validate:"required"`
	IsEnabled bool   `json:"is_enabled"`
}

// GetTenantModules handles GET /api/v1/tenants/{tenant}/settings/modules
func (h *TenantHandler) GetTenantModules(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTeamID(r.Context())
	if tenantID.IsZero() {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}

	if h.moduleService == nil {
		apierror.InternalServerError("Module service not configured").WriteJSON(w)
		return
	}

	config, err := h.moduleService.GetTenantModuleConfig(r.Context(), tenantID.String())
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toTenantModuleListResponse(config))
}

// UpdateTenantModules handles PATCH /api/v1/tenants/{tenant}/settings/modules
func (h *TenantHandler) UpdateTenantModules(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTeamID(r.Context())
	if tenantID.IsZero() {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}

	if h.moduleService == nil {
		apierror.InternalServerError("Module service not configured").WriteJSON(w)
		return
	}

	var req UpdateTenantModulesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	// Convert to domain types
	updates := make([]moduleTypes.TenantModuleUpdate, len(req.Modules))
	for i, m := range req.Modules {
		updates[i] = moduleTypes.TenantModuleUpdate{
			ModuleID:  m.ModuleID,
			IsEnabled: m.IsEnabled,
		}
	}

	actx := h.buildAuditContext(r)
	config, err := h.moduleService.UpdateTenantModules(r.Context(), tenantID.String(), updates, actx)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toTenantModuleListResponse(config))
}

// ResetTenantModules handles POST /api/v1/tenants/{tenant}/settings/modules/reset
func (h *TenantHandler) ResetTenantModules(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTeamID(r.Context())
	if tenantID.IsZero() {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}

	if h.moduleService == nil {
		apierror.InternalServerError("Module service not configured").WriteJSON(w)
		return
	}

	actx := h.buildAuditContext(r)
	config, err := h.moduleService.ResetTenantModules(r.Context(), tenantID.String(), actx)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toTenantModuleListResponse(config))
}

func toTenantModuleListResponse(config *app.TenantModuleConfigOutput) TenantModuleListResponse {
	modules := make([]TenantModuleResponse, 0, len(config.Modules))
	for _, info := range config.Modules {
		m := info.Module
		resp := TenantModuleResponse{
			ID:            m.ID(),
			Name:          m.Name(),
			Description:   m.Description(),
			Icon:          m.Icon(),
			Category:      m.Category(),
			DisplayOrder:  m.DisplayOrder(),
			IsCore:        m.IsCore(),
			IsEnabled:     info.IsEnabled,
			ReleaseStatus: string(m.ReleaseStatus()),
		}

		if len(info.SubModules) > 0 {
			resp.SubModules = make([]TenantSubModuleResponse, 0, len(info.SubModules))
			for _, sub := range info.SubModules {
				resp.SubModules = append(resp.SubModules, TenantSubModuleResponse{
					ID:            sub.Module.ID(),
					Name:          sub.Module.Name(),
					Description:   sub.Module.Description(),
					Icon:          sub.Module.Icon(),
					ReleaseStatus: string(sub.Module.ReleaseStatus()),
					IsEnabled:     sub.IsEnabled,
				})
			}
		}

		modules = append(modules, resp)
	}

	return TenantModuleListResponse{
		Modules: modules,
		Summary: TenantModuleSummaryResponse{
			Total:    config.Summary.Total,
			Enabled:  config.Summary.Enabled,
			Disabled: config.Summary.Disabled,
			Core:     config.Summary.Core,
		},
	}
}

// =============================================================================
// Asset Identity Settings Endpoints (RFC-001)
// =============================================================================

// GetAssetIdentitySettings handles GET /api/v1/tenants/{tenant}/settings/asset-identity
func (h *TenantHandler) GetAssetIdentitySettings(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTeamID(r.Context())
	if tenantID.IsZero() {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}

	settings, err := h.service.GetTenantSettings(r.Context(), tenantID.String())
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(settings.AssetIdentity)
}

// UpdateAssetIdentitySettings handles PATCH /api/v1/tenants/{tenant}/settings/asset-identity
func (h *TenantHandler) UpdateAssetIdentitySettings(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTeamID(r.Context())
	if tenantID.IsZero() {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}

	var req struct {
		StaleAssetDays int `json:"stale_asset_days"`
		MaxIPsPerAsset int `json:"max_ips_per_asset"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	// Validate bounds
	if req.StaleAssetDays < 0 || req.StaleAssetDays > 365 {
		apierror.BadRequest("stale_asset_days must be 0-365 (0 = system default)").WriteJSON(w)
		return
	}
	if req.MaxIPsPerAsset < 0 || req.MaxIPsPerAsset > 100 {
		apierror.BadRequest("max_ips_per_asset must be 0-100 (0 = system default)").WriteJSON(w)
		return
	}

	settings, err := h.service.GetTenantSettings(r.Context(), tenantID.String())
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	settings.AssetIdentity.StaleAssetDays = req.StaleAssetDays
	settings.AssetIdentity.MaxIPsPerAsset = req.MaxIPsPerAsset

	actx := h.buildAuditContext(r)
	updated, err := h.service.UpdateTenantSettings(r.Context(), tenantID.String(), *settings, actx)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(updated.AssetIdentity)
}
