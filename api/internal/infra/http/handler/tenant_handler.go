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

	"github.com/openctemio/openctem/api/internal/app"
	assetapp "github.com/openctemio/openctem/api/internal/app/asset"
	"github.com/openctemio/openctem/api/internal/app/module"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	moduleTypes "github.com/openctemio/openctem/api/pkg/domain/module"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// recalculateCooldown is the minimum interval between recalculations per tenant.
const recalculateCooldown = 5 * time.Minute

// recalculateLastRun tracks the last recalculation time per tenant ID.
var recalculateLastRun sync.Map

// TenantHandler handles tenant-related HTTP requests.
// Note: "Team" is the UI-facing name for tenants.
type TenantHandler struct {
	service         *tenantapp.TenantService
	roleService     *app.RoleService
	assetService    *assetapp.AssetService
	moduleService   *app.ModuleService
	lifecycleWorker *assetapp.AssetLifecycleWorker
	validator       *validator.Validator
	logger          *logger.Logger
	// selfServiceCreation allows POST /tenants (TENANT_CREATION_MODE=
	// self_service). Off by default: organizations are then created by the
	// platform administrator only.
	selfServiceCreation bool
	// provisioning creates accounts on behalf of organization administrators.
	// Nil disables POST /tenants/{tenant}/users.
	provisioning *tenantapp.UserProvisioningService
	// invalidateSecurityPolicy drops the IP-allowlist gate's cached policy for
	// an organization after its security settings change.
	invalidateSecurityPolicy func(tenantID string)
}

// SetUserProvisioning wires administrator-created accounts.
func (h *TenantHandler) SetUserProvisioning(svc *tenantapp.UserProvisioningService) {
	h.provisioning = svc
}

// SetSecurityPolicyInvalidator wires the IP-allowlist gate's cache invalidation.
func (h *TenantHandler) SetSecurityPolicyInvalidator(fn func(tenantID string)) {
	h.invalidateSecurityPolicy = fn
}

// SetSelfServiceTenantCreation lets signed-in users create organizations
// (TENANT_CREATION_MODE=self_service). Without it POST /tenants is refused.
func (h *TenantHandler) SetSelfServiceTenantCreation(enabled bool) {
	h.selfServiceCreation = enabled
}

// NewTenantHandler creates a new tenant handler.
func NewTenantHandler(svc *tenantapp.TenantService, v *validator.Validator, log *logger.Logger) *TenantHandler {
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
func (h *TenantHandler) SetAssetService(svc *assetapp.AssetService) {
	h.assetService = svc
}

// SetModuleService sets the module service for module management.
func (h *TenantHandler) SetModuleService(svc *app.ModuleService) {
	h.moduleService = svc
}

// SetAssetLifecycleWorker wires the lifecycle worker used by the
// POST /settings/asset-lifecycle/dry-run endpoint. Optional: when
// nil the dry-run endpoint returns 503.
func (h *TenantHandler) SetAssetLifecycleWorker(w *assetapp.AssetLifecycleWorker) {
	h.lifecycleWorker = w
}

// =============================================================================
// Response Types
// =============================================================================

// TenantResponse represents a tenant in API responses.
type TenantResponse struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Slug        string    `json:"slug"`
	Description string    `json:"description,omitempty"`
	LogoURL     string    `json:"logo_url,omitempty"`
	Plan        string    `json:"plan"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
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
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Role      string    `json:"role"`
	InvitedBy string    `json:"invited_by,omitempty"`
	JoinedAt  time.Time `json:"joined_at"`
	// Email and LastLoginAt are included only for owners and admins of the
	// tenant; other members get ids, names and avatars (enough for pickers).
	Email       string     `json:"email,omitempty"`
	Name        string     `json:"name"`
	AvatarURL   string     `json:"avatar_url,omitempty"`
	Status      string     `json:"status"`
	LastLoginAt *time.Time `json:"last_login_at,omitempty"`
	// MFAStatus ("enabled" | "disabled" | "idp") is included only for owners
	// and admins of the tenant.
	MFAStatus string `json:"mfa_status,omitempty"`
	// PendingSetup is true for an account an administrator created whose
	// owner has not set a password or signed in yet.
	PendingSetup bool `json:"pending_setup"`
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
	// ModulePresetID optionally binds a module preset at creation time.
	// Empty = no preset applied (every active catalog module is on by
	// default, i.e. ctem_full-equivalent — kept for backward compat).
	// Valid values match pkg/domain/module/presets.go (e.g.
	// "vm_essentials", "asset_inventory", "bug_bounty").
	ModulePresetID string `json:"module_preset_id,omitempty" validate:"omitempty,max=64"`
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
	// Any member can read this response, so it carries the profile only:
	// the security policy (IP allowlist, allowed domains), AI and risk
	// configuration are read through GET /settings by those allowed to.
	return TenantResponse{
		ID:          t.ID().String(),
		Name:        t.Name(),
		Slug:        t.Slug(),
		Description: t.Description(),
		LogoURL:     t.LogoURL(),
		Plan:        t.Plan().String(),
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

// InvitationListItem is a pending invitation in the list. It has no token:
// tokens are stored hashed, so the list could only return the hash, which is
// not a usable link. The raw token is returned once, by the create call.
type InvitationListItem struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Role      string    `json:"role"`
	RoleIDs   []string  `json:"role_ids"`
	InvitedBy string    `json:"invited_by"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
	Pending   bool      `json:"pending"`
}

// InvitationListResponse is the body of GET /tenants/{tenant}/invitations.
type InvitationListResponse struct {
	Data  []InvitationListItem `json:"data"`
	Total int                  `json:"total"`
}

func toInvitationListItem(inv *tenant.Invitation) InvitationListItem {
	r := toInvitationResponse(inv, false)
	return InvitationListItem{
		ID: r.ID, Email: r.Email, Role: r.Role, RoleIDs: r.RoleIDs, InvitedBy: r.InvitedBy,
		ExpiresAt: r.ExpiresAt, CreatedAt: r.CreatedAt, Pending: r.Pending,
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

// buildAuditContext builds an app.AuditContext from the HTTP request.
func (h *TenantHandler) buildAuditContext(r *http.Request) app.AuditContext {
	actx := app.AuditContext{
		ActorIP:   getClientIP(r),
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
	// Module toggle rejections carry a structured ToggleError so the
	// UI can render a dependency-aware confirmation dialog without
	// regex-ing the error message. Detect it BEFORE the generic
	// shared.ErrValidation branch collapses it into a string.
	var toggleErr *module.ToggleError
	if errors.As(err, &toggleErr) {
		writeToggleErrorJSON(w, toggleErr)
		return
	}
	var conflict *tenant.SettingsConflictError
	if errors.As(err, &conflict) {
		writeSettingsConflict(w, conflict)
		return
	}
	if errors.Is(err, tenant.ErrSettingsSectionCorrupt) {
		// The service already logged the tenant and section; the error text can
		// carry stored values, so it is not logged here.
		h.logger.Error("settings section unreadable")
		apierror.InternalServerError("These settings could not be read. Contact your platform administrator.").WriteJSON(w)
		return
	}
	switch {
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Tenant").WriteJSON(w)
	case errors.Is(err, shared.ErrAlreadyExists):
		apierror.Conflict("Tenant already exists").WriteJSON(w)
	case errors.Is(err, shared.ErrConflict):
		apierror.Conflict(err.Error()).WriteJSON(w)
	case errors.Is(err, shared.ErrForbidden):
		msg := err.Error()
		if idx := strings.Index(msg, ": "); idx != -1 {
			msg = msg[idx+2:]
		}
		apierror.Forbidden(msg).WriteJSON(w)
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

// writeToggleErrorJSON serialises a module.ToggleError as the 400
// body. The shape matches pkg/apierror's apierror.Error contract —
// UI's parseErrorResponse reads `code`, `message`, `details` — so
// blocker/required info is nested under `details` where the UI can
// consume it via err.details.blockers.
func writeToggleErrorJSON(w http.ResponseWriter, e *module.ToggleError) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"code":    "module_dependency_violation",
		"message": e.Error(),
		"details": map[string]any{
			"module_id":   e.ModuleID,
			"module_name": e.ModuleName,
			"action":      e.Action,
			"blockers":    e.Blockers,
			"required":    e.Required,
		},
	})
}

// =============================================================================
// Tenant Handlers
// =============================================================================

// Create handles POST /api/v1/tenants
func (h *TenantHandler) Create(w http.ResponseWriter, r *http.Request) {
	if !h.selfServiceCreation {
		apierror.Forbidden("Organizations are created by the application administrator").WriteJSON(w)
		return
	}
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
	// An unknown preset used to be accepted and silently ignored (the
	// organization got every module). Refuse it before anything is created.
	if req.ModulePresetID != "" && moduleTypes.FindPreset(req.ModulePresetID) == nil {
		apierror.BadRequest("Unknown module preset: " + req.ModulePresetID).WriteJSON(w)
		return
	}

	input := tenantapp.CreateTenantInput{
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

	// Apply the chosen module preset if one was picked during creation.
	// Failures are logged but do NOT abort the tenant creation — the
	// admin can always apply the preset later from Settings → Modules.
	// This keeps the onboarding flow resilient when a preset validation
	// hiccups on an unusual deployment.
	if req.ModulePresetID != "" && h.moduleService != nil {
		presetActx := actx
		presetActx.TenantID = t.ID().String()
		if _, presetErr := h.moduleService.ApplyPreset(r.Context(), t.ID().String(), req.ModulePresetID, presetActx); presetErr != nil {
			h.logger.Warn("failed to apply module preset during tenant creation",
				"tenant_id", t.ID().String(), "preset_id", req.ModulePresetID, "error", presetErr)
		}
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

	input := tenantapp.UpdateTenantInput{
		Name:        req.Name,
		Slug:        req.Slug,
		Description: req.Description,
		LogoURL:     req.LogoURL,
		// Renaming the slug is owner-only; the service compares it with the
		// stored slug, so admins saving name/description are unaffected.
		CallerIsOwner: middleware.GetTeamRole(r.Context()) == tenant.RoleOwner,
	}

	t, err := h.service.UpdateTenant(r.Context(), tenantID.String(), input, h.buildAuditContext(r))
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

	actx := h.buildAuditContext(r)
	if err := h.service.DeleteTenant(r.Context(), actx, tenantID.String()); err != nil {
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
//   - search: search term for name or email (requires include=user); name
//     only for callers who are not an owner or admin
//
// Member emails and last sign-in are owner/admin only (owner decision
// 2026-10-02): other members get ids, names, avatars and roles, which is what
// the assignee and owner pickers need.
//   - status: active | suspended (membership status); empty = any
//   - role: owner | admin | member | viewer (effective system role); empty = any
//   - limit: max results (default 100, max 100)
//   - offset: pagination offset
//   - status: active | suspended | offboarded | all. Default: active and
//     suspended (offboarded tombstones are left out, so pickers never offer
//     a person who left; pickers pass status=active to leave out disabled
//     members too).
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

	// Owners and admins see the member directory (emails, last sign-in,
	// second-factor status); everyone else sees names only.
	callerRole := middleware.GetTeamRole(r.Context())
	showDirectory := callerRole == tenant.RoleOwner || callerRole == tenant.RoleAdmin

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
	statusFilter := r.URL.Query().Get("status")
	switch statusFilter {
	case "", tenant.MemberFilterAll, string(tenant.MemberStatusActive),
		string(tenant.MemberStatusSuspended), string(tenant.MemberStatusOffboarded):
	default:
		apierror.BadRequest("status must be active, suspended, offboarded or all").WriteJSON(w)
		return
	}
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
			Search:         search,
			SearchNameOnly: !showDirectory,
			Limit:          limit,
			Offset:         offset,
			Status:         statusFilter,
			Role:           r.URL.Query().Get("role"),
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
				ID:           m.ID.String(),
				UserID:       m.UserID.String(),
				Role:         m.Role.String(),
				InvitedBy:    invitedBy,
				JoinedAt:     m.JoinedAt,
				Name:         m.Name,
				AvatarURL:    m.AvatarURL,
				Status:       m.Status,
				PendingSetup: m.PendingSetup,
			}
			if showDirectory {
				response[i].Email = m.Email
				response[i].LastLoginAt = m.LastLoginAt
				response[i].MFAStatus = m.MFAStatus
			}
		}

		// Fetch RBAC roles for all members if requested
		if includeRoles && h.roleService != nil {
			h.enrichMembersWithRoles(r.Context(), tenantID.String(), response)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data":   response,
			"total":  total,
			"limit":  limit,
			"offset": offset,
		})
		return
	}

	// Basic member list. Paginated like the include=user path: it used to
	// return every member of the organization in one response.
	result, err := h.service.SearchMembersWithUserInfo(r.Context(), tenantID.String(),
		tenant.MemberSearchFilters{Search: search, SearchNameOnly: !showDirectory, Limit: limit, Offset: offset, Status: statusFilter})
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	response := make([]MemberResponse, len(result.Members))
	for i, m := range result.Members {
		var invitedBy string
		if m.InvitedBy != nil {
			invitedBy = m.InvitedBy.String()
		}
		response[i] = MemberResponse{
			ID:        m.ID.String(),
			UserID:    m.UserID.String(),
			Role:      m.Role.String(),
			InvitedBy: invitedBy,
			JoinedAt:  m.JoinedAt,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"data":   response,
		"total":  result.Total,
		"limit":  limit,
		"offset": offset,
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

	input := tenantapp.AddMemberInput{
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

	input := tenantapp.UpdateMemberRoleInput{
		Role: req.Role,
	}

	actx := h.buildAuditContext(r)
	if actx.ActorID == "" {
		// The peer-administrator rule needs to know who is acting; an empty
		// actor means a system path in the service.
		apierror.Unauthorized("Authentication required").WriteJSON(w)
		return
	}
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
	if actx.ActorID == "" {
		// The peer-administrator rule needs to know who is acting; an empty
		// actor means a system path in the service.
		apierror.Unauthorized("Authentication required").WriteJSON(w)
		return
	}
	if err := h.service.RemoveMember(r.Context(), memberID, actx); err != nil {
		h.writeLifecycleError(w, err)
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
	if actx.ActorID == "" {
		// The peer-administrator rule needs to know who is acting; an empty
		// actor means a system path in the service.
		apierror.Unauthorized("Authentication required").WriteJSON(w)
		return
	}
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
	if actx.ActorID == "" {
		// The peer-administrator rule needs to know who is acting; an empty
		// actor means a system path in the service.
		apierror.Unauthorized("Authentication required").WriteJSON(w)
		return
	}
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
// @Summary List pending invitations
// @Description Pending invitations of the organization. No token: tokens are stored hashed and the raw token is returned only once, by the create call.
// @Tags Tenants
// @Produce json
// @Param tenant path string true "Tenant ID or slug"
// @Success 200 {object} InvitationListResponse
// @Failure 403 {object} apierror.Error
// @Security BearerAuth
// @Router /tenants/{tenant}/invitations [get]
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

	response := InvitationListResponse{Data: make([]InvitationListItem, len(invitations)), Total: len(invitations)}
	for i, inv := range invitations {
		response.Data[i] = toInvitationListItem(inv)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
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

	// Anti-escalation: an inviter may only grant roles whose permissions they
	// themselves hold. Otherwise an admin could invite a user with the system
	// owner/admin role bundle, escalating beyond their own ceiling on accept.
	if !h.canGrantRoles(w, r, req.RoleIDs, "cannot invite with a role whose permissions you do not hold") {
		return
	}

	// In simplified model, all invited users are "member"
	// Permissions come from RBAC roles (roleIDs)
	input := tenantapp.CreateInvitationInput{
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

// canGrantRoles enforces anti-escalation for invitations and administrator-
// created accounts: a caller who is not an organization admin may only grant
// roles whose permissions they hold. Writes the error response and returns
// false when refused.
func (h *TenantHandler) canGrantRoles(w http.ResponseWriter, r *http.Request, roleIDs []string, refusal string) bool {
	if middleware.IsAdmin(r.Context()) || h.roleService == nil {
		return true
	}
	// Resolve roles in the URL-path tenant (the one being administered), not the
	// JWT-claim tenant — these handlers all act on GetTeamID.
	teamID := middleware.GetTeamID(r.Context())
	if teamID.IsZero() {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return false
	}
	for _, rid := range roleIDs {
		role, rErr := h.roleService.GetRole(r.Context(), teamID.String(), rid)
		if rErr != nil {
			h.handleServiceError(w, rErr)
			return false
		}
		if e := assertCanGrantPermissions(r.Context(), role.Permissions()); e != nil {
			apierror.Forbidden(refusal).WriteJSON(w)
			return false
		}
	}
	return true
}

// CreateTenantUserRequest creates an account in the organization.
type CreateTenantUserRequest struct {
	Email   string   `json:"email" validate:"required,email,max=254"`
	Name    string   `json:"name" validate:"max=255"`
	RoleIDs []string `json:"role_ids" validate:"required,min=1,max=10"`
}

// ProvisionedUserInfo identifies the account in a ProvisionedUserResponse.
type ProvisionedUserInfo struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

// ProvisionedUserResponse is the result of creating an account or reissuing
// its set-password link. SetupToken is present only when the link was not
// emailed; it is shown once to the administrator and never stored in clear.
type ProvisionedUserResponse struct {
	User           ProvisionedUserInfo `json:"user"`
	MembershipID   string              `json:"membership_id,omitempty"`
	Role           string              `json:"role,omitempty"`
	EmailSent      bool                `json:"email_sent"`
	SetupToken     string              `json:"setup_token,omitempty"`
	SetupExpiresAt *time.Time          `json:"setup_expires_at,omitempty"`
	// EmailFailed: the organization can send email but the send failed, and
	// the link is deliberately not returned (platform administrator's
	// first-owner bootstrap). The person uses forgot-password.
	EmailFailed bool `json:"email_failed,omitempty"`
}

// toProvisionedUserResponse renders a ProvisionedUser for the API.
func toProvisionedUserResponse(p *tenantapp.ProvisionedUser) ProvisionedUserResponse {
	resp := ProvisionedUserResponse{
		User:        ProvisionedUserInfo{ID: p.User.ID().String(), Email: p.User.Email(), Name: p.User.Name()},
		EmailSent:   p.EmailSent,
		EmailFailed: p.EmailFailed,
	}
	if p.Membership != nil {
		resp.MembershipID = p.Membership.ID().String()
		resp.Role = p.Membership.Role().String()
	}
	// Report the role actually granted (e.g. "admin"), not the membership
	// label, which stays "member" for the admin RBAC role.
	if p.EffectiveRole != "" {
		resp.Role = p.EffectiveRole
	}
	if p.SetupToken != "" {
		exp := p.SetupExpiresAt
		resp.SetupToken = p.SetupToken
		resp.SetupExpiresAt = &exp
	}
	return resp
}

// writeProvisionedUser writes a response that may carry a one-time secret.
func writeProvisionedUser(w http.ResponseWriter, status int, p *tenantapp.ProvisionedUser) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(toProvisionedUserResponse(p))
}

// handleProvisioningError maps account-provisioning errors.
func (h *TenantHandler) handleProvisioningError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, tenantapp.ErrAccountExists):
		apierror.Conflict("An account with this email already exists. Invite them instead.").WriteJSON(w)
	case errors.Is(err, tenant.ErrPlatformAdminMembership):
		apierror.Conflict("Platform administrators cannot belong to an organization.").WriteJSON(w)
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("User").WriteJSON(w)
	case errors.Is(err, tenantapp.ErrSetupLinkForbidden):
		apierror.Forbidden("You cannot issue a set-password link for this account").WriteJSON(w)
	default:
		h.handleServiceError(w, err)
	}
}

// CreateUser handles POST /api/v1/tenants/{tenant}/users
// @Summary      Create a user in the organization
// @Description  Creates an account with the given RBAC roles and a one-time set-password link (24h, single use). The link is emailed when SMTP is configured; otherwise setup_token is returned once to the creating administrator. Owner/admin only. Refused with 409 when the email already has an account (invite instead) and 400 when the email domain is outside the organization's allowed domains.
// @Tags         Tenants
// @Accept       json
// @Produce      json
// @Param        tenant   path      string                   true  "Tenant ID or slug"
// @Param        request  body      CreateTenantUserRequest  true  "User"
// @Success      201  {object}  ProvisionedUserResponse
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /tenants/{tenant}/users [post]
func (h *TenantHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	if h.provisioning == nil {
		apierror.ServiceUnavailable("User creation is not available").WriteJSON(w)
		return
	}
	tenantID := middleware.GetTeamID(r.Context())
	if tenantID.IsZero() {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}
	creatorID := middleware.GetLocalUserID(r.Context())
	if creatorID.IsZero() {
		apierror.Unauthorized("Authentication required").WriteJSON(w)
		return
	}

	var req CreateTenantUserRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384)).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}
	if !h.canGrantRoles(w, r, req.RoleIDs, "cannot grant a role whose permissions you do not hold") {
		return
	}

	result, err := h.provisioning.CreateUser(r.Context(), tenantapp.CreateUserInput{
		TenantID:  tenantID.String(),
		Email:     req.Email,
		Name:      req.Name,
		RoleIDs:   req.RoleIDs,
		CreatedBy: creatorID,
	}, h.buildAuditContext(r))
	if err != nil {
		h.handleProvisioningError(w, err)
		return
	}
	writeProvisionedUser(w, http.StatusCreated, result)
}

// ReissueSetupLink handles POST /api/v1/tenants/{tenant}/users/{userId}/setup-link
// @Summary      Issue a new set-password link for a pending account
// @Description  Replaces the one-time set-password link of an account an administrator created that has never been used and belongs to this organization only. Owner/admin only; an owner or administrator account, or one holding a role the caller could not grant, needs an owner (403). 400 for any other account (its owner recovers it with forgot-password).
// @Tags         Tenants
// @Produce      json
// @Param        tenant  path  string  true  "Tenant ID or slug"
// @Param        userId  path  string  true  "User ID"
// @Success      200  {object}  ProvisionedUserResponse
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /tenants/{tenant}/users/{userId}/setup-link [post]
func (h *TenantHandler) ReissueSetupLink(w http.ResponseWriter, r *http.Request) {
	if h.provisioning == nil {
		apierror.ServiceUnavailable("User creation is not available").WriteJSON(w)
		return
	}
	tenantID := middleware.GetTeamID(r.Context())
	if tenantID.IsZero() {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}
	userID, err := shared.IDFromString(r.PathValue("userId"))
	if err != nil {
		apierror.BadRequest("Invalid user ID").WriteJSON(w)
		return
	}
	callerID := middleware.GetLocalUserID(r.Context())
	if callerID.IsZero() {
		apierror.Unauthorized("Authentication required").WriteJSON(w)
		return
	}
	result, err := h.provisioning.ReissueSetupLink(r.Context(), tenantID.String(), userID.String(), callerID.String(), h.buildAuditContext(r))
	if err != nil {
		h.handleProvisioningError(w, err)
		return
	}
	writeProvisionedUser(w, http.StatusOK, result)
}

// DeleteInvitation handles DELETE /api/v1/tenants/{tenant}/invitations/{invitationId}
func (h *TenantHandler) DeleteInvitation(w http.ResponseWriter, r *http.Request) {
	// The tenant MUST come from the URL path (GetTeamID), the same tenant
	// RequireTeamAdmin/RequireMembership authorized. Using the JWT-claim tenant
	// (MustGetTenantID) here was a confused-deputy IDOR: a user who is admin of
	// org B but only holds a token scoped to org A could delete org A's
	// invitation by POSTing to /tenants/B/... — the gate checked B, the
	// operation ran against A.
	tenantID := middleware.GetTeamID(r.Context())
	if tenantID.IsZero() {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}
	invitationID := r.PathValue("invitationId")
	if invitationID == "" {
		apierror.BadRequest("Invitation ID is required").WriteJSON(w)
		return
	}

	if err := h.service.DeleteInvitation(r.Context(), tenantID.String(), invitationID, h.buildAuditContext(r)); err != nil {
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
	// Tenant from the URL path (GetTeamID), the same tenant RequireTeamAdmin
	// authorized — not the JWT-claim tenant (confused-deputy IDOR; see
	// DeleteInvitation).
	tenantID := middleware.GetTeamID(r.Context())
	if tenantID.IsZero() {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}
	invitationID := r.PathValue("invitationId")
	if invitationID == "" {
		apierror.BadRequest("Invitation ID is required").WriteJSON(w)
		return
	}

	actx := h.buildAuditContext(r)
	if err := h.service.ResendInvitation(r.Context(), tenantID.String(), invitationID, actx); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"message": "Invitation email resent",
	})
}

// The invitation token is a bearer credential: whoever holds it can see the
// invitation, decline it, or (signed in as the invited email) accept it. The
// body routes below carry it in the request body (RFC-041, docs/rfcs/RFC-041-api-path-design.md):
// a URL path is written to access logs, metric labels, traces, the browser
// history and Referer headers. The /api/v1/invitations/{token}/... routes are
// deprecated aliases of these and share their handlers.

// InvitationTokenRequest is the body of the invitation routes that take the
// token: lookup, accept and decline.
type InvitationTokenRequest struct {
	Token string `json:"token" example:"Zm9vYmFyYmF6cXV4cXV1eGNvcmdlZ3JhdWx0Z2FycGx5d2FsZG8"`
}

// maxInvitationTokenBody bounds the body of the invitation routes (a token
// and, for accept-with-refresh, a refresh token).
const maxInvitationTokenBody = 8 << 10

// validInvitationToken reports whether t has the shape of an invitation token
// (32 random bytes, base64url: 43 characters), with room for older formats.
// Anything else is refused before it reaches the database.
func validInvitationToken(t string) bool {
	return len(t) >= 40 && len(t) <= 100 && !strings.ContainsRune(t, 0)
}

// decodeInvitationBody decodes an invitation route's JSON body into dst. On
// failure it writes the 400 and returns false.
func decodeInvitationBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	if r.Body == nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return false
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxInvitationTokenBody)).Decode(dst); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return false
	}
	return true
}

// invitationTokenFromBody reads {"token": ...}. On failure it writes the 400
// and returns false.
func invitationTokenFromBody(w http.ResponseWriter, r *http.Request) (string, bool) {
	var req InvitationTokenRequest
	if !decodeInvitationBody(w, r, &req) {
		return "", false
	}
	if !validInvitationToken(req.Token) {
		apierror.BadRequest("Invalid invitation token").WriteJSON(w)
		return "", false
	}
	return req.Token, true
}

// invitationTokenFromPath reads the token of a deprecated
// /api/v1/invitations/{token}/... route. On failure it writes the 400 and
// returns false.
func invitationTokenFromPath(w http.ResponseWriter, r *http.Request) (string, bool) {
	token := r.PathValue("token")
	if !validInvitationToken(token) {
		apierror.BadRequest("Invalid invitation token").WriteJSON(w)
		return "", false
	}
	return token, true
}

// GetInvitation handles GET /api/v1/invitations/{token} (deprecated; the
// successor is POST /api/v1/invitations/lookup).
func (h *TenantHandler) GetInvitation(w http.ResponseWriter, r *http.Request) {
	token, ok := invitationTokenFromPath(w, r)
	if !ok {
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

// InvitationLookupResponse is what an invitation token reveals before sign-in:
// enough to decide whether to join, and nothing else (no token, no tenant
// settings, never the inviter's email).
type InvitationLookupResponse struct {
	Invitation InvitationLookupInvitation `json:"invitation"`
	Tenant     InvitationLookupTenant     `json:"tenant"`
}

// InvitationLookupInvitation is the invitation part of InvitationLookupResponse.
type InvitationLookupInvitation struct {
	ID          string    `json:"id"`
	Email       string    `json:"email"`
	Role        string    `json:"role"`
	Pending     bool      `json:"pending"`
	ExpiresAt   time.Time `json:"expires_at"`
	InviterName string    `json:"inviter_name"`
}

// InvitationLookupTenant is the organization part of InvitationLookupResponse.
type InvitationLookupTenant struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Slug string `json:"slug"`
}

// LookupInvitation handles POST /api/v1/invitations/lookup (public).
// @Summary      Look up an invitation
// @Description  What an invitation token grants, readable before sign-in: the organization, the invited email and role, and whether it is still pending. The token travels in the body, never in the URL.
// @Tags         Invitations
// @Accept       json
// @Produce      json
// @Param        request  body      InvitationTokenRequest  true  "Invitation token"
// @Success      200  {object}  InvitationLookupResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      429  {object}  apierror.Error
// @Router       /invitations/lookup [post]
func (h *TenantHandler) LookupInvitation(w http.ResponseWriter, r *http.Request) {
	if token, ok := invitationTokenFromBody(w, r); ok {
		h.writeInvitationLookup(w, r, token)
	}
}

// GetInvitationPreview handles GET /api/v1/invitations/{token}/preview
// (public, deprecated; the successor is POST /api/v1/invitations/lookup).
func (h *TenantHandler) GetInvitationPreview(w http.ResponseWriter, r *http.Request) {
	if token, ok := invitationTokenFromPath(w, r); ok {
		h.writeInvitationLookup(w, r, token)
	}
}

// writeInvitationLookup answers a lookup: limited invitation info, without
// authentication, so the invited person sees what they are invited to before
// signing in.
func (h *TenantHandler) writeInvitationLookup(w http.ResponseWriter, r *http.Request, token string) {
	invitation, err := h.service.GetInvitationByToken(r.Context(), token)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	t, err := h.service.GetTenant(r.Context(), invitation.TenantID().String())
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(InvitationLookupResponse{
		Invitation: InvitationLookupInvitation{
			ID:          invitation.ID().String(),
			Email:       invitation.Email(),
			Role:        invitation.Role().String(),
			Pending:     invitation.IsPending(),
			ExpiresAt:   invitation.ExpiresAt(),
			InviterName: h.service.GetUserDisplayName(r.Context(), invitation.InvitedBy()),
		},
		Tenant: InvitationLookupTenant{ID: t.ID().String(), Name: t.Name(), Slug: t.Slug()},
	})
}

// AcceptInvitationToken handles POST /api/v1/invitations/accept.
// @Summary      Accept an invitation
// @Description  Joins the organization of the invitation. The caller must be signed in as the invited email. The token travels in the body, never in the URL.
// @Tags         Invitations
// @Accept       json
// @Produce      json
// @Param        request  body      InvitationTokenRequest  true  "Invitation token"
// @Success      200  {object}  MemberResponse
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      429  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /invitations/accept [post]
func (h *TenantHandler) AcceptInvitationToken(w http.ResponseWriter, r *http.Request) {
	if token, ok := invitationTokenFromBody(w, r); ok {
		h.acceptInvitation(w, r, token)
	}
}

// AcceptInvitation handles POST /api/v1/invitations/{token}/accept
// (deprecated; the successor is POST /api/v1/invitations/accept).
func (h *TenantHandler) AcceptInvitation(w http.ResponseWriter, r *http.Request) {
	if token, ok := invitationTokenFromPath(w, r); ok {
		h.acceptInvitation(w, r, token)
	}
}

func (h *TenantHandler) acceptInvitation(w http.ResponseWriter, r *http.Request, token string) {
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

// DeclineInvitationToken handles POST /api/v1/invitations/decline (public:
// holding the token is the authorization, like an unsubscribe link).
// @Summary      Decline an invitation
// @Description  Deletes the invitation. Holding the token is the authorization, so no sign-in is needed. The token travels in the body, never in the URL.
// @Tags         Invitations
// @Accept       json
// @Param        request  body      InvitationTokenRequest  true  "Invitation token"
// @Success      204
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      429  {object}  apierror.Error
// @Router       /invitations/decline [post]
func (h *TenantHandler) DeclineInvitationToken(w http.ResponseWriter, r *http.Request) {
	if token, ok := invitationTokenFromBody(w, r); ok {
		h.declineInvitation(w, r, token)
	}
}

// DeclineInvitation handles POST /api/v1/invitations/{token}/decline
// (public, deprecated; the successor is POST /api/v1/invitations/decline).
func (h *TenantHandler) DeclineInvitation(w http.ResponseWriter, r *http.Request) {
	if token, ok := invitationTokenFromPath(w, r); ok {
		h.declineInvitation(w, r, token)
	}
}

func (h *TenantHandler) declineInvitation(w http.ResponseWriter, r *http.Request, token string) {
	invitation, err := h.service.GetInvitationByToken(r.Context(), token)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// Delete the invitation (public decline: the token authorizes it; pass the
	// invitation's own tenant so the scoping check is satisfied).
	if err := h.service.DeleteInvitation(r.Context(), invitation.TenantID().String(), invitation.ID().String(), app.AuditContext{
		ActorIP: getClientIP(r), UserAgent: r.UserAgent(), RequestID: r.Header.Get("X-Request-ID"),
	}); err != nil {
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
	General GeneralSettingsResponse `json:"general"`
	// Security and RiskScoring are returned to owners and admins only
	// (absent for other roles): the IP allowlist, allowed domains and scoring
	// formula are reconnaissance material no member workflow needs.
	Security    *SecuritySettingsResponse   `json:"security,omitempty"`
	Branding    BrandingSettingsResponse    `json:"branding"`
	RiskScoring *tenant.RiskScoringSettings `json:"risk_scoring,omitempty"`
	Pentest     tenant.PentestSettings      `json:"pentest"`
	// ETags holds the entity tag of each settings section as stored (keys:
	// general, security, branding, risk_scoring, pentest, ...). Send the
	// section's tag as If-Match on its PATCH to get 409 SETTINGS_CONFLICT
	// instead of overwriting a change saved since you read it.
	ETags map[string]string `json:"etags,omitempty"`
}

// forRole drops the admin-only sections for callers who are not an owner or
// admin of the organization.
func (resp SettingsResponse) forRole(role tenant.Role) SettingsResponse {
	if role == tenant.RoleOwner || role == tenant.RoleAdmin {
		return resp
	}
	resp.Security = nil
	resp.RiskScoring = nil
	return resp
}

// withSettingsETags returns resp with its per-section ETags set.
func withSettingsETags(resp SettingsResponse, etags map[string]string) SettingsResponse {
	resp.ETags = etags
	return resp
}

// settingsWriteCtx carries the request's If-Match header (a settings-section
// ETag) to the service, which refuses the write with 409 when it is stale.
func settingsWriteCtx(r *http.Request) context.Context {
	return tenantapp.WithSettingsIfMatch(r.Context(), r.Header.Get("If-Match"))
}

// settingsETags returns the stored ETag of every settings section, or nil
// (logged) when it cannot be read; ETags are advisory for clients.
func (h *TenantHandler) settingsETags(ctx context.Context, tenantID shared.ID) map[string]string {
	etags, err := h.service.SectionETags(ctx, tenantID.String())
	if err != nil {
		h.logger.Warn("failed to compute settings ETags", "tenant_id", tenantID.String(), "error", err)
		return nil
	}
	return etags
}

// writeSectionETag sets the ETag response header to the stored tag of one
// settings section and returns every section's tag.
func (h *TenantHandler) writeSectionETag(w http.ResponseWriter, r *http.Request, tenantID shared.ID, section string) map[string]string {
	etags := h.settingsETags(r.Context(), tenantID)
	if tag := etags[section]; tag != "" {
		w.Header().Set("ETag", tag)
	}
	return etags
}

// writeSettingsConflict writes 409 SETTINGS_CONFLICT with the current
// (redacted) section and its ETag, so the client can show what changed.
func writeSettingsConflict(w http.ResponseWriter, e *tenant.SettingsConflictError) {
	current := tenant.RedactSettings(map[string]any{e.Section: e.Current})[e.Section]
	w.Header().Set("ETag", e.ETag)
	apierror.New(http.StatusConflict, "SETTINGS_CONFLICT", e.Error()).WithDetails(map[string]any{
		"section": e.Section,
		"etag":    e.ETag,
		"current": current,
	}).WriteJSON(w)
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
	// SSOEnforced is read-only here: set by the platform administrator.
	SSOEnforced           bool     `json:"sso_enforced"`
	MFARequired           bool     `json:"mfa_required"`
	SessionTimeoutMin     int      `json:"session_timeout_min"`
	IPWhitelist           []string `json:"ip_whitelist"`
	AllowedDomains        []string `json:"allowed_domains"`
	EmailVerificationMode string   `json:"email_verification_mode"`
	// RequireSensorLocalPolicyForPrivateTargets: jobs with private targets
	// go only to sensors that enforce a local policy (RFC-040 §5.7).
	RequireSensorLocalPolicyForPrivateTargets bool `json:"require_sensor_local_policy_for_private_targets"`
	// AllowSensorInteractsh / AllowSensorCustomTemplates: the platform sends
	// jobs with out-of-band callbacks / custom templates to sensors only when
	// on (research/25 D3; off by default).
	AllowSensorInteractsh      bool `json:"allow_sensor_interactsh"`
	AllowSensorCustomTemplates bool `json:"allow_sensor_custom_templates"`
	// CurrentIP is the caller's IP as the API sees it, the value the IP
	// allowlist is checked against (empty outside a request context).
	CurrentIP string `json:"current_ip,omitempty"`
}

// BrandingSettingsResponse represents branding settings.
type BrandingSettingsResponse struct {
	PrimaryColor string `json:"primary_color"`
	LogoDarkURL  string `json:"logo_dark_url,omitempty"`
	LogoData     string `json:"logo_data,omitempty"`
}

func toSettingsResponse(s *tenant.Settings) SettingsResponse {
	rs := s.RiskScoring

	return SettingsResponse{
		General: GeneralSettingsResponse{
			Timezone: s.General.Timezone,
			Language: s.General.Language,
			Industry: s.General.Industry,
			Website:  s.General.Website,
		},
		Security: &SecuritySettingsResponse{
			SSOEnforced:           s.Security.SSOEnforced,
			MFARequired:           s.Security.MFARequired,
			SessionTimeoutMin:     s.Security.SessionTimeoutMin,
			IPWhitelist:           s.Security.IPWhitelist,
			AllowedDomains:        s.Security.AllowedDomains,
			EmailVerificationMode: string(s.Security.EmailVerificationMode),
			RequireSensorLocalPolicyForPrivateTargets: s.Security.RequireSensorLocalPolicyForPrivateTargets,
			AllowSensorInteractsh:                     s.Security.AllowSensorInteractsh,
			AllowSensorCustomTemplates:                s.Security.AllowSensorCustomTemplates,
		},
		Branding: BrandingSettingsResponse{
			PrimaryColor: s.Branding.PrimaryColor,
			LogoDarkURL:  s.Branding.LogoDarkURL,
			LogoData:     s.Branding.LogoData,
		},
		RiskScoring: &rs,
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

	resp := withSettingsETags(toSettingsResponse(settings), h.settingsETags(r.Context(), tenantID)).
		forRole(middleware.GetTeamRole(r.Context()))
	if resp.Security != nil {
		resp.Security.CurrentIP = getClientIP(r)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// UpdateGeneralSettingsRequest represents the request to update general settings.
// Fields are pointers so a partial PATCH only touches the fields it sends —
// omitted fields are left untouched (not reset to empty).
type UpdateGeneralSettingsRequest struct {
	Timezone *string `json:"timezone"`
	Language *string `json:"language" validate:"omitempty,oneof=en vi ja ko zh"`
	Industry *string `json:"industry" validate:"omitempty,max=100"`
	// No `url` tag: with pointer fields omitempty does not skip a non-nil
	// pointer to "", so `url` would reject an explicit empty string (used to
	// clear the field). GeneralSettings.Validate enforces URL format when
	// the value is non-empty.
	Website *string `json:"website" validate:"omitempty,max=500"`
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

	input := tenantapp.UpdateGeneralSettingsInput{
		Timezone: req.Timezone,
		Language: req.Language,
		Industry: req.Industry,
		Website:  req.Website,
	}

	actx := h.buildAuditContext(r)
	settings, err := h.service.UpdateGeneralSettings(settingsWriteCtx(r), tenantID.String(), input, actx)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	etags := h.writeSectionETag(w, r, tenantID, tenant.SectionGeneral)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(withSettingsETags(toSettingsResponse(settings), etags))
}

// UpdateSecuritySettingsRequest represents the request to update security settings.
// Scalar fields are pointers so a partial PATCH only touches what it sends;
// slice fields keep their nil-vs-[] meaning (omitted => unchanged, [] => clear).
type UpdateSecuritySettingsRequest struct {
	// SSOEnforced is accepted only to refuse it explicitly: SSO enforcement is
	// set by the platform administrator per organization (RFC-022), and a
	// silently ignored field would look like it saved.
	SSOEnforced           *bool    `json:"sso_enforced"`
	MFARequired           *bool    `json:"mfa_required"`
	SessionTimeoutMin     *int     `json:"session_timeout_min" validate:"omitempty,min=15,max=480"`
	IPWhitelist           []string `json:"ip_whitelist"`
	AllowedDomains        []string `json:"allowed_domains"`
	EmailVerificationMode *string  `json:"email_verification_mode" validate:"omitempty,oneof=auto always never"`
	// RequireSensorLocalPolicyForPrivateTargets: see SecuritySettingsResponse.
	RequireSensorLocalPolicyForPrivateTargets *bool `json:"require_sensor_local_policy_for_private_targets"`
	// AllowSensorInteractsh / AllowSensorCustomTemplates: see
	// SecuritySettingsResponse. Turning one on is audited (critical) and
	// alerted.
	AllowSensorInteractsh      *bool `json:"allow_sensor_interactsh"`
	AllowSensorCustomTemplates *bool `json:"allow_sensor_custom_templates"`
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
	if req.SSOEnforced != nil {
		apierror.Forbidden("SSO enforcement is managed by the application administrator").WriteJSON(w)
		return
	}

	clientIP := getClientIP(r)
	input := tenantapp.UpdateSecuritySettingsInput{
		MFARequired:           req.MFARequired,
		SessionTimeoutMin:     req.SessionTimeoutMin,
		IPWhitelist:           req.IPWhitelist,
		AllowedDomains:        req.AllowedDomains,
		EmailVerificationMode: req.EmailVerificationMode,
		RequireSensorLocalPolicyForPrivateTargets: req.RequireSensorLocalPolicyForPrivateTargets,
		AllowSensorInteractsh:                     req.AllowSensorInteractsh,
		AllowSensorCustomTemplates:                req.AllowSensorCustomTemplates,
		// Lockout guard: the saved IP allowlist must include this IP.
		RequesterIP: clientIP,
	}

	actx := h.buildAuditContext(r)
	settings, err := h.service.UpdateSecuritySettings(settingsWriteCtx(r), tenantID.String(), input, actx)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	etags := h.writeSectionETag(w, r, tenantID, tenant.SectionSecurity)
	if h.invalidateSecurityPolicy != nil {
		h.invalidateSecurityPolicy(tenantID.String())
	}

	resp := withSettingsETags(toSettingsResponse(settings), etags)
	resp.Security.CurrentIP = clientIP // security PATCH is owner-only
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// UpdateBrandingSettingsRequest represents the request to update branding settings.
// Fields are pointers so a partial PATCH only touches what it sends — omitted
// fields (e.g. the logo when only the color changes) are left untouched.
type UpdateBrandingSettingsRequest struct {
	PrimaryColor *string `json:"primary_color"`
	// No `url` tag — see note on UpdateGeneralSettingsRequest.Website.
	// BrandingSettings.Validate checks the URL when non-empty.
	LogoDarkURL *string `json:"logo_dark_url"`
	LogoData    *string `json:"logo_data"` // Base64 encoded logo (max 150KB)
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

	input := tenantapp.UpdateBrandingSettingsInput{
		PrimaryColor: req.PrimaryColor,
		LogoDarkURL:  req.LogoDarkURL,
		LogoData:     req.LogoData,
	}

	actx := h.buildAuditContext(r)
	settings, err := h.service.UpdateBrandingSettings(settingsWriteCtx(r), tenantID.String(), input, actx)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	etags := h.writeSectionETag(w, r, tenantID, tenant.SectionBranding)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(withSettingsETags(toSettingsResponse(settings), etags))
}

// UpdateBranchSettingsRequest represents the request to update branch naming convention settings.
type UpdateBranchSettingsRequest struct {
	TypeRules []tenantapp.BranchTypeRuleInput `json:"type_rules" validate:"dive"`
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

	input := tenantapp.UpdateBranchSettingsInput{
		TypeRules: req.TypeRules,
	}

	actx := h.buildAuditContext(r)
	settings, err := h.service.UpdateBranchSettings(settingsWriteCtx(r), tenantID.String(), input, actx)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	etags := h.writeSectionETag(w, r, tenantID, tenant.SectionBranch)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(withSettingsETags(toSettingsResponse(settings), etags))
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
	h.writeSectionETag(w, r, tenantID, tenant.SectionPentest)

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

	input := tenantapp.UpdatePentestSettingsInput{
		CampaignTypes: req.CampaignTypes,
		Methodologies: req.Methodologies,
	}

	actx := h.buildAuditContext(r)
	settings, err := h.service.UpdatePentestSettings(settingsWriteCtx(r), tenantID.String(), input, actx)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	etags := h.writeSectionETag(w, r, tenantID, tenant.SectionPentest)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(withSettingsETags(toSettingsResponse(settings), etags))
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
	h.writeSectionETag(w, r, tenantID, tenant.SectionRiskScoring)

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
	settings, err := h.service.UpdateRiskScoringSettings(settingsWriteCtx(r), tenantID.String(), req, actx)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	h.writeSectionETag(w, r, tenantID, tenant.SectionRiskScoring)

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

// GetAssetSourceSettings handles GET /api/v1/tenants/{tenant}/settings/asset-source.
// Returns the tenant's current asset source priority + trust-level
// configuration (RFC-003 Phase 1a). Empty response means the feature
// is not enabled for this tenant — ingest falls back to today's
// last-write-wins merge.
func (h *TenantHandler) GetAssetSourceSettings(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTeamID(r.Context())
	if tenantID.IsZero() {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}

	as, err := h.service.GetAssetSourceSettings(r.Context(), tenantID.String())
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	h.writeSectionETag(w, r, tenantID, tenant.SectionAssetSource)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(as)
}

// UpdateAssetSourceSettings handles PUT /api/v1/tenants/{tenant}/settings/asset-source.
// Replaces the entire asset-source configuration. Pass an empty
// body (or empty priority + empty trust_levels) to disable the
// feature and restore default last-write-wins behavior.
func (h *TenantHandler) UpdateAssetSourceSettings(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTeamID(r.Context())
	if tenantID.IsZero() {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}

	// DisallowUnknownFields rejects payloads with typos like
	// "trust_level" (singular) or "priorities" — without it, such
	// mistakes would silently no-op and leave the admin confused
	// why their settings "didn't save".
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var req tenant.AssetSourceSettings
	if err := decoder.Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	// Structural validation runs in the domain layer via
	// UpdateAssetSourceSettings. We still do it here so bad
	// requests come back as 400 rather than being translated by
	// handleServiceError.
	if err := req.Validate(); err != nil {
		apierror.BadRequest(err.Error()).WriteJSON(w)
		return
	}

	actx := h.buildAuditContext(r)
	settings, err := h.service.UpdateAssetSourceSettings(settingsWriteCtx(r), tenantID.String(), req, actx)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	h.writeSectionETag(w, r, tenantID, tenant.SectionAssetSource)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(settings.AssetSource)
}

// GetRetestSettings handles GET /api/v1/organization/settings/retest.
// @Summary      Get auto-retest settings
// @Description  The tenant's auto-retest settings (RFC-039). auto_enabled is false until an admin turns it on; zero interval/cap mean the defaults (24 h, 200 per day).
// @Tags         Tenants
// @Produce      json
// @Success      200     {object}  tenant.RetestSettings
// @Failure      400     {object}  apierror.Error
// @Failure      403     {object}  apierror.Error
// @Security     BearerAuth
// @Router       /organization/settings/retest [get]
func (h *TenantHandler) GetRetestSettings(w http.ResponseWriter, r *http.Request) {
	tenantID, err := shared.IDFromString(middleware.GetTenantID(r.Context()))
	if err != nil || tenantID.IsZero() {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}
	rs, err := h.service.GetRetestSettings(r.Context(), tenantID.String())
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	h.writeSectionETag(w, r, tenantID, tenant.SectionRetest)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(rs)
}

// UpdateRetestSettings handles PUT /api/v1/organization/settings/retest.
// @Summary      Update auto-retest settings
// @Description  Turns auto-retest on or off and sets its interval (6–168 h) and daily cap (1–2000). Audited.
// @Tags         Tenants
// @Accept       json
// @Produce      json
// @Param        body    body      tenant.RetestSettings  true  "Auto-retest settings"
// @Success      200     {object}  tenant.RetestSettings
// @Failure      400     {object}  apierror.Error
// @Failure      403     {object}  apierror.Error
// @Security     BearerAuth
// @Router       /organization/settings/retest [put]
func (h *TenantHandler) UpdateRetestSettings(w http.ResponseWriter, r *http.Request) {
	tenantID, err := shared.IDFromString(middleware.GetTenantID(r.Context()))
	if err != nil || tenantID.IsZero() {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var req tenant.RetestSettings
	if err := decoder.Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	if err := req.Validate(); err != nil {
		apierror.BadRequest(err.Error()).WriteJSON(w)
		return
	}
	rs, err := h.service.UpdateRetestSettings(settingsWriteCtx(r), tenantID.String(), req, h.buildAuditContext(r))
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	h.writeSectionETag(w, r, tenantID, tenant.SectionRetest)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(rs)
}

// GetAssetLifecycleSettings handles
// GET /api/v1/tenants/{tenant}/settings/asset-lifecycle.
// Returns the zero-value struct when nothing has been configured so
// the UI can render defaults without a special "not configured"
// code-path.
func (h *TenantHandler) GetAssetLifecycleSettings(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTeamID(r.Context())
	if tenantID.IsZero() {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}

	al, err := h.service.GetAssetLifecycleSettings(r.Context(), tenantID.String())
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	h.writeSectionETag(w, r, tenantID, tenant.SectionAssetLifecycle)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(al)
}

// UpdateAssetLifecycleSettings handles
// PUT /api/v1/tenants/{tenant}/settings/asset-lifecycle.
//
// DisallowUnknownFields rejects body typos — otherwise an admin who
// writes "stale_threshold_day" (singular) would see the request
// succeed with their value silently ignored.
func (h *TenantHandler) UpdateAssetLifecycleSettings(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTeamID(r.Context())
	if tenantID.IsZero() {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var req tenant.AssetLifecycleSettings
	if err := decoder.Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	if err := req.Validate(); err != nil {
		apierror.BadRequest(err.Error()).WriteJSON(w)
		return
	}

	actx := h.buildAuditContext(r)
	settings, err := h.service.UpdateAssetLifecycleSettings(settingsWriteCtx(r), tenantID.String(), req, actx)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	h.writeSectionETag(w, r, tenantID, tenant.SectionAssetLifecycle)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(settings.AssetLifecycle)
}

// DryRunAssetLifecycle handles
// POST /api/v1/tenants/{tenant}/settings/asset-lifecycle/dry-run.
//
// Returns the LifecycleRunReport without writing. On success the
// service stamps DryRunCompletedAt so the next PUT with Enabled=true
// passes validation. An enable-without-dry-run attempt returns 400
// from the domain validator.
func (h *TenantHandler) DryRunAssetLifecycle(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTeamID(r.Context())
	if tenantID.IsZero() {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}
	if h.lifecycleWorker == nil {
		apierror.ServiceUnavailable("Asset lifecycle worker is not configured").WriteJSON(w)
		return
	}

	report, err := h.lifecycleWorker.Run(r.Context(), tenantID, true)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	if err := h.service.StampAssetLifecycleDryRunCompleted(r.Context(), tenantID.String()); err != nil {
		// Non-fatal: dry-run data is still useful even if we can't
		// stamp the timestamp. Log and return the report.
		h.logger.Warn("failed to stamp dry-run completion; ignoring",
			"tenant_id", tenantID.String(),
			"error", err,
		)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(report)
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

	config := assetapp.MapTenantToAssetScoringConfig(&req)
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
		lastTime, ok := lastRun.(time.Time)
		if !ok {
			recalculateLastRun.Delete(tenantKey)
			lastTime = time.Time{}
		}
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
	Modules []TenantModuleResponse      `json:"modules"`
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

	// ETag based on module-config version. Same module state across
	// tenant admins → same ETag → 304s on repeat fetches. Mutations
	// bump the version via ModuleService.notifyModuleChange.
	modVersion := h.moduleService.GetTenantModuleVersion(r.Context(), tenantID.String())
	// Include tenant prefix in etag — see bootstrap_handler comment.
	tidStr := tenantID.String()
	if len(tidStr) > 8 {
		tidStr = tidStr[:8]
	}
	etag := fmt.Sprintf(`"t%s-m%d"`, tidStr, modVersion)
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "private, max-age=300")
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
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

// ValidateTenantModuleToggle handles POST /settings/modules/validate —
// dry-run of the toggle validation. Returns structured blockers +
// warnings + required so the UI can render a confirmation modal
// BEFORE the tenant admin commits the toggle. No state change.
func (h *TenantHandler) ValidateTenantModuleToggle(w http.ResponseWriter, r *http.Request) {
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

	updates := make([]moduleTypes.TenantModuleUpdate, len(req.Modules))
	for i, m := range req.Modules {
		updates[i] = moduleTypes.TenantModuleUpdate{
			ModuleID:  m.ModuleID,
			IsEnabled: m.IsEnabled,
		}
	}

	result, err := h.moduleService.ValidateToggle(r.Context(), tenantID.String(), updates)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

// GetModuleDependencyGraph handles GET /api/v1/modules/graph.
// Returns the platform-wide module dependency graph (static, loaded from
// pkg/domain/module/dependency.go). The UI consumes this to render the
// Settings → Modules page with dependency badges and to surface
// "disabling X will also affect Y, Z" confirmation dialogs.
func (h *TenantHandler) GetModuleDependencyGraph(w http.ResponseWriter, r *http.Request) {
	if h.moduleService == nil {
		apierror.InternalServerError("Module service not configured").WriteJSON(w)
		return
	}
	graph := h.moduleService.GetDependencyGraph(r.Context())
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(graph)
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

// ListModulePresets handles GET /api/v1/tenants/{tenant}/settings/modules/presets.
// Returns the static preset catalog so the UI can render the picker.
// Does NOT require tenant context for reads, but gated behind
// RequireTeamAdmin so the pricing/persona copy isn't exposed to
// unauthenticated probes.
func (h *TenantHandler) ListModulePresets(w http.ResponseWriter, r *http.Request) {
	if h.moduleService == nil {
		apierror.InternalServerError("Module service not configured").WriteJSON(w)
		return
	}
	presets := h.moduleService.ListModulePresets(r.Context())
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"presets": presets})
}

type subscribeBundlesRequest struct {
	BundleIDs []string `json:"bundle_ids"`
}

// GetModuleBundles returns the tenant's current bundle subscription plus the
// available bundle catalog. Empty subscription = the tenant runs every module.
func (h *TenantHandler) GetModuleBundles(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTeamID(r.Context())
	if tenantID.IsZero() {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}
	if h.moduleService == nil {
		apierror.InternalServerError("Module service not configured").WriteJSON(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"subscribed": h.moduleService.GetSubscribedBundles(r.Context(), tenantID.String()),
		"available":  h.moduleService.ListModulePresets(r.Context()),
	})
}

// SubscribeModuleBundles replaces the tenant's bundle subscription. An empty
// list clears it (every module on). The enabled-module set is then resolved live
// from the chosen bundles; per-module overrides still apply on top.
func (h *TenantHandler) SubscribeModuleBundles(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTeamID(r.Context())
	if tenantID.IsZero() {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}
	if h.moduleService == nil {
		apierror.InternalServerError("Module service not configured").WriteJSON(w)
		return
	}
	var req subscribeBundlesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	actx := h.buildAuditContext(r)
	if err := h.moduleService.SubscribeBundles(r.Context(), tenantID.String(), req.BundleIDs, actx); err != nil {
		h.handleServiceError(w, err)
		return
	}
	// Return the fresh module config so the UI can refresh in one round trip.
	config, err := h.moduleService.GetTenantModuleConfig(r.Context(), tenantID.String())
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(config)
}

// PreviewModulePreset handles POST /.../settings/modules/presets/{presetId}/preview.
// Dry-run — returns what would change if the preset were applied.
func (h *TenantHandler) PreviewModulePreset(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTeamID(r.Context())
	if tenantID.IsZero() {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}
	if h.moduleService == nil {
		apierror.InternalServerError("Module service not configured").WriteJSON(w)
		return
	}
	presetID := r.PathValue("presetId")
	if presetID == "" {
		apierror.BadRequest("preset id is required").WriteJSON(w)
		return
	}

	diff, err := h.moduleService.PreviewPreset(r.Context(), tenantID.String(), presetID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(diff)
}

// ApplyModulePreset handles POST /.../settings/modules/presets/{presetId}/apply.
// Writes the preset into tenant_modules via UpdateTenantModules (same
// validation and audit as manual toggles).
func (h *TenantHandler) ApplyModulePreset(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTeamID(r.Context())
	if tenantID.IsZero() {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}
	if h.moduleService == nil {
		apierror.InternalServerError("Module service not configured").WriteJSON(w)
		return
	}
	presetID := r.PathValue("presetId")
	if presetID == "" {
		apierror.BadRequest("preset id is required").WriteJSON(w)
		return
	}

	actx := h.buildAuditContext(r)
	config, err := h.moduleService.ApplyPreset(r.Context(), tenantID.String(), presetID, actx)
	if err != nil {
		// Dependency-violation errors get the same structured JSON body
		// as manual UpdateTenantModules so the UI can reuse its handler.
		var toggleErr *module.ToggleError
		if errors.As(err, &toggleErr) {
			writeToggleErrorJSON(w, toggleErr)
			return
		}
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
	h.writeSectionETag(w, r, tenantID, tenant.SectionAssetIdentity)

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

	actx := h.buildAuditContext(r)
	updated, err := h.service.UpdateAssetIdentitySettings(settingsWriteCtx(r), tenantID.String(), tenant.AssetIdentitySettings{
		StaleAssetDays: req.StaleAssetDays,
		MaxIPsPerAsset: req.MaxIPsPerAsset,
	}, actx)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	h.writeSectionETag(w, r, tenantID, tenant.SectionAssetIdentity)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(updated.AssetIdentity)
}
