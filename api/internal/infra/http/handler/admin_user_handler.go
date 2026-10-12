// Package handler provides HTTP handlers for the API server.
// This file implements admin user management endpoints.
package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// AdminUserHandler handles admin user management endpoints.
type AdminUserHandler struct {
	repo   *postgres.AdminRepository
	logger *logger.Logger
}

// NewAdminUserHandler creates a new AdminUserHandler.
func NewAdminUserHandler(repo *postgres.AdminRepository, log *logger.Logger) *AdminUserHandler {
	return &AdminUserHandler{
		repo:   repo,
		logger: log.With("handler", "admin_user"),
	}
}

// =============================================================================
// Response Types
// =============================================================================

// AdminResponse represents an admin user in API responses.
type AdminResponse struct {
	ID         string  `json:"id"`
	Email      string  `json:"email"`
	Name       string  `json:"name"`
	Role       string  `json:"role"`
	IsActive   bool    `json:"is_active"`
	LastUsedAt *string `json:"last_used_at,omitempty"`
	LastUsedIP string  `json:"last_used_ip,omitempty"`
	CreatedAt  string  `json:"created_at"`
	UpdatedAt  string  `json:"updated_at"`

	// Break-glass (emergency access) and platform IdP state (RFC-022 rev. 4).
	IsBreakGlass           bool    `json:"is_break_glass"`
	BreakGlassTestedAt     *string `json:"break_glass_tested_at,omitempty"`
	BreakGlassTestOverdue  bool    `json:"break_glass_test_overdue"`
	PasswordChangeRequired bool    `json:"password_change_required"`
	IdPBound               bool    `json:"idp_bound"`
	IdPBoundAt             *string `json:"idp_bound_at,omitempty"`
}

// AdminListResponse represents a paginated list of admins.
type AdminListResponse struct {
	Data       []AdminResponse `json:"data"`
	Total      int64           `json:"total"`
	Page       int             `json:"page"`
	PerPage    int             `json:"per_page"`
	TotalPages int             `json:"total_pages"`
}

// =============================================================================
// Request Types
// =============================================================================

// UpdateAdminRequest represents the request to update an admin.
type UpdateAdminRequest struct {
	Name     *string `json:"name,omitempty"`
	Role     *string `json:"role,omitempty"`
	IsActive *bool   `json:"is_active,omitempty"`
	// IsBreakGlass marks or unmarks an emergency-access administrator.
	IsBreakGlass *bool `json:"is_break_glass,omitempty"`
}

// =============================================================================
// Handlers
// =============================================================================

// List lists all admin users.
// GET /api/v1/admin/admins
func (h *AdminUserHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse pagination
	paging, ok := listPage(w, r, 20)
	if !ok {
		return
	}
	page, perPage := paging.Page, paging.PerPage

	// Parse filters
	filter := admin.Filter{
		Email:  r.URL.Query().Get("email"),
		Search: r.URL.Query().Get("search"),
	}
	if roleStr := r.URL.Query().Get("role"); roleStr != "" {
		role := admin.AdminRole(roleStr)
		filter.Role = &role
	}
	if activeStr := r.URL.Query().Get("is_active"); activeStr != "" {
		isActive := activeStr == queryParamTrue || activeStr == "1"
		filter.IsActive = &isActive
	}

	// Fetch admins
	result, err := h.repo.List(ctx, filter, pagination.Pagination{Page: page, PerPage: perPage})
	if err != nil {
		h.logger.Error("failed to list admins", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	// Build response
	admins := make([]AdminResponse, 0, len(result.Data))
	for _, a := range result.Data {
		admins = append(admins, toAdminResponse(a))
	}

	response := AdminListResponse{
		Data:       admins,
		Total:      result.Total,
		Page:       result.Page,
		PerPage:    result.PerPage,
		TotalPages: result.TotalPages,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

// Get retrieves a single admin user.
// GET /api/v1/admin/admins/{id}
func (h *AdminUserHandler) Get(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := chi.URLParam(r, "id")

	id, err := shared.IDFromString(idStr)
	if err != nil {
		apierror.BadRequest("invalid admin id").WriteJSON(w)
		return
	}

	adminUser, err := h.repo.GetByID(ctx, id)
	if err != nil {
		if admin.IsAdminNotFound(err) {
			apierror.NotFound("Admin").WriteJSON(w)
			return
		}
		h.logger.Error("failed to get admin", "error", err, "id", idStr)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toAdminResponse(adminUser))
}

// Update updates an admin user.
// PATCH /api/v1/admin/admins/{id}
func (h *AdminUserHandler) Update(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := chi.URLParam(r, "id")
	currentAdmin := middleware.MustGetAdminUser(ctx)

	id, err := shared.IDFromString(idStr)
	if err != nil {
		apierror.BadRequest("invalid admin id").WriteJSON(w)
		return
	}

	// Role gating is enforced at the route layer (super_admin only).

	var req UpdateAdminRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}

	// No self-deactivation or self-role-change. Together with the ban on
	// deleting yourself, the super admin making a change always remains an
	// active super admin, so the platform can never be left without one.
	if id == currentAdmin.ID() {
		if req.IsActive != nil && !*req.IsActive {
			apierror.BadRequest("cannot deactivate yourself").WriteJSON(w)
			return
		}
		if req.Role != nil && admin.AdminRole(*req.Role) != currentAdmin.Role() {
			apierror.BadRequest("cannot change your own role").WriteJSON(w)
			return
		}
		if req.IsBreakGlass != nil && *req.IsBreakGlass != currentAdmin.IsBreakGlass() {
			apierror.BadRequest("cannot change your own break-glass marker").WriteJSON(w)
			return
		}
	}

	adminUser, err := h.repo.GetByID(ctx, id)
	if err != nil {
		if admin.IsAdminNotFound(err) {
			apierror.NotFound("Admin").WriteJSON(w)
			return
		}
		h.logger.Error("failed to get admin", "error", err, "id", idStr)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	// Apply updates
	if req.Name != nil {
		if err := adminUser.UpdateName(*req.Name); err != nil {
			apierror.BadRequest(err.Error()).WriteJSON(w)
			return
		}
	}
	if req.Role != nil {
		if err := adminUser.UpdateRole(admin.AdminRole(*req.Role)); err != nil {
			apierror.BadRequest(err.Error()).WriteJSON(w)
			return
		}
	}
	if req.IsActive != nil {
		if *req.IsActive {
			adminUser.Activate()
		} else {
			adminUser.Deactivate()
		}
	}
	if req.IsBreakGlass != nil {
		if *req.IsBreakGlass && adminUser.Role() != admin.AdminRoleSuperAdmin {
			apierror.BadRequest("a break-glass administrator must be a super admin").WriteJSON(w)
			return
		}
		if err := adminUser.SetBreakGlass(*req.IsBreakGlass); err != nil {
			apierror.Conflict("This administrator is bound to the identity provider; remove the binding first.").WriteJSON(w)
			return
		}
	}

	// Save changes. The roster guard refuses a change that would leave no
	// active local super admin (a break-glass one while the IdP is required).
	if err := h.repo.GuardedUpdate(ctx, adminUser); err != nil {
		writeAdminRosterError(w, h.logger, err, "update")
		return
	}

	h.logger.Info("admin updated",
		"admin_id", adminUser.ID().String(),
		"updated_by", currentAdmin.Email())

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toAdminResponse(adminUser))
}

// Delete deletes an admin user.
// DELETE /api/v1/admin/admins/{id}
func (h *AdminUserHandler) Delete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := chi.URLParam(r, "id")
	currentAdmin := middleware.MustGetAdminUser(ctx)

	id, err := shared.IDFromString(idStr)
	if err != nil {
		apierror.BadRequest("invalid admin id").WriteJSON(w)
		return
	}

	// Prevent self-deletion. Role gating (super_admin only) is enforced at
	// the route layer.
	if id == currentAdmin.ID() {
		apierror.BadRequest("cannot delete yourself").WriteJSON(w)
		return
	}

	if err := h.repo.GuardedDelete(ctx, id); err != nil {
		writeAdminRosterError(w, h.logger, err, "delete")
		return
	}

	h.logger.Info("admin deleted",
		"admin_id", logger.SanitizeValue(idStr),
		"deleted_by", currentAdmin.Email())

	w.WriteHeader(http.StatusNoContent)
}

// =============================================================================
// Helpers
// =============================================================================

func toAdminResponse(a *admin.AdminUser) AdminResponse {
	resp := AdminResponse{
		ID:        a.ID().String(),
		Email:     a.Email(),
		Name:      a.Name(),
		Role:      string(a.Role()),
		IsActive:  a.IsActive(),
		CreatedAt: a.CreatedAt().Format("2006-01-02T15:04:05Z"),
		UpdatedAt: a.UpdatedAt().Format("2006-01-02T15:04:05Z"),
	}

	if a.LastUsedAt() != nil {
		t := a.LastUsedAt().Format("2006-01-02T15:04:05Z")
		resp.LastUsedAt = &t
	}
	if a.LastUsedIP() != "" {
		resp.LastUsedIP = a.LastUsedIP()
	}
	st := a.SignInState()
	resp.IsBreakGlass = st.BreakGlass
	resp.BreakGlassTestOverdue = a.BreakGlassTestOverdue(time.Now())
	resp.PasswordChangeRequired = st.PasswordChangeRequired
	resp.IdPBound = st.IdPSubject != ""
	if st.BreakGlassTestedAt != nil {
		t := st.BreakGlassTestedAt.UTC().Format(time.RFC3339)
		resp.BreakGlassTestedAt = &t
	}
	if st.IdPBoundAt != nil {
		t := st.IdPBoundAt.UTC().Format(time.RFC3339)
		resp.IdPBoundAt = &t
	}

	return resp
}

// writeAdminRosterError maps roster-change errors to responses.
func writeAdminRosterError(w http.ResponseWriter, log *logger.Logger, err error, op string) {
	switch {
	case admin.IsAdminNotFound(err):
		apierror.NotFound("Admin").WriteJSON(w)
	case errors.Is(err, admin.ErrLastLocalAdmin):
		apierror.Conflict("At least one active local super admin must remain (a break-glass super admin while the identity provider is required).").WriteJSON(w)
	case errors.Is(err, admin.ErrBreakGlassBound):
		apierror.Conflict("This administrator is bound to the identity provider; remove the binding first.").WriteJSON(w)
	default:
		log.Error("admin roster change failed", "op", op, "error", err)
		apierror.InternalError(err).WriteJSON(w)
	}
}
