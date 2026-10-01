// Package handler provides HTTP handlers for the API server.
// This file implements admin user management endpoints.
package handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/internal/infra/postgres"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/admin"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
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
}

// =============================================================================
// Handlers
// =============================================================================

// List lists all admin users.
// GET /api/v1/admin/admins
func (h *AdminUserHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse pagination
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if perPage < 1 || perPage > 100 {
		perPage = 20
	}

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

	// Prevent self-deactivation
	if id == currentAdmin.ID() {
		var req UpdateAdminRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
			if req.IsActive != nil && !*req.IsActive {
				apierror.BadRequest("cannot deactivate yourself").WriteJSON(w)
				return
			}
		}
		// Re-read body for actual processing
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
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

	var req UpdateAdminRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
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

	// Save changes
	if err := h.repo.Update(ctx, adminUser); err != nil {
		h.logger.Error("failed to update admin", "error", err, "id", idStr)
		apierror.InternalError(err).WriteJSON(w)
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

	if err := h.repo.Delete(ctx, id); err != nil {
		if admin.IsAdminNotFound(err) {
			apierror.NotFound("Admin").WriteJSON(w)
			return
		}
		h.logger.Error("failed to delete admin", "error", err, "id", idStr)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	h.logger.Info("admin deleted",
		"admin_id", idStr,
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

	return resp
}
