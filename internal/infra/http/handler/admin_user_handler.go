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

// AdminCreateResponse includes the API key (only shown on creation).
type AdminCreateResponse struct {
	Admin  AdminResponse `json:"admin"`
	APIKey string        `json:"api_key"`
}

// AdminRotateKeyResponse includes the new API key.
type AdminRotateKeyResponse struct {
	APIKey string `json:"api_key"`
}

// =============================================================================
// Request Types
// =============================================================================

// CreateAdminRequest represents the request to create an admin.
type CreateAdminRequest struct {
	Email string `json:"email"`
	Name  string `json:"name"`
	Role  string `json:"role"`
}

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

// Create creates a new admin user.
// POST /api/v1/admin/admins
func (h *AdminUserHandler) Create(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get current admin (for created_by)
	currentAdmin := middleware.MustGetAdminUser(ctx)

	// RBAC Check: Only super_admin can create admins
	if currentAdmin.Role() != admin.AdminRoleSuperAdmin {
		apierror.Forbidden("only super admins can create other admins").WriteJSON(w)
		return
	}

	var req CreateAdminRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}

	// Validate request
	if req.Email == "" {
		apierror.BadRequest("email is required").WriteJSON(w)
		return
	}
	if req.Role == "" {
		req.Role = string(admin.RoleViewer)
	}

	// Check if email already exists
	existing, err := h.repo.GetByEmail(ctx, req.Email)
	if err == nil && existing != nil {
		apierror.Conflict("admin with this email already exists").WriteJSON(w)
		return
	}

	// Create admin user
	name := req.Name
	if name == "" {
		// Derive name from email
		name = admin.DeriveNameFromEmail(req.Email)
	}

	createdByID := currentAdmin.ID()
	adminUser, rawKey, err := admin.NewAdminUser(
		req.Email,
		name,
		admin.AdminRole(req.Role),
		&createdByID,
	)
	if err != nil {
		h.logger.Error("failed to create admin entity", "error", err)
		apierror.BadRequest(err.Error()).WriteJSON(w)
		return
	}

	// Save to database
	if err := h.repo.Create(ctx, adminUser); err != nil {
		if admin.IsAdminAlreadyExists(err) {
			apierror.Conflict("admin already exists").WriteJSON(w)
			return
		}
		h.logger.Error("failed to save admin", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	h.logger.Info("admin created",
		"admin_id", adminUser.ID().String(),
		"email", adminUser.Email(),
		"role", adminUser.Role(),
		"created_by", currentAdmin.Email())

	response := AdminCreateResponse{
		Admin:  toAdminResponse(adminUser),
		APIKey: rawKey,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(response)
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

	// RBAC Check: Only super_admin can update other admins
	if id != currentAdmin.ID() && currentAdmin.Role() != admin.AdminRoleSuperAdmin {
		apierror.Forbidden("only super admins can update other admins").WriteJSON(w)
		return
	}

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

	// Prevent self-deletion
	if id == currentAdmin.ID() {
		apierror.BadRequest("cannot delete yourself").WriteJSON(w)
		return
	}

	// RBAC Check: Only super_admin can delete admins
	if currentAdmin.Role() != admin.AdminRoleSuperAdmin {
		apierror.Forbidden("only super admins can delete admins").WriteJSON(w)
		return
	}

	// RBAC Check: Only super_admin can delete admins
	if currentAdmin.Role() != admin.AdminRoleSuperAdmin {
		apierror.Forbidden("only super admins can delete admins").WriteJSON(w)
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

// RotateKey rotates an admin's API key.
// POST /api/v1/admin/admins/{id}/rotate-key
func (h *AdminUserHandler) RotateKey(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := chi.URLParam(r, "id")
	currentAdmin := middleware.MustGetAdminUser(ctx)

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

	// Rotate the API key - generates new key internally
	newKey, err := adminUser.RotateAPIKey()
	if err != nil {
		h.logger.Error("failed to rotate API key", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	// RBAC Check: Only super_admin can rotate keys for others
	if id != currentAdmin.ID() && currentAdmin.Role() != admin.AdminRoleSuperAdmin {
		apierror.Forbidden("only super admins can rotate other admins' keys").WriteJSON(w)
		return
	}

	// Save changes
	if err := h.repo.Update(ctx, adminUser); err != nil {
		h.logger.Error("failed to save admin after key rotation", "error", err, "id", idStr)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	h.logger.Info("admin API key rotated",
		"admin_id", adminUser.ID().String(),
		"rotated_by", currentAdmin.Email())

	response := AdminRotateKeyResponse{
		APIKey: newKey,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
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
