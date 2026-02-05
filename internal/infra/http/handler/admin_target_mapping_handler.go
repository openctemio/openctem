// Package handler provides HTTP handlers for the API server.
// This file implements admin target mapping management endpoints.
package handler

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/internal/infra/postgres"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/admin"
	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/tool"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// AdminTargetMappingHandler handles admin target mapping management endpoints.
type AdminTargetMappingHandler struct {
	repo   *postgres.TargetMappingRepository
	logger *logger.Logger
}

// NewAdminTargetMappingHandler creates a new AdminTargetMappingHandler.
func NewAdminTargetMappingHandler(repo *postgres.TargetMappingRepository, log *logger.Logger) *AdminTargetMappingHandler {
	return &AdminTargetMappingHandler{
		repo:   repo,
		logger: log.With("handler", "admin_target_mapping"),
	}
}

// =============================================================================
// Response Types
// =============================================================================

// TargetMappingResponse represents a target mapping in API responses.
type TargetMappingResponse struct {
	ID          string  `json:"id"`
	TargetType  string  `json:"target_type"`
	AssetType   string  `json:"asset_type"`
	Priority    int     `json:"priority"`
	IsActive    bool    `json:"is_active"`
	IsPrimary   bool    `json:"is_primary"`            // Derived from priority == 10
	Description *string `json:"description,omitempty"` // Optional description
	CreatedBy   *string `json:"created_by,omitempty"`
	CreatedAt   string  `json:"created_at"`
	UpdatedAt   string  `json:"updated_at"`
}

// TargetMappingListResponse represents a paginated list of target mappings.
type TargetMappingListResponse struct {
	Data       []TargetMappingResponse `json:"data"`
	Total      int64                   `json:"total"`
	Page       int                     `json:"page"`
	PerPage    int                     `json:"per_page"`
	TotalPages int                     `json:"total_pages"`
}

// TargetMappingStatsResponse represents aggregated stats for target mappings.
type TargetMappingStatsResponse struct {
	Total         int64            `json:"total"`
	ByTargetType  map[string]int64 `json:"by_target_type"`
	ByAssetType   map[string]int64 `json:"by_asset_type"`
	ActiveCount   int64            `json:"active_count"`
	InactiveCount int64            `json:"inactive_count"`
}

// =============================================================================
// Request Types
// =============================================================================

// CreateTargetMappingRequest represents the request to create a target mapping.
type CreateTargetMappingRequest struct {
	TargetType  string  `json:"target_type"`
	AssetType   string  `json:"asset_type"`
	Priority    *int    `json:"priority,omitempty"`
	IsPrimary   *bool   `json:"is_primary,omitempty"` // Convenience: sets priority to 10 if true
	IsActive    *bool   `json:"is_active,omitempty"`
	Description *string `json:"description,omitempty"`
}

// UpdateTargetMappingRequest represents the request to update a target mapping.
type UpdateTargetMappingRequest struct {
	Priority    *int    `json:"priority,omitempty"`
	IsPrimary   *bool   `json:"is_primary,omitempty"` // Convenience: sets priority to 10 if true
	IsActive    *bool   `json:"is_active,omitempty"`
	Description *string `json:"description,omitempty"`
}

// =============================================================================
// Handlers
// =============================================================================

// List lists all target mappings.
// GET /api/v1/admin/target-mappings
func (h *AdminTargetMappingHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse pagination
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if perPage < 1 || perPage > 100 {
		perPage = 50
	}

	// Parse filters
	filter := tool.TargetMappingFilter{}
	if targetType := r.URL.Query().Get("target_type"); targetType != "" {
		filter.TargetType = &targetType
	}
	if assetType := r.URL.Query().Get("asset_type"); assetType != "" {
		filter.AssetType = &assetType
	}
	if activeStr := r.URL.Query().Get("is_active"); activeStr != "" {
		isActive := activeStr == "true" || activeStr == "1"
		filter.IsActive = &isActive
	}

	// Fetch target mappings
	result, err := h.repo.List(ctx, filter, pagination.Pagination{Page: page, PerPage: perPage})
	if err != nil {
		h.logger.Error("failed to list target mappings", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	// Build response
	mappings := make([]TargetMappingResponse, 0, len(result.Data))
	for _, m := range result.Data {
		mappings = append(mappings, toTargetMappingResponse(m))
	}

	response := TargetMappingListResponse{
		Data:       mappings,
		Total:      result.Total,
		Page:       result.Page,
		PerPage:    result.PerPage,
		TotalPages: result.TotalPages,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

// Get retrieves a single target mapping.
// GET /api/v1/admin/target-mappings/{id}
func (h *AdminTargetMappingHandler) Get(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := chi.URLParam(r, "id")

	id, err := shared.IDFromString(idStr)
	if err != nil {
		apierror.BadRequest("invalid target mapping id").WriteJSON(w)
		return
	}

	mapping, err := h.repo.GetByID(ctx, id)
	if err != nil {
		h.logger.Error("failed to get target mapping", "error", err, "id", idStr)
		apierror.InternalError(err).WriteJSON(w)
		return
	}
	if mapping == nil {
		apierror.NotFound("TargetMapping").WriteJSON(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toTargetMappingResponse(mapping))
}

// Create creates a new target mapping.
// POST /api/v1/admin/target-mappings
func (h *AdminTargetMappingHandler) Create(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get current admin (for created_by)
	currentAdmin := middleware.MustGetAdminUser(ctx)

	// RBAC Check: Only super_admin and ops_admin can create mappings
	if currentAdmin.Role() != admin.AdminRoleSuperAdmin && currentAdmin.Role() != admin.AdminRoleOpsAdmin {
		apierror.Forbidden("only super admins and ops admins can create target mappings").WriteJSON(w)
		return
	}

	var req CreateTargetMappingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}

	// Validate required fields
	if req.TargetType == "" {
		apierror.BadRequest("target_type is required").WriteJSON(w)
		return
	}
	if req.AssetType == "" {
		apierror.BadRequest("asset_type is required").WriteJSON(w)
		return
	}

	// Validate target type
	if !tool.IsValidTargetType(req.TargetType) {
		apierror.BadRequest("invalid target_type: " + req.TargetType).WriteJSON(w)
		return
	}

	// Validate asset type
	assetType := asset.AssetType(req.AssetType)
	if !assetType.IsValid() {
		apierror.BadRequest("invalid asset_type: " + req.AssetType).WriteJSON(w)
		return
	}

	// Create mapping
	mapping := tool.NewTargetAssetTypeMapping(req.TargetType, asset.AssetType(req.AssetType))
	adminID := currentAdmin.ID()
	mapping.CreatedBy = &adminID

	// Apply optional fields
	// IsPrimary takes precedence over Priority if both are set
	if req.IsPrimary != nil {
		mapping.SetPrimary(*req.IsPrimary)
	} else if req.Priority != nil {
		mapping.Priority = *req.Priority
	}
	if req.IsActive != nil {
		mapping.IsActive = *req.IsActive
	}
	if req.Description != nil {
		mapping.Description = *req.Description
	}

	// Save to database
	if err := h.repo.Create(ctx, mapping); err != nil {
		h.logger.Error("failed to create target mapping", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	h.logger.Info("target mapping created",
		"mapping_id", mapping.ID.String(),
		"target_type", mapping.TargetType,
		"asset_type", string(mapping.AssetType),
		"created_by", currentAdmin.Email())

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(toTargetMappingResponse(mapping))
}

// Update updates a target mapping.
// PATCH /api/v1/admin/target-mappings/{id}
func (h *AdminTargetMappingHandler) Update(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := chi.URLParam(r, "id")
	currentAdmin := middleware.MustGetAdminUser(ctx)

	// RBAC Check: Only super_admin and ops_admin can update mappings
	if currentAdmin.Role() != admin.AdminRoleSuperAdmin && currentAdmin.Role() != admin.AdminRoleOpsAdmin {
		apierror.Forbidden("only super admins and ops admins can update target mappings").WriteJSON(w)
		return
	}

	id, err := shared.IDFromString(idStr)
	if err != nil {
		apierror.BadRequest("invalid target mapping id").WriteJSON(w)
		return
	}

	mapping, err := h.repo.GetByID(ctx, id)
	if err != nil {
		h.logger.Error("failed to get target mapping", "error", err, "id", idStr)
		apierror.InternalError(err).WriteJSON(w)
		return
	}
	if mapping == nil {
		apierror.NotFound("TargetMapping").WriteJSON(w)
		return
	}

	var req UpdateTargetMappingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}

	// Apply updates
	// IsPrimary takes precedence over Priority if both are set
	if req.IsPrimary != nil {
		mapping.SetPrimary(*req.IsPrimary)
	} else if req.Priority != nil {
		mapping.Priority = *req.Priority
	}
	if req.IsActive != nil {
		mapping.IsActive = *req.IsActive
	}
	if req.Description != nil {
		mapping.Description = *req.Description
	}
	mapping.UpdatedAt = time.Now().UTC()

	// Save changes
	if err := h.repo.Update(ctx, mapping); err != nil {
		h.logger.Error("failed to update target mapping", "error", err, "id", idStr)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	h.logger.Info("target mapping updated",
		"mapping_id", mapping.ID.String(),
		"updated_by", currentAdmin.Email())

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toTargetMappingResponse(mapping))
}

// Delete deletes a target mapping.
// DELETE /api/v1/admin/target-mappings/{id}
func (h *AdminTargetMappingHandler) Delete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := chi.URLParam(r, "id")
	currentAdmin := middleware.MustGetAdminUser(ctx)

	// RBAC Check: Only super_admin can delete mappings
	if currentAdmin.Role() != admin.AdminRoleSuperAdmin {
		apierror.Forbidden("only super admins can delete target mappings").WriteJSON(w)
		return
	}

	id, err := shared.IDFromString(idStr)
	if err != nil {
		apierror.BadRequest("invalid target mapping id").WriteJSON(w)
		return
	}

	// Verify mapping exists
	mapping, err := h.repo.GetByID(ctx, id)
	if err != nil {
		h.logger.Error("failed to get target mapping", "error", err, "id", idStr)
		apierror.InternalError(err).WriteJSON(w)
		return
	}
	if mapping == nil {
		apierror.NotFound("TargetMapping").WriteJSON(w)
		return
	}

	if err := h.repo.Delete(ctx, id); err != nil {
		h.logger.Error("failed to delete target mapping", "error", err, "id", idStr)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	h.logger.Info("target mapping deleted",
		"mapping_id", idStr,
		"deleted_by", currentAdmin.Email())

	w.WriteHeader(http.StatusNoContent)
}

// GetStats returns aggregated statistics for target mappings.
// GET /api/v1/admin/target-mappings/stats
func (h *AdminTargetMappingHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Fetch all mappings (no pagination for stats)
	result, err := h.repo.List(ctx, tool.TargetMappingFilter{}, pagination.Pagination{Page: 1, PerPage: 1000})
	if err != nil {
		h.logger.Error("failed to list target mappings for stats", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	// Calculate stats
	byTargetType := make(map[string]int64)
	byAssetType := make(map[string]int64)
	var activeCount, inactiveCount int64

	for _, m := range result.Data {
		byTargetType[m.TargetType]++
		byAssetType[string(m.AssetType)]++
		if m.IsActive {
			activeCount++
		} else {
			inactiveCount++
		}
	}

	response := TargetMappingStatsResponse{
		Total:         result.Total,
		ByTargetType:  byTargetType,
		ByAssetType:   byAssetType,
		ActiveCount:   activeCount,
		InactiveCount: inactiveCount,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

// =============================================================================
// Helpers
// =============================================================================

func toTargetMappingResponse(m *tool.TargetAssetTypeMapping) TargetMappingResponse {
	resp := TargetMappingResponse{
		ID:         m.ID.String(),
		TargetType: m.TargetType,
		AssetType:  string(m.AssetType),
		Priority:   m.Priority,
		IsActive:   m.IsActive,
		IsPrimary:  m.IsPrimary(),
		CreatedAt:  m.CreatedAt.Format(time.RFC3339),
		UpdatedAt:  m.UpdatedAt.Format(time.RFC3339),
	}

	if m.Description != "" {
		resp.Description = &m.Description
	}

	if m.CreatedBy != nil {
		s := m.CreatedBy.String()
		resp.CreatedBy = &s
	}

	return resp
}
