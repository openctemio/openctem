package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/toolcategory"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/validator"
)

// ToolCategoryHandler handles HTTP requests for tool categories.
type ToolCategoryHandler struct {
	service   *app.ToolCategoryService
	validator *validator.Validator
	logger    *logger.Logger
}

// NewToolCategoryHandler creates a new ToolCategoryHandler.
func NewToolCategoryHandler(service *app.ToolCategoryService, v *validator.Validator, log *logger.Logger) *ToolCategoryHandler {
	return &ToolCategoryHandler{
		service:   service,
		validator: v,
		logger:    log.With("handler", "toolcategory"),
	}
}

// =============================================================================
// Request/Response Types
// =============================================================================

// CreateToolCategoryRequest represents the request body for creating a category.
type CreateToolCategoryRequest struct {
	Name        string `json:"name" validate:"required,min=2,max=50"`
	DisplayName string `json:"display_name" validate:"required,max=100"`
	Description string `json:"description" validate:"max=500"`
	Icon        string `json:"icon" validate:"max=50"`
	Color       string `json:"color" validate:"max=20"`
}

// UpdateToolCategoryRequest represents the request body for updating a category.
type UpdateToolCategoryRequest struct {
	DisplayName string `json:"display_name" validate:"required,max=100"`
	Description string `json:"description" validate:"max=500"`
	Icon        string `json:"icon" validate:"max=50"`
	Color       string `json:"color" validate:"max=20"`
}

// ToolCategoryResponse represents the response for a tool category.
type ToolCategoryResponse struct {
	ID          string  `json:"id"`
	TenantID    *string `json:"tenant_id,omitempty"`
	Name        string  `json:"name"`
	DisplayName string  `json:"display_name"`
	Description string  `json:"description,omitempty"`
	Icon        string  `json:"icon"`
	Color       string  `json:"color"`
	IsBuiltin   bool    `json:"is_builtin"`
	SortOrder   int     `json:"sort_order"`
	CreatedBy   *string `json:"created_by,omitempty"`
	CreatedAt   string  `json:"created_at"`
	UpdatedAt   string  `json:"updated_at"`
}

// toToolCategoryResponse converts a domain category to a response.
func toToolCategoryResponse(tc *toolcategory.ToolCategory) ToolCategoryResponse {
	resp := ToolCategoryResponse{
		ID:          tc.ID.String(),
		Name:        tc.Name,
		DisplayName: tc.DisplayName,
		Description: tc.Description,
		Icon:        tc.Icon,
		Color:       tc.Color,
		IsBuiltin:   tc.IsBuiltin,
		SortOrder:   tc.SortOrder,
		CreatedAt:   tc.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:   tc.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}

	if tc.TenantID != nil {
		tid := tc.TenantID.String()
		resp.TenantID = &tid
	}

	if tc.CreatedBy != nil {
		cid := tc.CreatedBy.String()
		resp.CreatedBy = &cid
	}

	return resp
}

// =============================================================================
// List Operations (Read)
// =============================================================================

// ListCategories lists all tool categories (platform + tenant custom).
// GET /api/v1/tool-categories
func (h *ToolCategoryHandler) ListCategories(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())

	page := parseQueryInt(r.URL.Query().Get("page"), 1)
	perPage := parseQueryInt(r.URL.Query().Get("per_page"), 20)
	search := r.URL.Query().Get("search")

	var isBuiltin *bool
	if b := r.URL.Query().Get("is_builtin"); b != "" {
		val := b == queryParamTrue
		isBuiltin = &val
	}

	result, err := h.service.ListCategories(r.Context(), app.ListCategoriesInput{
		TenantID:  tenantID,
		IsBuiltin: isBuiltin,
		Search:    search,
		Page:      page,
		PerPage:   perPage,
	})
	if err != nil {
		h.handleError(w, err, "tool category")
		return
	}

	// Convert to response
	items := make([]ToolCategoryResponse, 0, len(result.Data))
	for _, tc := range result.Data {
		items = append(items, toToolCategoryResponse(tc))
	}

	resp := map[string]any{
		"items":    items,
		"total":    result.Total,
		"page":     result.Page,
		"per_page": result.PerPage,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// ListAllCategories lists all categories for dropdowns (no pagination).
// GET /api/v1/tool-categories/all
func (h *ToolCategoryHandler) ListAllCategories(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())

	categories, err := h.service.ListAllCategories(r.Context(), tenantID)
	if err != nil {
		h.handleError(w, err, "tool category")
		return
	}

	items := make([]ToolCategoryResponse, 0, len(categories))
	for _, tc := range categories {
		items = append(items, toToolCategoryResponse(tc))
	}

	resp := map[string]any{
		"items": items,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// GetCategory returns a category by ID.
// GET /api/v1/tool-categories/:id
func (h *ToolCategoryHandler) GetCategory(w http.ResponseWriter, r *http.Request) {
	categoryID := chi.URLParam(r, "id")

	tc, err := h.service.GetCategory(r.Context(), categoryID)
	if err != nil {
		h.handleError(w, err, "tool category")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toToolCategoryResponse(tc))
}

// =============================================================================
// Tenant Custom Category Operations (Write)
// =============================================================================

// CreateCustomCategory creates a new tenant custom category.
// POST /api/v1/custom-tool-categories
func (h *ToolCategoryHandler) CreateCustomCategory(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())

	var req CreateToolCategoryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		apierror.BadRequest(err.Error()).WriteJSON(w)
		return
	}

	tc, err := h.service.CreateCategory(r.Context(), app.CreateCategoryInput{
		TenantID:    tenantID,
		CreatedBy:   userID,
		Name:        req.Name,
		DisplayName: req.DisplayName,
		Description: req.Description,
		Icon:        req.Icon,
		Color:       req.Color,
	})
	if err != nil {
		h.handleError(w, err, "tool category")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(toToolCategoryResponse(tc))
}

// UpdateCustomCategory updates a tenant custom category.
// PUT /api/v1/custom-tool-categories/:id
func (h *ToolCategoryHandler) UpdateCustomCategory(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())
	categoryID := chi.URLParam(r, "id")

	var req UpdateToolCategoryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		apierror.BadRequest(err.Error()).WriteJSON(w)
		return
	}

	tc, err := h.service.UpdateCategory(r.Context(), app.UpdateCategoryInput{
		TenantID:    tenantID,
		ID:          categoryID,
		DisplayName: req.DisplayName,
		Description: req.Description,
		Icon:        req.Icon,
		Color:       req.Color,
	})
	if err != nil {
		h.handleError(w, err, "tool category")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toToolCategoryResponse(tc))
}

// DeleteCustomCategory deletes a tenant custom category.
// DELETE /api/v1/custom-tool-categories/:id
func (h *ToolCategoryHandler) DeleteCustomCategory(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())
	categoryID := chi.URLParam(r, "id")

	if err := h.service.DeleteCategory(r.Context(), tenantID, categoryID); err != nil {
		h.handleError(w, err, "tool category")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// =============================================================================
// Error Handling
// =============================================================================

func (h *ToolCategoryHandler) handleError(w http.ResponseWriter, err error, resource string) {
	switch {
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound(resource).WriteJSON(w)
	case errors.Is(err, shared.ErrConflict):
		apierror.Conflict(err.Error()).WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	case errors.Is(err, shared.ErrForbidden):
		apierror.Forbidden(err.Error()).WriteJSON(w)
	default:
		h.logger.Error("unexpected error", "error", err)
		apierror.InternalError(err).WriteJSON(w)
	}
}
