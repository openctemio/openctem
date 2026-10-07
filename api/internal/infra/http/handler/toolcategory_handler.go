package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/openctemio/openctem/api/internal/app/tool"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/toolcategory"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// ToolCategoryHandler handles HTTP requests for tool categories.
type ToolCategoryHandler struct {
	service   *tool.CategoryService
	validator *validator.Validator
	logger    *logger.Logger
}

// NewToolCategoryHandler creates a new ToolCategoryHandler.
func NewToolCategoryHandler(service *tool.CategoryService, v *validator.Validator, log *logger.Logger) *ToolCategoryHandler {
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

// ToolCategoryListResponse is a page of tool categories.
type ToolCategoryListResponse struct {
	Items      []ToolCategoryResponse `json:"items"`
	Total      int64                  `json:"total"`
	Page       int                    `json:"page"`
	PerPage    int                    `json:"per_page"`
	TotalPages int                    `json:"total_pages"`
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

// ListCategories handles GET /api/v1/tool-categories
// @Summary      List tool categories
// @Description  Platform categories plus the organization's custom categories.
// @Tags         Tool Categories
// @Produce      json
// @Param        source    query     string  false  "platform or custom"  Enums(platform, custom)
// @Param        q         query     string  false  "Search the name and display name"
// @Param        page      query     int     false  "Page number" default(1)
// @Param        per_page  query     int     false  "Items per page (max 100)" default(20)
// @Success      200  {object}  ToolCategoryListResponse
// @Failure      400  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /tool-categories [get]
func (h *ToolCategoryHandler) ListCategories(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	result, err := h.service.ListCategories(r.Context(), tool.ListCategoriesInput{
		TenantID: middleware.GetTenantID(r.Context()),
		Source:   q.Get("source"),
		Search:   q.Get("q"),
		Page:     parseQueryInt(q.Get("page"), 1),
		PerPage:  parseQueryIntBounded(q.Get("per_page"), 20, 1, MaxPerPage),
	})
	if err != nil {
		h.handleError(w, err, "tool category")
		return
	}

	resp := ToolCategoryListResponse{
		Items:      make([]ToolCategoryResponse, 0, len(result.Data)),
		Total:      result.Total,
		Page:       result.Page,
		PerPage:    result.PerPage,
		TotalPages: result.TotalPages,
	}
	for _, tc := range result.Data {
		resp.Items = append(resp.Items, toToolCategoryResponse(tc))
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// GetCategory handles GET /api/v1/tool-categories/{id}
// @Summary      Get tool category
// @Description  A platform category or one of the organization's custom categories; any other id is not found.
// @Tags         Tool Categories
// @Produce      json
// @Param        id   path      string  true  "Category ID"
// @Success      200  {object}  ToolCategoryResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /tool-categories/{id} [get]
func (h *ToolCategoryHandler) GetCategory(w http.ResponseWriter, r *http.Request) {
	tc, err := h.service.GetCategory(r.Context(), middleware.GetTenantID(r.Context()), chi.URLParam(r, "id"))
	if err != nil {
		h.handleError(w, err, "tool category")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toToolCategoryResponse(tc))
}

// =============================================================================
// Tenant Custom Category Operations (Write)
// =============================================================================

// CreateCustomCategory handles POST /api/v1/tool-categories
// @Summary      Create custom tool category
// @Description  Create a custom category owned by the organization.
// @Tags         Tool Categories
// @Accept       json
// @Produce      json
// @Param        body  body      CreateToolCategoryRequest  true  "Category"
// @Success      201   {object}  ToolCategoryResponse
// @Failure      400   {object}  apierror.Error
// @Failure      409   {object}  apierror.Error
// @Failure      500   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /tool-categories [post]
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

	tc, err := h.service.CreateCategory(r.Context(), tool.CreateCategoryInput{
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

// UpdateCustomCategory handles PUT /api/v1/tool-categories/{id}
// @Summary      Update custom tool category
// @Description  Update one of the organization's custom categories. A platform category or another organization's is not found.
// @Tags         Tool Categories
// @Accept       json
// @Produce      json
// @Param        id    path      string                     true  "Category ID"
// @Param        body  body      UpdateToolCategoryRequest  true  "Category"
// @Success      200   {object}  ToolCategoryResponse
// @Failure      400   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Failure      500   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /tool-categories/{id} [put]
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

	tc, err := h.service.UpdateCategory(r.Context(), tool.UpdateCategoryInput{
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

// DeleteCustomCategory handles DELETE /api/v1/tool-categories/{id}
// @Summary      Delete custom tool category
// @Description  Delete one of the organization's custom categories (refused while a tool uses it). A platform category or another organization's is not found.
// @Tags         Tool Categories
// @Param        id   path      string  true  "Category ID"
// @Success      204  "No Content"
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /tool-categories/{id} [delete]
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
