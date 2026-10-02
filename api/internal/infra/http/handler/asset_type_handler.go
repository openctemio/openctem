package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/assettype"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
	"github.com/openctemio/api/pkg/validator"
)

// AssetTypeHandler handles asset type-related HTTP requests.
// Asset types are read-only system configuration.
type AssetTypeHandler struct {
	service   *app.AssetTypeService
	validator *validator.Validator
	logger    *logger.Logger
}

// NewAssetTypeHandler creates a new asset type handler.
func NewAssetTypeHandler(svc *app.AssetTypeService, v *validator.Validator, log *logger.Logger) *AssetTypeHandler {
	return &AssetTypeHandler{
		service:   svc,
		validator: v,
		logger:    log,
	}
}

// CategoryResponse represents a category in API responses.
type CategoryResponse struct {
	ID           string    `json:"id"`
	Code         string    `json:"code"`
	Name         string    `json:"name"`
	Description  string    `json:"description,omitempty"`
	Icon         string    `json:"icon,omitempty"`
	DisplayOrder int       `json:"display_order"`
	IsActive     bool      `json:"is_active"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// AssetTypeResponse represents an asset type in API responses.
type AssetTypeResponse struct {
	ID                 string            `json:"id"`
	CategoryID         string            `json:"category_id,omitempty"`
	Category           *CategoryResponse `json:"category,omitempty"`
	Code               string            `json:"code"`
	Name               string            `json:"name"`
	Description        string            `json:"description,omitempty"`
	Icon               string            `json:"icon,omitempty"`
	Color              string            `json:"color,omitempty"`
	DisplayOrder       int               `json:"display_order"`
	PatternRegex       string            `json:"pattern_regex,omitempty"`
	PatternPlaceholder string            `json:"pattern_placeholder,omitempty"`
	PatternExample     string            `json:"pattern_example,omitempty"`
	SupportsWildcard   bool              `json:"supports_wildcard"`
	SupportsCIDR       bool              `json:"supports_cidr"`
	IsDiscoverable     bool              `json:"is_discoverable"`
	IsScannable        bool              `json:"is_scannable"`
	IsSystem           bool              `json:"is_system"`
	IsActive           bool              `json:"is_active"`
	CreatedAt          time.Time         `json:"created_at"`
	UpdatedAt          time.Time         `json:"updated_at"`
}

// toCategoryResponse converts a domain category to API response.
func toCategoryResponse(c *assettype.Category) CategoryResponse {
	return CategoryResponse{
		ID:           c.ID().String(),
		Code:         c.Code(),
		Name:         c.Name(),
		Description:  c.Description(),
		Icon:         c.Icon(),
		DisplayOrder: c.DisplayOrder(),
		IsActive:     c.IsActive(),
		CreatedAt:    c.CreatedAt(),
		UpdatedAt:    c.UpdatedAt(),
	}
}

// toAssetTypeResponse converts a domain asset type to API response.
func toAssetTypeResponse(at *assettype.AssetType) AssetTypeResponse {
	resp := AssetTypeResponse{
		ID:                 at.ID().String(),
		Code:               at.Code(),
		Name:               at.Name(),
		Description:        at.Description(),
		Icon:               at.Icon(),
		Color:              at.Color(),
		DisplayOrder:       at.DisplayOrder(),
		PatternRegex:       at.PatternRegex(),
		PatternPlaceholder: at.PatternPlaceholder(),
		PatternExample:     at.PatternExample(),
		SupportsWildcard:   at.SupportsWildcard(),
		SupportsCIDR:       at.SupportsCIDR(),
		IsDiscoverable:     at.IsDiscoverable(),
		IsScannable:        at.IsScannable(),
		IsSystem:           at.IsSystem(),
		IsActive:           at.IsActive(),
		CreatedAt:          at.CreatedAt(),
		UpdatedAt:          at.UpdatedAt(),
	}

	if at.CategoryID() != nil {
		resp.CategoryID = at.CategoryID().String()
	}

	return resp
}

// toAssetTypeWithCategoryResponse converts a domain asset type with category to API response.
func toAssetTypeWithCategoryResponse(atc *assettype.AssetTypeWithCategory) AssetTypeResponse {
	resp := toAssetTypeResponse(atc.AssetType)
	if atc.Category != nil {
		cat := toCategoryResponse(atc.Category)
		resp.Category = &cat
	}
	return resp
}

// handleServiceError converts service errors to API errors.
func (h *AssetTypeHandler) handleServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, assettype.ErrAssetTypeNotFound):
		apierror.NotFound("Asset Type").WriteJSON(w)
	case errors.Is(err, assettype.ErrCategoryNotFound):
		apierror.NotFound("Category").WriteJSON(w)
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Resource").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	default:
		h.logger.Error("service error", "error", err)
		apierror.InternalError(err).WriteJSON(w)
	}
}

// ===== Category Handlers =====

// ListCategories handles GET /api/v1/asset-types/categories
// @Summary      List asset type categories
// @Description  Retrieves a paginated list of asset type categories. Use active_only=true to get all active categories without pagination.
// @Tags         Asset Types
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        active_only query bool false "Return only active categories (bypasses pagination)"
// @Param        search query string false "Search by name or code"
// @Param        page query int false "Page number" default(1)
// @Param        per_page query int false "Items per page" default(20)
// @Success      200  {object}  object{data=[]CategoryResponse,total=int,page=int,per_page=int,total_pages=int}
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Router       /asset-types/categories [get]
func (h *AssetTypeHandler) ListCategories(w http.ResponseWriter, r *http.Request) { //nolint:dupl // Similar to FindingSourceHandler.ListCategories but different types
	query := r.URL.Query()
	activeOnly := query.Get("active_only") == queryParamTrue

	if activeOnly {
		categories, err := h.service.ListActiveCategories(r.Context())
		if err != nil {
			h.handleServiceError(w, err)
			return
		}

		data := make([]CategoryResponse, len(categories))
		for i, c := range categories {
			data[i] = toCategoryResponse(c)
		}

		response := struct {
			Data  []CategoryResponse `json:"data"`
			Total int                `json:"total"`
		}{
			Data:  data,
			Total: len(data),
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(response)
		return
	}

	// Parse pagination
	pageNum := 1
	perPage := 20
	if p := query.Get("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			pageNum = parsed
		}
	}
	if pp := query.Get("per_page"); pp != "" {
		if parsed, err := strconv.Atoi(pp); err == nil && parsed > 0 {
			perPage = parsed
		}
	}
	page := pagination.New(pageNum, perPage)

	// Build filter
	filter := assettype.NewCategoryFilter()
	if search := query.Get("search"); search != "" {
		filter = filter.WithSearch(search)
	}

	categories, err := h.service.ListCategories(r.Context(), filter, page)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	data := make([]CategoryResponse, len(categories.Data))
	for i, c := range categories.Data {
		data[i] = toCategoryResponse(c)
	}

	response := struct {
		Data       []CategoryResponse `json:"data"`
		Total      int64              `json:"total"`
		Page       int                `json:"page"`
		PerPage    int                `json:"per_page"`
		TotalPages int                `json:"total_pages"`
	}{
		Data:       data,
		Total:      categories.Total,
		Page:       categories.Page,
		PerPage:    categories.PerPage,
		TotalPages: categories.TotalPages,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

// GetCategory handles GET /api/v1/asset-types/categories/{categoryId}
// @Summary      Get a category by ID
// @Description  Retrieves a single asset type category by its unique identifier
// @Tags         Asset Types
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        categoryId path string true "Category ID (UUID)"
// @Success      200  {object}  CategoryResponse
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Router       /asset-types/categories/{categoryId} [get]
func (h *AssetTypeHandler) GetCategory(w http.ResponseWriter, r *http.Request) {
	categoryID := r.PathValue("categoryId")
	if categoryID == "" {
		apierror.BadRequest("Category ID is required").WriteJSON(w)
		return
	}

	c, err := h.service.GetCategory(r.Context(), categoryID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toCategoryResponse(c))
}

// ===== Asset Type Handlers =====

// ListAssetTypes handles GET /api/v1/asset-types
// @Summary      List asset types
// @Description  Retrieves a paginated list of system asset types. Asset types are read-only configuration. Use active_only=true to get all active types without pagination.
// @Tags         Asset Types
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        active_only query bool false "Return only active asset types (bypasses pagination)"
// @Param        include_category query bool false "Include category details in response"
// @Param        search query string false "Search by name or code"
// @Param        category_id query string false "Filter by category ID"
// @Param        code query string false "Filter by exact code"
// @Param        is_system query bool false "Filter by system type"
// @Param        is_scannable query bool false "Filter by scannable flag"
// @Param        is_discoverable query bool false "Filter by discoverable flag"
// @Param        sort query string false "Sort field (e.g., 'name', '-display_order')"
// @Param        page query int false "Page number" default(1)
// @Param        per_page query int false "Items per page" default(50)
// @Success      200  {object}  object{data=[]AssetTypeResponse,total=int,page=int,per_page=int,total_pages=int}
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Router       /asset-types [get]
func (h *AssetTypeHandler) ListAssetTypes(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()

	// Check if active only
	activeOnly := query.Get("active_only") == queryParamTrue
	includeCategory := query.Get("include_category") == queryParamTrue

	if activeOnly {
		types, err := h.service.ListActiveAssetTypes(r.Context())
		if err != nil {
			h.handleServiceError(w, err)
			return
		}

		data := make([]AssetTypeResponse, len(types))
		for i, t := range types {
			data[i] = toAssetTypeResponse(t)
		}

		response := struct {
			Data  []AssetTypeResponse `json:"data"`
			Total int                 `json:"total"`
		}{
			Data:  data,
			Total: len(data),
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(response)
		return
	}

	// Parse pagination
	pageNum := 1
	perPage := 50
	if p := query.Get("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			pageNum = parsed
		}
	}
	if pp := query.Get("per_page"); pp != "" {
		if parsed, err := strconv.Atoi(pp); err == nil && parsed > 0 {
			perPage = parsed
		}
	}
	page := pagination.New(pageNum, perPage)

	// Build filter
	filter := assettype.NewFilter()

	if search := query.Get("search"); search != "" {
		filter = filter.WithSearch(search)
	}
	if categoryID := query.Get("category_id"); categoryID != "" {
		filter = filter.WithCategoryID(categoryID)
	}
	if code := query.Get("code"); code != "" {
		filter = filter.WithCode(code)
	}
	if query.Get("is_system") != "" {
		isSystem := query.Get("is_system") == queryParamTrue
		filter = filter.WithIsSystem(isSystem)
	}
	if query.Get("is_scannable") != "" {
		isScannable := query.Get("is_scannable") == queryParamTrue
		filter = filter.WithIsScannable(isScannable)
	}
	if query.Get("is_discoverable") != "" {
		isDiscoverable := query.Get("is_discoverable") == queryParamTrue
		filter = filter.WithIsDiscoverable(isDiscoverable)
	}

	opts := assettype.NewListOptions()
	if sortStr := query.Get("sort"); sortStr != "" {
		allowedFields := assettype.AllowedSortFields()
		opts = opts.WithSort(pagination.NewSortOption(allowedFields).Parse(sortStr))
	}

	if includeCategory {
		result, err := h.service.ListAssetTypesWithCategory(r.Context(), filter, opts, page)
		if err != nil {
			h.handleServiceError(w, err)
			return
		}

		data := make([]AssetTypeResponse, len(result.Data))
		for i, t := range result.Data {
			data[i] = toAssetTypeWithCategoryResponse(t)
		}

		response := struct {
			Data       []AssetTypeResponse `json:"data"`
			Total      int64               `json:"total"`
			Page       int                 `json:"page"`
			PerPage    int                 `json:"per_page"`
			TotalPages int                 `json:"total_pages"`
		}{
			Data:       data,
			Total:      result.Total,
			Page:       result.Page,
			PerPage:    result.PerPage,
			TotalPages: result.TotalPages,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(response)
		return
	}

	result, err := h.service.ListAssetTypes(r.Context(), filter, opts, page)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	data := make([]AssetTypeResponse, len(result.Data))
	for i, t := range result.Data {
		data[i] = toAssetTypeResponse(t)
	}

	response := struct {
		Data       []AssetTypeResponse `json:"data"`
		Total      int64               `json:"total"`
		Page       int                 `json:"page"`
		PerPage    int                 `json:"per_page"`
		TotalPages int                 `json:"total_pages"`
	}{
		Data:       data,
		Total:      result.Total,
		Page:       result.Page,
		PerPage:    result.PerPage,
		TotalPages: result.TotalPages,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

// GetAssetType handles GET /api/v1/asset-types/{id}
// @Summary      Get an asset type by ID
// @Description  Retrieves a single system asset type by its unique identifier
// @Tags         Asset Types
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id path string true "Asset Type ID (UUID)"
// @Success      200  {object}  AssetTypeResponse
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Router       /asset-types/{id} [get]
func (h *AssetTypeHandler) GetAssetType(w http.ResponseWriter, r *http.Request) {
	assetTypeID := r.PathValue("id")
	if assetTypeID == "" {
		apierror.BadRequest("Asset Type ID is required").WriteJSON(w)
		return
	}

	at, err := h.service.GetAssetType(r.Context(), assetTypeID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toAssetTypeResponse(at))
}
